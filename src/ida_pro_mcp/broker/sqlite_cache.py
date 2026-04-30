"""IDA static-information SQLite persistent cache

Design goals:
- Run a background daemon thread inside the IDA plugin process; while idle,
  fully extract the static information (strings, functions, globals, imports
  and their xrefs) from the IDA database and persist it to a SQLite database.
- The database file lives in the same directory as the IDB and shares its
  name, with the suffix `.mcp.sqlite` appended, so that the second time the
  same IDB is opened it loads "instantly" (no need to re-pull everything).
- For external callers (broker/manager interceptors), only a read-only query
  interface is exposed, so we don't compete with the IDA main thread.

All the implementation lives in the broker layer and does not invade the
upstream ida_mcp directory.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional

# ============================================================================
# SQLite database schema
# ============================================================================

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS strings (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    text TEXT NOT NULL,
    length INTEGER NOT NULL,
    segment TEXT
);
CREATE INDEX IF NOT EXISTS idx_strings_text ON strings(text);
CREATE INDEX IF NOT EXISTS idx_strings_segment ON strings(segment);

CREATE TABLE IF NOT EXISTS string_xrefs (
    str_addr TEXT NOT NULL,
    xref_addr TEXT NOT NULL,
    xref_ea INTEGER NOT NULL,
    type TEXT NOT NULL,
    PRIMARY KEY (str_addr, xref_addr)
);
CREATE INDEX IF NOT EXISTS idx_string_xrefs_str ON string_xrefs(str_addr);

CREATE TABLE IF NOT EXISTS functions (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    segment TEXT,
    has_type INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_segment ON functions(segment);

CREATE TABLE IF NOT EXISTS function_xrefs (
    func_addr TEXT NOT NULL,
    xref_addr TEXT NOT NULL,
    xref_ea INTEGER NOT NULL,
    direction TEXT NOT NULL,  -- 'to' (caller ->) or 'from' (-> callee)
    type TEXT NOT NULL,
    PRIMARY KEY (func_addr, xref_addr, direction)
);
CREATE INDEX IF NOT EXISTS idx_function_xrefs_func ON function_xrefs(func_addr);

CREATE TABLE IF NOT EXISTS globals (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    size INTEGER,
    segment TEXT
);
CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(name);
CREATE INDEX IF NOT EXISTS idx_globals_segment ON globals(segment);

CREATE TABLE IF NOT EXISTS imports (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    module TEXT
);
CREATE INDEX IF NOT EXISTS idx_imports_name ON imports(name);
CREATE INDEX IF NOT EXISTS idx_imports_module ON imports(module);
"""


# ============================================================================
# Helpers: database path resolution
# ============================================================================


def resolve_cache_path(idb_path: str) -> Optional[str]:
    """Compute the cache database path from the IDB path.

    Rule: `xxx.i64` -> `xxx.i64.mcp.sqlite`
    This way the database file name stays in sync with the IDB, so the next
    time the client opens the same IDB it can load it in seconds.
    """
    if not idb_path:
        return None
    return idb_path + ".mcp.sqlite"


# ============================================================================
# Database connection helpers
# ============================================================================


def _connect(db_path: str) -> sqlite3.Connection:
    """Open/create a database connection with WAL + FK enabled.

    WAL mode allows a single writer with multiple readers, so even while IDA
    is writing the cache, the broker can still query at high speed.
    """
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.executescript(SCHEMA_SQL)
    return conn


def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    cur = conn.execute("SELECT value FROM meta WHERE key=?", (key,))
    row = cur.fetchone()
    return row[0] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
        (key, str(value)),
    )


# ============================================================================
# IDA side: idle detection + full extraction + bulk write
#
# Any code that uses idaapi / idautils / idc must be invoked on the IDA main
# thread. We wrap both "idle detection" and "data extraction" as small
# functions that can be scheduled via execute_sync.
# ============================================================================


@dataclass
class CacheStats:
    strings: int = 0
    string_xrefs: int = 0
    functions: int = 0
    function_xrefs: int = 0
    globals_: int = 0
    imports: int = 0
    elapsed_ms: float = 0.0


def _ida_is_idle() -> bool:
    """On the main thread, check whether IDA is idle (auto_analysis_ready && hexrays_ready)."""
    try:
        import ida_auto
        import ida_hexrays

        auto_ok = bool(ida_auto.auto_is_ok())
        try:
            hexrays_ok = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            hexrays_ok = False
        return auto_ok and hexrays_ok
    except Exception:
        return False


def _collect_all_data() -> dict:
    """Collect the five categories of static information on the main thread. Time scales with IDB size."""
    import idaapi
    import idautils
    import idc
    import ida_bytes
    import ida_funcs
    import ida_nalt
    import ida_typeinf

    def _segname(ea: int) -> str:
        seg = idaapi.getseg(ea)
        if not seg:
            return ""
        try:
            return idaapi.get_segm_name(seg) or ""
        except Exception:
            return ""

    out: dict = {
        "strings": [],
        "string_xrefs": [],
        "functions": [],
        "function_xrefs": [],
        "globals": [],
        "imports": [],
    }

    # Strings + string xrefs
    for s in idautils.Strings():
        if s is None:
            continue
        try:
            ea = int(s.ea)
            text = str(s)
            length = len(text)
            addr = hex(ea)
            out["strings"].append((addr, ea, text, length, _segname(ea)))
            for xref in idautils.XrefsTo(ea, 0):
                xaddr = hex(xref.frm)
                xtype = "code" if xref.iscode else "data"
                out["string_xrefs"].append((addr, xaddr, int(xref.frm), xtype))
        except Exception:
            continue

    # Functions + function xrefs (to + from)
    for fea in idautils.Functions():
        try:
            fn = idaapi.get_func(fea)
            if not fn:
                continue
            fn_addr = hex(fn.start_ea)
            fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
            fn_size = fn.end_ea - fn.start_ea
            has_type = 1 if ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea) else 0
            out["functions"].append(
                (fn_addr, int(fn.start_ea), fn_name, int(fn_size), _segname(fn.start_ea), has_type)
            )
            # Xrefs to: callers
            for xref in idautils.XrefsTo(fn.start_ea, 0):
                xtype = "code" if xref.iscode else "data"
                out["function_xrefs"].append(
                    (fn_addr, hex(xref.frm), int(xref.frm), "to", xtype)
                )
        except Exception:
            continue

    # Globals (names that are not functions)
    for ea, name in idautils.Names():
        try:
            if name is None:
                continue
            if idaapi.get_func(ea):
                continue
            out["globals"].append(
                (hex(ea), int(ea), name, int(idc.get_item_size(ea) or 0), _segname(ea))
            )
        except Exception:
            continue

    # Imports
    try:
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module = ida_nalt.get_import_module_name(i) or "<unnamed>"

            def _cb(ea, symbol, ordinal, acc=out["imports"], mod=module):
                if not symbol:
                    symbol = f"#{ordinal}"
                acc.append((hex(ea), int(ea), symbol, mod))
                return True

            ida_nalt.enum_import_names(i, _cb)
    except Exception:
        pass

    return out


def _write_data_to_db(db_path: str, data: dict) -> CacheStats:
    """Bulk transactional write. Clears all business tables before writing."""
    stats = CacheStats()
    t0 = time.perf_counter()
    conn = _connect(db_path)
    try:
        with conn:
            set_meta(conn, "status", "building")
            set_meta(conn, "schema_version", str(SCHEMA_VERSION))

            conn.execute("DELETE FROM strings")
            conn.execute("DELETE FROM string_xrefs")
            conn.execute("DELETE FROM functions")
            conn.execute("DELETE FROM function_xrefs")
            conn.execute("DELETE FROM globals")
            conn.execute("DELETE FROM imports")

            conn.executemany(
                "INSERT OR REPLACE INTO strings(addr, ea, text, length, segment) VALUES(?,?,?,?,?)",
                data["strings"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO string_xrefs(str_addr, xref_addr, xref_ea, type) VALUES(?,?,?,?)",
                data["string_xrefs"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO functions(addr, ea, name, size, segment, has_type) VALUES(?,?,?,?,?,?)",
                data["functions"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO function_xrefs(func_addr, xref_addr, xref_ea, direction, type) VALUES(?,?,?,?,?)",
                data["function_xrefs"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO globals(addr, ea, name, size, segment) VALUES(?,?,?,?,?)",
                data["globals"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO imports(addr, ea, name, module) VALUES(?,?,?,?)",
                data["imports"],
            )

            set_meta(conn, "status", "ready")
            set_meta(conn, "last_updated", str(int(time.time())))

        stats.strings = len(data["strings"])
        stats.string_xrefs = len(data["string_xrefs"])
        stats.functions = len(data["functions"])
        stats.function_xrefs = len(data["function_xrefs"])
        stats.globals_ = len(data["globals"])
        stats.imports = len(data["imports"])
    finally:
        conn.close()
    stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return stats


# ============================================================================
# Background daemon thread
# ============================================================================


REFRESH_INTERVAL_SEC = 30 * 60  # 30-minute fallback poll
IDLE_POLL_SEC = 2.0  # Fast poll cadence while not yet ready


@dataclass
class _DaemonHandle:
    idb_path: str
    db_path: str
    thread: threading.Thread
    stop_event: threading.Event
    force_event: threading.Event
    last_stats: Optional[CacheStats] = None
    last_error: Optional[str] = None
    last_idb_mtime: float = 0.0
    idb_hook: Optional[object] = None


_daemons: dict[str, _DaemonHandle] = {}
_daemons_lock = threading.Lock()


def _execute_in_ida_main(fn):
    """Dispatch a function to the IDA main thread and synchronously get the return value back.

    Relies on ida_kernwin.execute_sync(..., MFF_READ). Returns None on failure.
    """
    import ida_kernwin

    box: list = [None]
    exc_box: list = [None]

    def runner():
        try:
            box[0] = fn()
        except Exception as e:  # noqa: BLE001
            exc_box[0] = e
        return 1

    ida_kernwin.execute_sync(runner, ida_kernwin.MFF_READ)
    if exc_box[0] is not None:
        raise exc_box[0]
    return box[0]


def _run_build_once(handle: _DaemonHandle) -> None:
    try:
        data = _execute_in_ida_main(_collect_all_data)
        if data is None:
            return
        stats = _write_data_to_db(handle.db_path, data)
        handle.last_stats = stats
        handle.last_error = None
        try:
            handle.last_idb_mtime = os.path.getmtime(handle.idb_path)
        except OSError:
            pass
        print(
            f"[MCP][cache] Write completed {handle.db_path}: "
            f"strings={stats.strings} ({stats.string_xrefs} xrefs), "
            f"functions={stats.functions} ({stats.function_xrefs} xrefs), "
            f"globals={stats.globals_}, imports={stats.imports}, "
            f"elapsed={stats.elapsed_ms:.0f}ms",
            file=sys.stderr,
        )
    except Exception as e:  # noqa: BLE001
        handle.last_error = str(e)
        print(f"[MCP][cache] Build failed: {e}", file=sys.stderr)


def _daemon_loop(handle: _DaemonHandle) -> None:
    """Daemon thread main loop.

    Algorithm:
    1. Continuously poll IDA's idle state; once ready, run a full build.
    2. Then loop on a 5-minute cycle; each time the cycle hits, idle is
       re-checked before building.
    3. force_event lets external callers (the refresh_cache tool) wake it
       up immediately.
    """
    # First build - wait for idle
    print(f"[MCP][cache] Daemon thread started, target database: {handle.db_path}", file=sys.stderr)
    try:
        _ensure_meta_building(handle.db_path)
    except Exception as e:  # noqa: BLE001
        print(f"[MCP][cache] Database initialization failed: {e}", file=sys.stderr)
        return

    # 1. Wait for idle, then do the first build
    while not handle.stop_event.is_set():
        try:
            idle = _execute_in_ida_main(_ida_is_idle)
        except Exception:
            idle = False
        if idle:
            _run_build_once(handle)
            break
        handle.stop_event.wait(IDLE_POLL_SEC)

    # 2. Periodic / passive refresh (mtime-driven: skip rebuild if IDB hasn't changed)
    while not handle.stop_event.is_set():
        triggered = handle.force_event.wait(REFRESH_INTERVAL_SEC)
        if handle.stop_event.is_set():
            break
        handle.force_event.clear()
        # When not force-triggered, check IDB mtime; skip if unchanged
        if not triggered:
            try:
                mtime = os.path.getmtime(handle.idb_path)
            except OSError:
                mtime = 0.0
            if mtime == handle.last_idb_mtime:
                print(f"[MCP][cache] IDB unchanged, skipping rebuild: {handle.idb_path}", file=sys.stderr)
                continue
        while not handle.stop_event.is_set():
            try:
                idle = _execute_in_ida_main(_ida_is_idle)
            except Exception:
                idle = False
            if idle:
                _run_build_once(handle)
                break
            handle.stop_event.wait(IDLE_POLL_SEC)


def _ensure_meta_building(db_path: str) -> None:
    """On first open / new database, write status=building so external interceptors can check it.

    If the database already exists and status is already ready, ready is preserved.
    This is the "instant load": the second time the same IDB is opened the cache file
    already exists, the Broker's interception takes effect immediately, and the
    background daemon thread only needs to do an overwrite refresh once it sees idle.
    """
    conn = _connect(db_path)
    try:
        cur = conn.execute("SELECT value FROM meta WHERE key='status'")
        row = cur.fetchone()
        if row is None:
            with conn:
                set_meta(conn, "status", "building")
                set_meta(conn, "schema_version", str(SCHEMA_VERSION))
    finally:
        conn.close()


def _make_idb_save_hook(handle: _DaemonHandle):
    """Create and register an IDB_Hooks subclass instance on the IDA main thread."""
    import ida_idp

    class _Hook(ida_idp.IDB_Hooks):
        def savebase(self):
            handle.force_event.set()
            return 0

    h = _Hook()
    h.hook()
    return h


def start_cache_daemon(idb_path: str) -> Optional[str]:
    """Start the SQLite cache background daemon thread associated with the given IDB.

    Returns the database path eventually used (may be None if idb_path is empty).
    Repeated calls are idempotent: if a daemon thread for the same idb_path is already
    running, the existing path is returned.
    """
    db_path = resolve_cache_path(idb_path)
    if not db_path:
        return None

    with _daemons_lock:
        existing = _daemons.get(idb_path)
        if existing and existing.thread.is_alive():
            return existing.db_path

        stop_event = threading.Event()
        force_event = threading.Event()
        handle = _DaemonHandle(
            idb_path=idb_path,
            db_path=db_path,
            thread=None,  # type: ignore[arg-type]
            stop_event=stop_event,
            force_event=force_event,
        )
        thread = threading.Thread(
            target=_daemon_loop,
            args=(handle,),
            name=f"mcp-sqlite-cache:{os.path.basename(idb_path)}",
            daemon=True,
        )
        handle.thread = thread
        try:
            handle.idb_hook = _make_idb_save_hook(handle)
        except Exception as e:
            print(f"[MCP][cache] IDB_Hooks registration failed: {e}", file=sys.stderr)
        _daemons[idb_path] = handle
        thread.start()

    return db_path


def request_refresh(idb_path: str) -> bool:
    """Wake the daemon thread for the specified IDB to immediately perform a refresh."""
    with _daemons_lock:
        handle = _daemons.get(idb_path)
    if handle is None:
        return False
    handle.force_event.set()
    return True


def stop_cache_daemon(idb_path: str) -> None:
    """Stop the specified daemon thread and clean up its state."""
    with _daemons_lock:
        handle = _daemons.pop(idb_path, None)
    if handle is None:
        return
    handle.stop_event.set()
    handle.force_event.set()  # wake up waiters
