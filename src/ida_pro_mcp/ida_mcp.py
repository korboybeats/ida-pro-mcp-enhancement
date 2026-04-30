"""IDA Pro MCP Plugin Loader (HTTP+SSE version)

Communicates with the MCP server via HTTP+SSE.
Auto-connects when the plugin loads; press Ctrl+Alt+M to manually reconnect.
"""

import os
import sys
import threading
import idaapi
import idc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def _generate_instance_id() -> str:
    """Generate the instance ID, based on the process ID."""
    return f"ida-{os.getpid()}"


def _get_current_binary_path() -> str:
    """Get the path of the currently opened binary file."""
    try:
        return idc.get_input_file_path() or ""
    except Exception:
        return ""


def _get_current_idb_path() -> str:
    """Get the current IDB database path (.idb/.i64). Used to generate the SQLite cache file alongside it."""
    try:
        return idc.get_idb_path() or ""
    except Exception:
        return ""


def _get_current_binary_name() -> str:
    """Get the name of the currently opened binary file."""
    path = _get_current_binary_path()
    return os.path.basename(path) if path else ""


def _get_arch_info() -> dict:
    """Get the architecture info of the currently opened binary file."""
    try:
        import ida_ida

        proc_name = ida_ida.inf_get_procname() if hasattr(ida_ida, 'inf_get_procname') else ""
        is_64bit = ida_ida.inf_is_64bit() if hasattr(ida_ida, 'inf_is_64bit') else False
        bitness = 64 if is_64bit else 32
        is_be = ida_ida.inf_is_be() if hasattr(ida_ida, 'inf_is_be') else False
        endian = "big" if is_be else "little"

        file_type = ida_ida.inf_get_filetype() if hasattr(ida_ida, 'inf_get_filetype') else 0
        file_type_names = {
            0: "unknown", 1: "EXE", 2: "COM", 3: "BIN", 4: "DRV", 5: "WIN",
            6: "HEX", 7: "MEX", 8: "LX", 9: "LE", 10: "NLM", 11: "COFF",
            12: "PE", 13: "OMF", 14: "SREC", 15: "ZIP", 16: "OMFLIB",
            17: "AR", 18: "LOADER", 19: "ELF", 20: "W32RUN", 21: "AOUT",
            22: "PRC", 23: "PILOT", 24: "MACHO", 25: "MACHO64",
        }
        file_type_str = file_type_names.get(file_type, f"type_{file_type}")
        base_addr = hex(idaapi.get_imagebase())

        return {
            "processor": proc_name,
            "bitness": bitness,
            "endian": endian,
            "file_type": file_type_str,
            "base_addr": base_addr,
        }
    except Exception as e:
        return {"error": str(e)}


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        self._connected = False
        self._connecting = False  # connecting-in-progress flag, prevents duplicate connections
        self._mcp_server = None
        self._auto_connect_tried = False
        self._idb_path_for_cache = ""

        def auto_connect_timer():
            if not self._auto_connect_tried:
                self._auto_connect_tried = True
                self._try_connect(silent=True)
            return -1

        idaapi.register_timer(500, auto_connect_timer)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Manual connect/reconnect (Ctrl+Alt+M)"""
        self._try_connect(silent=False)

    def _try_connect(self, silent: bool = False):
        """Try to connect to the MCP server (executed on a background thread, does not block the UI)"""
        if self._connecting:
            if not silent:
                print("[MCP] Connection already in progress, please wait...")
            return

        if self._connected:
            self._disconnect()

        self._connecting = True

        # Prepare parameters on the UI thread
        unload_package("ida_mcp")

        if TYPE_CHECKING:
            from .ida_mcp import (
                MCP_SERVER,
                connect_to_server,
                disconnect,
                is_connected,
                set_auto_reconnect,
            )
        else:
            from ida_mcp import (
                MCP_SERVER,
                connect_to_server,
                disconnect,
                is_connected,
                set_auto_reconnect,
            )

        set_auto_reconnect(True)
        self._mcp_server = MCP_SERVER

        instance_id = _generate_instance_id()
        binary_path = _get_current_binary_path()
        binary_name = _get_current_binary_name()
        idb_path = _get_current_idb_path()
        arch_info = _get_arch_info()
        # Stuff idb_path into arch_info; once registered with the Broker, external code can locate the .mcp.sqlite cache file.
        if idb_path:
            arch_info["idb_path"] = idb_path

        # Start the SQLite static cache background daemon thread (implementation lives in the broker subdirectory; per IDA plugin loading convention we use absolute imports)
        if idb_path:
            try:
                if TYPE_CHECKING:
                    from .broker import sqlite_cache as _mcp_sqlite_cache
                else:
                    from broker import sqlite_cache as _mcp_sqlite_cache
                _mcp_sqlite_cache.start_cache_daemon(idb_path)
                self._idb_path_for_cache = idb_path
            except Exception as _e:
                print(f"[MCP] SQLite cache daemon thread failed to start: {_e}")
                self._idb_path_for_cache = ""
        else:
            self._idb_path_for_cache = ""

        def handle_mcp_request(request: dict) -> dict:
            """Handle MCP requests from the server.

            First intercepts cache tools (find_regex / entity_query / list_funcs /
            list_globals / imports / refresh_cache / cache_status) and responds
            directly with local SQLite, bypassing the normal ida_mcp dispatch and
            not occupying the IDA main thread.
            """
            from typing import cast as _cast
            if TYPE_CHECKING:
                from .broker import cache_handlers as _cache_handlers
                from .broker.cache_types import JsonRpcRequest as _JsonRpcRequest
            else:
                from broker import cache_handlers as _cache_handlers
                from broker.cache_types import JsonRpcRequest as _JsonRpcRequest

            typed_req = _cast(_JsonRpcRequest, request)
            if _cache_handlers.is_cache_tool(typed_req):
                idb_for_cache = self._idb_path_for_cache or _get_current_idb_path()
                return dict(_cache_handlers.handle_cache_tool_locally(typed_req, idb_for_cache))

            out = MCP_SERVER.registry.dispatch(request)
            if out is None:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "Internal error"},
                    "id": request.get("id"),
                }
            return dict(out)

        if not silent:
            print("[MCP] Connecting to MCP server...")

        def do_connect():
            """Perform the connection on a background thread"""
            try:
                success = connect_to_server(
                    instance_id=instance_id,
                    instance_type="gui",
                    name=binary_name or f"IDA-{os.getpid()}",
                    binary_path=binary_path,
                    arch_info=arch_info,
                    on_mcp_request=handle_mcp_request,
                )

                def update_status():
                    self._connecting = False
                    if success:
                        self._connected = True
                        print(f"[MCP] Connected ({binary_name or 'IDA'})")
                    else:
                        if silent:
                            print("[MCP] Auto-connect failed, press Ctrl+Alt+M to retry manually")
                        else:
                            print("[MCP] Connection failed, please make sure Cursor is running")
                    return -1

                idaapi.execute_sync(lambda: update_status(), idaapi.MFF_WRITE)
            except Exception as e:
                def report_error():
                    self._connecting = False
                    print(f"[MCP] Connection exception: {e}")
                    return -1
                idaapi.execute_sync(lambda: report_error(), idaapi.MFF_WRITE)

        thread = threading.Thread(target=do_connect, daemon=True)
        thread.start()

    def _disconnect(self):
        """Disconnect from the server"""
        if not self._connected:
            return

        try:
            if TYPE_CHECKING:
                from .ida_mcp import disconnect
            else:
                from ida_mcp import disconnect

            disconnect()
            self._connected = False
        except Exception:
            pass

        # Also stop the SQLite cache daemon thread for that IDB
        target = getattr(self, "_idb_path_for_cache", "") or ""
        if target:
            try:
                if TYPE_CHECKING:
                    from .broker import sqlite_cache as _mcp_sqlite_cache
                else:
                    from broker import sqlite_cache as _mcp_sqlite_cache
                _mcp_sqlite_cache.stop_cache_daemon(target)
            except Exception:
                pass
        self._idb_path_for_cache = ""

    def term(self):
        self._disconnect()


def PLUGIN_ENTRY():
    return MCP()


PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
