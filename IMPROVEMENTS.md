# Improvements Over Upstream (mrexodia/ida-pro-mcp)

This document details every improvement this enhanced fork introduces over the original [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp). The upstream project is an excellent MCP server for IDA Pro — this fork builds on it with architectural changes that solve real pain points in multi-client and large-binary workflows.

---

## Architecture: Broker Routing Layer

**Problem in upstream:** The original architecture has each MCP client communicate directly with a single IDA instance via a bound port. If you open multiple Cursor windows, multiple VS Code instances, or multiple IDA databases, they fight over the same port and can't coexist.

**Solution:** This fork introduces a standalone **Broker process** that listens on `127.0.0.1:13337`. Every MCP client and every IDA instance connects to the Broker instead of to each other directly.

| Aspect | Upstream | This Fork |
|--------|----------|-----------|
| Port binding | IDA plugin binds a port; one client at a time | Broker binds one port; unlimited clients and IDA instances |
| Multi-client | Not supported — second client fails to connect | Multiple Cursor/Claude/VS Code windows connect simultaneously |
| Multi-IDA | Not supported | Multiple IDA instances register with the Broker; each gets an `instance_id` |
| Routing | Implicit "current instance" state | Explicit `instance_id` on every tool call — no hidden state |

### New Files

| File | Purpose |
|------|---------|
| `broker/server.py` (16 KB) | HTTP listener, IDA instance registry, SSE push channel |
| `broker/manager.py` (10 KB) | `dispatch_proxy` — routes `tools/call` by `instance_id`, injects virtual tools into `tools/list` |
| `broker/client.py` (2 KB) | Lightweight HTTP client used by MCP processes to talk to the Broker |

### New Instance Management Tools

| Tool | Description |
|------|-------------|
| `instance_list()` | List all connected IDA instances with metadata (name, binary path, IDB path, base address) |
| `instance_info(instance_id)` | Get detailed info for a specific instance |

The upstream concepts of `instance_switch` and `instance_current` (implicit active instance) are deliberately removed. Every tool call requires an explicit `instance_id`, preventing cross-client state corruption when multiple agents share a Broker.

---

## Performance: SQLite Static Cache

**Problem in upstream:** Every query — listing functions, searching strings, enumerating globals — goes through the IDA API on IDA's main thread. For large binaries (10K+ functions, 100K+ strings), this creates significant latency and blocks IDA's UI.

**Solution:** This fork adds a **client-side SQLite cache** that runs entirely within the IDA plugin process. A daemon thread harvests data during IDA idle time and writes it to a `.mcp.sqlite` file next to the IDB.

### How It Works

1. **Daemon thread** watches for IDA idle state, then bulk-dumps strings, functions, globals, imports, and cross-references into SQLite.
2. **Cache interception layer** (`cache_handlers.py`) intercepts 7 specific tool calls and responds directly from SQLite — zero IDA main thread usage.
3. **WAL mode** allows concurrent reads while writes are in progress.
4. **Three re-index triggers:** IDB save (Ctrl+S), explicit `refresh_cache` call, 30-minute fallback poll.

### Performance Impact

| Operation | Upstream | This Fork |
|-----------|----------|-----------|
| `find_regex` on 100K strings | Blocks IDA main thread, seconds of latency | Instant SQLite REGEXP query, IDA stays responsive |
| `list_funcs` on 50K functions | Serial IDA API calls | SQLite SELECT with optional LIKE filter |
| `imports` enumeration | IDA API iteration | SQLite query |
| Concurrent queries from multiple agents | Serialized on IDA main thread | Parallel SQLite reads, zero contention |

### Cache-Intercepted Tools (7 total)

| Tool | What it does from cache |
|------|------------------------|
| `find_regex` | Regex search the string table with optional cross-references |
| `entity_query` | Unified query for strings, functions, globals, or imports |
| `list_funcs` | Function listing with name pattern filtering |
| `list_globals` | Global variable listing |
| `imports` | Import table enumeration |
| `refresh_cache` | Manually trigger cache rebuild |
| `cache_status` | Check cache existence, build status, and table counts |

### New Files

| File | Size | Purpose |
|------|------|---------|
| `broker/sqlite_cache.py` | 18 KB | Daemon thread: idle detection, bulk collection from IDA API, batch SQLite writes |
| `broker/sqlite_query.py` | 14 KB | Read-only query layer: SQL + REGEXP, strongly typed returns |
| `broker/cache_handlers.py` | 12 KB | Interception router: decides whether a `tools/call` hits cache or falls through to IDA |
| `broker/cache_types.py` | 5 KB | Protocol `TypedDict` definitions for all cache request/response types |

### Hard Semantics on Cache Miss

When the cache isn't ready (`status != ready`), this fork **does not silently fall back** to the live IDA API. It returns error code `-32001` with a message telling the LLM to retry or call `refresh_cache`. This prevents the model from receiving inconsistent "half-cached, half-live" data that could lead to incorrect analysis.

---

## New Analysis Tools

The upstream provides `analyze_funcs` as its only composite analysis tool. This fork significantly expands the analysis toolkit:

### Composite Analysis (`api_composite.py` — 20 KB, entirely new)

| Tool | Description |
|------|-------------|
| `analyze_function(addr, ...)` | Deep single-function analysis: decompilation + assembly + xrefs + call relationships + basic blocks + constants + strings |
| `analyze_batch(queries)` | Batch version of `analyze_function` for analyzing multiple functions in one call |
| `analyze_component(...)` | Component-level analysis rooted at an entry point — builds a call tree and produces a data flow summary |
| `diff_before_after(...)` | Snapshot diff analysis — compare function state before and after modifications |
| `trace_data_flow(...)` | Data flow tracing through a function or across call boundaries |

### Survey & Discovery (`api_survey.py` — 12 KB, entirely new)

| Tool | Description |
|------|-------------|
| `func_profile(queries)` | Quick function profile: prologue type, return semantics, basic block summary, calling convention |
| `insn_query(queries)` | Instruction sequence query by mnemonic and operand semantics (e.g., "find all `call [rax+0x18]` patterns") |
| `xref_query(queries)` | Extended cross-reference query with filtering and grouping |
| `entity_query(...)` | Unified entity search across strings, functions, globals, and imports (cache-backed) |

### Discovery (`api_discovery.py` — 15 KB, entirely new)

Extended discovery and enumeration tools for binary reconnaissance.

---

## Strict Type Protocol

**Problem in upstream:** Tool request/response shapes are loosely typed — callers have to guess whether fields exist, what types values are, and how errors are structured.

**Solution:** This fork introduces strict `TypedDict` definitions for every new API surface:

- `FindRegexArgs` / `FindRegexResult`
- `EntityQueryArgs` / `EntityQueryResult`
- `ToolSchema` / `McpToolCallResult`
- `JsonRpcRequest` / `JsonRpcResponse` / `JsonRpcError`
- `CacheStatusResult` / `RefreshCacheResult`

All defined in `broker/cache_types.py`. This eliminates ambiguity for both the LLM consumer and any tooling built on top of the protocol.

---

## Virtual Tool Injection

The Broker injects `refresh_cache` and `cache_status` as virtual entries in the `tools/list` response. This means:

- The LLM sees these tools in the tool catalog and can call them naturally.
- The tools don't execute in the Broker — they're routed to the target IDA instance like any other tool.
- No special-casing needed on the client side.

---

## Structured Error Codes

This fork defines a consistent error code convention:

| Code | Meaning |
|------|---------|
| `-32001` | Cache not ready or file missing |
| `-32000` | No `instance_id` provided or no active IDA instances |
| `-32602` | Parameter validation error |
| `-32603` | Internal SQLite query exception |

The upstream doesn't have a formalized error code scheme for these scenarios.

---

## Codebase Organization

### Upstream Structure
- `ida_mcp/` — monolithic API files: `api_core.py`, `api_modify.py`, `api_memory.py`, `api_debug.py`, etc.
- No broker, no caching, no composite analysis

### This Fork Adds

```
broker/
  server.py          — Broker HTTP + registry + SSE
  manager.py         — Routing + virtual tool injection
  client.py          — MCP-to-Broker HTTP client
  sqlite_cache.py    — Write path (daemon thread)
  sqlite_query.py    — Read path (strongly typed queries)
  cache_handlers.py  — tools/call interception
  cache_types.py     — TypedDict protocol definitions

ida_mcp/
  api_composite.py   — Deep & batch analysis tools (NEW)
  api_survey.py      — Function profiling, instruction query (NEW)
  api_discovery.py   — Extended binary discovery (NEW)
  api_instances.py   — Multi-instance management (NEW)
```

Total new code: ~140 KB across 11 new source files.

---

## Summary Table

| Feature | Upstream | This Fork |
|---------|----------|-----------|
| Multi-client support | No | Yes — Broker handles unlimited MCP clients |
| Multi-IDA support | No | Yes — each IDA registers with a unique `instance_id` |
| Port conflicts | Common when opening multiple editors | Eliminated — single Broker port |
| SQLite cache for reads | No — all queries hit IDA main thread | Yes — 7 high-frequency tools served from local SQLite |
| IDA UI responsiveness | Degrades under heavy LLM queries | Maintained — cache serves reads off-thread |
| Composite analysis tools | `analyze_funcs` only | `analyze_function`, `analyze_batch`, `analyze_component`, `diff_before_after`, `trace_data_flow` |
| Function profiling | No | `func_profile` |
| Instruction pattern search | `find_insns` (basic) | `insn_query` (mnemonic + operand semantic matching) |
| Typed protocol | Loose | Strict `TypedDict` for all new APIs |
| Error code convention | Ad-hoc | Formalized (`-32001`, `-32000`, `-32602`, `-32603`) |
| Virtual tool injection | No | `refresh_cache` and `cache_status` appear in `tools/list` |
| Instance state model | Implicit "current instance" | Explicit `instance_id` on every call — no hidden state |
| Cache consistency | N/A | Hard fail on stale cache — no silent fallback |
