"""Cache module protocol types (TypedDict)

All request/response protocol types shared between the Broker and the IDA
plugin live here. The Broker process imports this file directly and must
not import any module under `ida_pro_mcp.ida_mcp` to avoid pulling in
IDA-only dependencies like `idaapi`.

This file independently re-declares the JSON-RPC TypedDicts it needs so
that we don't have to go through `ida_pro_mcp.ida_mcp.zeromcp.jsonrpc`,
which would indirectly load IDA modules via `ida_mcp/__init__.py`.
"""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypeAlias, TypedDict


# ---------------------------------------------------------------------------
# JSON-RPC (protocol-compatible with ida_pro_mcp.ida_mcp.zeromcp.jsonrpc; declared independently)
# ---------------------------------------------------------------------------

JsonRpcId: TypeAlias = str | int | float | None
JsonRpcParams: TypeAlias = dict[str, Any] | list[Any] | None


class JsonRpcRequest(TypedDict):
    jsonrpc: str
    method: str
    params: NotRequired[JsonRpcParams]
    id: NotRequired[JsonRpcId]


class JsonRpcError(TypedDict):
    code: int
    message: str
    data: NotRequired[Any]


class JsonRpcResponse(TypedDict):
    jsonrpc: str
    result: NotRequired[Any]
    error: NotRequired[JsonRpcError]
    id: JsonRpcId


# ---------------------------------------------------------------------------
# Common Literal / enum aliases
# ---------------------------------------------------------------------------

EntityKind: TypeAlias = Literal["strings", "functions", "globals", "imports"]
XrefType: TypeAlias = Literal["code", "data"]
XrefDirection: TypeAlias = Literal["to", "from"]
CacheSource: TypeAlias = Literal["sqlite_cache"]
CacheRunStatus: TypeAlias = Literal["ready", "building", "missing"]


# ---------------------------------------------------------------------------
# Tool arguments (passed via tools/call arguments.*)
# ---------------------------------------------------------------------------


class _BaseArgs(TypedDict):
    instance_id: str


class FindRegexArgs(_BaseArgs):
    pattern: str
    limit: NotRequired[int]
    offset: NotRequired[int]
    include_xrefs: NotRequired[bool]


class EntityQueryArgs(_BaseArgs):
    kind: EntityKind
    name_pattern: NotRequired[str]
    segment: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]
    include_xrefs: NotRequired[bool]


class ListFuncsArgs(_BaseArgs):
    name_pattern: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]
    include_xrefs: NotRequired[bool]


class ListGlobalsArgs(_BaseArgs):
    name_pattern: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]


class ImportsArgs(_BaseArgs):
    name_pattern: NotRequired[str]
    module_pattern: NotRequired[str]
    limit: NotRequired[int]
    offset: NotRequired[int]


class RefreshCacheArgs(_BaseArgs):
    pass


class CacheStatusArgs(_BaseArgs):
    pass


# ---------------------------------------------------------------------------
# Xref / item structures
# ---------------------------------------------------------------------------


class XrefItem(TypedDict):
    addr: str
    type: XrefType


class StringItem(TypedDict):
    addr: str
    text: str
    length: int
    segment: str
    xrefs: NotRequired[list[XrefItem]]


class FunctionItem(TypedDict):
    addr: str
    name: str
    size: int
    segment: str
    has_type: bool
    xrefs_to: NotRequired[list[XrefItem]]


class GlobalItem(TypedDict):
    addr: str
    name: str
    size: int
    segment: str


class ImportItem(TypedDict):
    addr: str
    name: str
    module: str


EntityItem: TypeAlias = StringItem | FunctionItem | GlobalItem | ImportItem


# ---------------------------------------------------------------------------
# Tool return values
# ---------------------------------------------------------------------------


class _PagedMeta(TypedDict):
    total: int
    offset: int
    limit: int
    source: CacheSource


class FindRegexResult(_PagedMeta):
    items: list[StringItem]


class EntityQueryResult(_PagedMeta):
    kind: EntityKind
    items: list[EntityItem]


class ListFuncsResult(_PagedMeta):
    items: list[FunctionItem]


class ListGlobalsResult(_PagedMeta):
    items: list[GlobalItem]


class ListImportsResult(_PagedMeta):
    items: list[ImportItem]


class RefreshCacheResult(TypedDict):
    triggered: bool
    idb_path: str


class CacheStatusResult(TypedDict):
    exists: bool
    db_path: str
    status: str
    meta: dict[str, str]
    strings: int
    string_xrefs: int
    functions: int
    function_xrefs: int
    globals: int
    imports: int


# ---------------------------------------------------------------------------
# MCP protocol shell: shape of the tools/call result
# ---------------------------------------------------------------------------


class McpTextContent(TypedDict):
    type: Literal["text"]
    text: str


class McpToolCallResult(TypedDict):
    content: list[McpTextContent]
    isError: bool


# ---------------------------------------------------------------------------
# tools/list schema shape
# ---------------------------------------------------------------------------


class ToolInputSchema(TypedDict):
    type: Literal["object"]
    properties: dict[str, dict[str, Any]]
    required: list[str]


class ToolSchema(TypedDict):
    name: str
    description: str
    inputSchema: ToolInputSchema
