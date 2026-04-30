"""Broker architecture management (pure routing)

In this module the Broker process only does:
1. Request pass-through: forwards tools/call / resources/read and similar
   requests sent by Cursor via SSE to the target IDA instance, and returns
   the response unchanged.
2. tools/list decoration: replaces the schema of IDA tools, and **appends**
   the schemas of two "virtual tools" (`refresh_cache`, `cache_status`) so
   the LLM can see them.

The actual cache reads/writes (SQLite) are performed inside the IDA plugin
process. The Broker process must NOT import `sqlite_cache` / `sqlite_query`,
to avoid polluting the routing responsibility.
"""

from __future__ import annotations

import os
import sys
import json
import time
from typing import TYPE_CHECKING, Optional, cast

from .client import BrokerClient
from .cache_types import ToolInputSchema, ToolSchema

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse
else:
    JsonRpcResponse = dict


_broker_client: Optional[BrokerClient] = None


def get_broker_client(broker_url: Optional[str] = None) -> BrokerClient:
    """Get the Broker client; required in MCP mode."""
    global _broker_client
    if _broker_client is None:
        _broker_client = BrokerClient(
            broker_url or os.environ.get("IDA_MCP_BROKER_URL", "http://127.0.0.1:13337"),
            10.0,
        )
    return _broker_client


# ---------------------------------------------------------------------------
# Virtual cache tool schemas (only inserted by the Broker into tools/list, not executed in the Broker)
# ---------------------------------------------------------------------------


_INSTANCE_ID_PROP: dict[str, str] = {
    "type": "string",
    "description": (
        "Required instance_id (or client_id), used to route the request precisely to a specific IDA instance. "
        "Call instance_list first to view and pick an appropriate client ID."
    ),
}


def _build_cache_tool_schemas() -> list[ToolSchema]:
    """Generate the MCP schemas for the two virtual tools refresh_cache / cache_status."""
    refresh_input: ToolInputSchema = {
        "type": "object",
        "properties": {"instance_id": dict(_INSTANCE_ID_PROP)},
        "required": ["instance_id"],
    }
    status_input: ToolInputSchema = {
        "type": "object",
        "properties": {"instance_id": dict(_INSTANCE_ID_PROP)},
        "required": ["instance_id"],
    }
    return [
        {
            "name": "refresh_cache",
            "description": (
                "Request the specified IDA instance to immediately refresh its local SQLite static cache (xxx.idb.mcp.sqlite). "
                "The actual refresh still requires IDA to enter idle state before it runs; this tool only wakes the plugin-side daemon thread and returns immediately."
            ),
            "inputSchema": refresh_input,
        },
        {
            "name": "cache_status",
            "description": (
                "Query the local SQLite static cache status of the specified IDA instance (status / last_updated / per-table counts). "
                "When status != 'ready', tools such as find_regex / entity_query / list_funcs / list_globals / imports will return an error and ask to retry later."
            ),
            "inputSchema": status_input,
        },
    ]


# ---------------------------------------------------------------------------
# Instance management tools
# ---------------------------------------------------------------------------


def register_broker_tools(mcp):
    """Register instance management tools (via the Broker client, no local REGISTRY needed)."""

    @mcp.tool
    def instance_list() -> list[dict]:
        """List all connected IDA/Hopper instances. Does not require loading an IDB. Returns instance_id, name, binary_path, idb_path, base_addr."""
        return get_broker_client().list_instances()

    @mcp.tool
    def instance_info(instance_id: str) -> dict:
        """Get details of the specified instance. instance_id comes from instance_list. Returns binary_path, idb_path, base_addr, processor, etc."""
        instances = get_broker_client().list_instances()
        for inst in instances:
            if inst.get("instance_id") == instance_id:
                return inst
        return {"error": f"Instance not found: {instance_id}"}


# ---------------------------------------------------------------------------
# Request routing: forward to the target IDA as-is
# ---------------------------------------------------------------------------


def route_to_ida(request: dict) -> JsonRpcResponse | None:
    """Route the request to the specified IDA instance (via the Broker)."""
    broker = get_broker_client()
    if not broker.has_instances():
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "No active IDA instance. Please start IDA and press Ctrl+Alt+M to connect.",
            },
            "id": request.get("id"),
        }

    instance_id: Optional[str] = None
    if request.get("method") == "tools/call":
        params = request.get("params", {}) or {}
        args = params.get("arguments", {}) or {}
        if "instance_id" not in args:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32602,
                    "message": "instance_id parameter must be provided. Call instance_list first to view and pick an appropriate client ID.",
                },
                "id": request.get("id"),
            }
        # Extract and remove instance_id so the actual arguments sent to IDA do not include the extra field
        instance_id = args.pop("instance_id")
    # For non-tool/call requests (e.g. resources/read), the Broker selects automatically based on the registered instance count.

    response = broker.send_request(request, instance_id)
    if response is None:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "IDA request timeout"},
            "id": request.get("id"),
        }
    return cast(JsonRpcResponse, response)


# ---------------------------------------------------------------------------
# dispatch proxy
# ---------------------------------------------------------------------------


def setup_dispatch_proxy(mcp, original_dispatch, ida_tools, ida_tool_schemas):
    """Set up a proxy dispatch: IDA tools -> forward, others -> handle locally."""

    # The Broker process generates virtual tool schemas; their names are also added to ida_tools so that tools/call goes through the route instead of the original dispatch
    extra_cache_schemas: list[ToolSchema] = _build_cache_tool_schemas()
    extra_cache_names: set[str] = {s["name"] for s in extra_cache_schemas}

    def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        if isinstance(request, dict):
            req: dict = request
        else:
            req = json.loads(request)

        method = req.get("method", "")

        # Local protocol methods
        if method in {"initialize", "ping"} or method.startswith("notifications/"):
            return original_dispatch(req)

        # tools/call - decide whether to forward to IDA
        if method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "") if isinstance(params, dict) else ""

            if tool_name in ida_tools or tool_name in extra_cache_names:
                return route_to_ida(req)

            return original_dispatch(req)

        # tools/list - first call upstream dispatch, then override IDA tool schemas, then append virtual tools
        if method == "tools/list":
            response = original_dispatch(req)
            tools = response.get("result", {}).get("tools", []) if response else []
            for i, tool in enumerate(tools):
                if tool.get("name") in ida_tool_schemas:
                    tools[i] = ida_tool_schemas[tool["name"]]
            # Append virtual cache tool schemas
            existing_names = {t.get("name") for t in tools}
            for schema in extra_cache_schemas:
                if schema["name"] not in existing_names:
                    tools.append(cast(dict, schema))

            broker = get_broker_client()
            instances = broker.list_instances()
            if instances:
                print(
                    f"[MCP] tools/list: {len(tools)} tools (active IDA instances: {len(instances)})",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[MCP] tools/list: {len(tools)} tools (waiting for IDA connection)",
                    file=sys.stderr,
                )
            return response

        # resources-related
        if method == "resources/list":
            return original_dispatch(req)
        if method == "resources/templates/list":
            return original_dispatch(req)
        if method == "resources/read":
            if not get_broker_client().has_instances():
                return cast(
                    JsonRpcResponse,
                    {"jsonrpc": "2.0", "result": {"contents": []}, "id": req.get("id")},
                )
            return route_to_ida(req)

        # prompts-related
        if method in {"prompts/list", "prompts/get"}:
            return original_dispatch(req)

        # All other requests are forwarded to IDA
        return route_to_ida(req)

    mcp.registry.dispatch = dispatch_proxy


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_broker(port: int):
    """Start the Broker server, blocking the main thread."""
    from .server import IDAHttpServer

    server = IDAHttpServer(port=port)
    server.start()
    print("[MCP] Broker started, press Ctrl+C to stop", file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
