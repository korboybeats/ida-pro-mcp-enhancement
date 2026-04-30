"""IDA Pro MCP Server

Broker architecture:
  - Broker mode (--broker): only starts HTTP, holds the REGISTRY; both IDA and the MCP client connect to this process.
  - MCP mode (default): stdio only, does not bind a port; sends requests to the Broker via the Broker client.

  Cursor --stdio--> server.py --HTTP--> Broker <--HTTP+SSE-- IDA Plugin
"""

import os
import sys
import json
import argparse
import threading
import time
from typing import Optional, BinaryIO, cast

# Handle both direct execution and execution as a package
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if __name__ == "__main__" or __package__ is None:
    sys.path.insert(0, os.path.dirname(SCRIPT_DIR))
    from ida_pro_mcp.tool_registry import parse_all_api_files, tool_to_mcp_schema, ToolDef
    from ida_pro_mcp.install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from ida_pro_mcp.broker.manager import get_broker_client, register_broker_tools, setup_dispatch_proxy, run_broker
else:
    from .tool_registry import parse_all_api_files, tool_to_mcp_schema, ToolDef
    from .install import install_ida_plugin, install_mcp_servers, print_mcp_config
    from .broker.manager import get_broker_client, register_broker_tools, setup_dispatch_proxy, run_broker

# Import the MCP implementation
sys.path.insert(0, os.path.join(SCRIPT_DIR, "ida_mcp"))
from zeromcp import McpServer
from zeromcp.jsonrpc import JsonRpcResponse
sys.path.pop(0)


# ============================================================================
# stdio output (for sending notifications)
# ============================================================================

_stdio_stdout: Optional[BinaryIO] = None
_stdio_lock = threading.Lock()


def send_notification(method: str, params: dict = None):
    """Send an MCP notification to the client (stdio)"""
    if _stdio_stdout is None:
        return

    notification = {"jsonrpc": "2.0", "method": method}
    if params:
        notification["params"] = params

    try:
        with _stdio_lock:
            _stdio_stdout.write(json.dumps(notification).encode("utf-8") + b"\n")
            _stdio_stdout.flush()
    except Exception as e:
        print(f"[MCP] Failed to send notification: {e}", file=sys.stderr)


# ============================================================================
# MCP server
# ============================================================================

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

# Register instance management tools (via the Broker client, no local REGISTRY required)
register_broker_tools(mcp)

# ============================================================================
# Dynamically register IDA tools and resources
# ============================================================================

_IDA_API_DIR = os.path.join(SCRIPT_DIR, "ida_mcp")
_IDA_TOOLS, _IDA_RESOURCES = parse_all_api_files(_IDA_API_DIR)
_IDA_TOOL_SCHEMAS = {t.name: tool_to_mcp_schema(t) for t in _IDA_TOOLS}

UNSAFE_TOOLS = {t.name for t in _IDA_TOOLS if t.is_unsafe}
IDA_TOOLS: set[str] = set()
_UNSAFE_ENABLED = False


def _create_ida_tool_wrapper(tool_def: ToolDef):
    """Create a wrapper function for an IDA tool"""
    from typing import Annotated, Any as AnyType

    def wrapper(**kwargs):
        pass

    wrapper.__name__ = tool_def.name
    wrapper.__doc__ = tool_def.description

    annotations = {}
    for param in tool_def.params:
        annotations[param.name] = Annotated[AnyType, param.description]
    annotations["return"] = AnyType
    wrapper.__annotations__ = annotations

    return wrapper


def _register_ida_tools(enable_unsafe: bool = False):
    """Register all IDA tools with the MCP server"""
    global IDA_TOOLS, _UNSAFE_ENABLED
    _UNSAFE_ENABLED = enable_unsafe

    registered_count = 0
    skipped_unsafe = 0

    for tool_def in _IDA_TOOLS:
        if tool_def.is_unsafe and not enable_unsafe:
            skipped_unsafe += 1
            continue

        IDA_TOOLS.add(tool_def.name)
        mcp.tools.methods[tool_def.name] = _create_ida_tool_wrapper(tool_def)
        registered_count += 1

    if skipped_unsafe > 0:
        print(f"[MCP] Registered {registered_count} IDA tools (skipped {skipped_unsafe} unsafe tools)", file=sys.stderr)
    else:
        print(f"[MCP] Registered {registered_count} IDA tools", file=sys.stderr)


def _register_ida_resources():
    """Register all IDA resources with the MCP server"""
    for res_def in _IDA_RESOURCES:
        def make_wrapper(uri):
            def wrapper(**kwargs):
                pass
            wrapper.__name__ = res_def.name
            wrapper.__doc__ = res_def.description
            setattr(wrapper, "__resource_uri__", uri)
            return wrapper

        mcp.resources.methods[res_def.name] = make_wrapper(res_def.uri)

    print(f"[MCP] Registered {len(_IDA_RESOURCES)} IDA resources", file=sys.stderr)


# ============================================================================
# Request routing
# ============================================================================

setup_dispatch_proxy(mcp, dispatch_original, IDA_TOOLS, _IDA_TOOL_SCHEMAS)


# =====================================================================

def main():
    global _stdio_stdout, _broker_client

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install the IDA plugin and MCP client config")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the IDA plugin and MCP client config")
    parser.add_argument("--allow-ida-free", action="store_true", help="Allow installation to IDA Free")
    parser.add_argument("--config", action="store_true", help="Print the MCP config")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe tools (debugger-related)")
    parser.add_argument("--port", type=int, default=13337, help="HTTP server port (Broker mode)")
    parser.add_argument("--broker", action="store_true", help="Start the Broker (HTTP) only, not stdio; for multi-window/multi-IDA setups, run this separately first")
    parser.add_argument("--broker-url", type=str, default="http://127.0.0.1:13337", help="URL the MCP mode uses to connect to the Broker")
    args = parser.parse_args()

    # Register tools
    _register_ida_tools(enable_unsafe=args.unsafe)
    _register_ida_resources()

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    if args.broker:
        # Broker mode: starts HTTP only, holds the REGISTRY, blocks the main thread
        run_broker(args.port)
        return

    # MCP mode: does not start HTTP, sends requests via the Broker client
    _broker_client = get_broker_client(args.broker_url)

    try:
        _stdio_stdout = sys.stdout.buffer
        mcp.stdio()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("[MCP] Exiting...", file=sys.stderr)
        _stdio_stdout = None
        os._exit(0)


if __name__ == "__main__":
    main()
