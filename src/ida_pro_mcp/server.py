"""IDA Pro MCP Server

Broker 架构:
  - Broker 模式 (--broker): 仅启动 HTTP，持有 REGISTRY，IDA 与 MCP 客户端均连此进程。
  - MCP 模式 (默认): 仅 stdio，不绑定端口，通过 Broker 客户端请求 Broker。

  Cursor --stdio--> server.py --HTTP--> Broker <--HTTP+SSE-- IDA Plugin
"""

import os
import sys
import json
import argparse
import threading
import time
from typing import Optional, BinaryIO, cast

# 处理直接运行和作为包运行两种情况
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

# 导入 MCP 实现
sys.path.insert(0, os.path.join(SCRIPT_DIR, "ida_mcp"))
from zeromcp import McpServer
from zeromcp.jsonrpc import JsonRpcResponse
sys.path.pop(0)


# ============================================================================
# stdio 输出（用于发送通知）
# ============================================================================

_stdio_stdout: Optional[BinaryIO] = None
_stdio_lock = threading.Lock()


def send_notification(method: str, params: dict = None):
    """发送 MCP 通知到客户端（stdio）"""
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
        print(f"[MCP] 发送通知失败: {e}", file=sys.stderr)


# ============================================================================
# MCP 服务器
# ============================================================================

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

# 注册实例管理工具（通过 Broker 客户端，无需本地 REGISTRY）
register_broker_tools(mcp)

# ============================================================================
# 动态注册 IDA 工具和资源
# ============================================================================

_IDA_API_DIR = os.path.join(SCRIPT_DIR, "ida_mcp")
_IDA_TOOLS, _IDA_RESOURCES = parse_all_api_files(_IDA_API_DIR)
_IDA_TOOL_SCHEMAS = {t.name: tool_to_mcp_schema(t) for t in _IDA_TOOLS}

UNSAFE_TOOLS = {t.name for t in _IDA_TOOLS if t.is_unsafe}
IDA_TOOLS: set[str] = set()
_UNSAFE_ENABLED = False


def _create_ida_tool_wrapper(tool_def: ToolDef):
    """为 IDA 工具创建 wrapper 函数"""
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
    """注册所有 IDA 工具到 MCP 服务器"""
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
        print(f"[MCP] 注册了 {registered_count} 个 IDA 工具 (跳过 {skipped_unsafe} 个 unsafe 工具)", file=sys.stderr)
    else:
        print(f"[MCP] 注册了 {registered_count} 个 IDA 工具", file=sys.stderr)


def _register_ida_resources():
    """注册所有 IDA 资源到 MCP 服务器"""
    for res_def in _IDA_RESOURCES:
        def make_wrapper(uri):
            def wrapper(**kwargs):
                pass
            wrapper.__name__ = res_def.name
            wrapper.__doc__ = res_def.description
            setattr(wrapper, "__resource_uri__", uri)
            return wrapper
        
        mcp.resources.methods[res_def.name] = make_wrapper(res_def.uri)
    
    print(f"[MCP] 注册了 {len(_IDA_RESOURCES)} 个 IDA 资源", file=sys.stderr)


# ============================================================================
# 请求路由
# ============================================================================

setup_dispatch_proxy(mcp, dispatch_original, IDA_TOOLS, _IDA_TOOL_SCHEMAS)


# =====================================================================

def main():
    global _stdio_stdout, _broker_client

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="安装 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--uninstall", action="store_true", help="卸载 IDA 插件和 MCP 客户端配置")
    parser.add_argument("--allow-ida-free", action="store_true", help="允许安装到 IDA Free")
    parser.add_argument("--config", action="store_true", help="打印 MCP 配置")
    parser.add_argument("--unsafe", action="store_true", help="启用不安全工具（调试器相关）")
    parser.add_argument("--port", type=int, default=13337, help="HTTP 服务器端口（Broker 模式）")
    parser.add_argument("--broker", action="store_true", help="仅启动 Broker（HTTP），不启动 stdio；多窗口/多 IDA 时请先单独运行")
    parser.add_argument("--broker-url", type=str, default="http://127.0.0.1:13337", help="MCP 模式连接 Broker 的 URL")
    args = parser.parse_args()

    # 注册工具
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
        # Broker 模式：仅启动 HTTP，持有 REGISTRY，阻塞主线程
        run_broker(args.port)
        return

    # MCP 模式：不启动 HTTP，通过 Broker 客户端请求
    _broker_client = get_broker_client(args.broker_url)

    try:
        _stdio_stdout = sys.stdout.buffer
        mcp.stdio()
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("[MCP] 正在退出...", file=sys.stderr)
        _stdio_stdout = None
        os._exit(0)


if __name__ == "__main__":
    main()
