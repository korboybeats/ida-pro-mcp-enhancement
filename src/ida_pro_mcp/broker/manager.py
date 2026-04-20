"""Broker 架构管理
"""

import os
import sys
import json
import time
from typing import Optional, cast, TYPE_CHECKING

from .client import BrokerClient
if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse
else:
    JsonRpcResponse = dict


_broker_client: Optional[BrokerClient] = None

def get_broker_client(broker_url: str = None) -> BrokerClient:
    """获取 Broker 客户端，MCP 模式下必有"""
    global _broker_client
    if _broker_client is None:
        _broker_client = BrokerClient(
            broker_url or os.environ.get("IDA_MCP_BROKER_URL", "http://127.0.0.1:13337"),
            10.0,
        )
    return _broker_client


def register_broker_tools(mcp):
    """注册实例管理工具（通过 Broker 客户端，无需本地 REGISTRY）"""
    @mcp.tool
    def instance_list() -> list[dict]:
        """列出所有已连接的 IDA/Hopper 实例。无需加载 IDB。返回 instance_id,name,binary_path,base_addr。用于多实例切换。"""
        return get_broker_client().list_instances()

    @mcp.tool
    def instance_current() -> dict:
        """获取当前活动实例信息。返回 instance_id,name,binary_path,base_addr,file_type。调用其他工具前建议先确认。"""
        out = get_broker_client().get_current()
        if out is None:
            return {"error": "Broker 不可用。请先启动: ida-pro-mcp --broker"}
        if out.get("error"):
            return {"error": out["error"]}
        return out

    @mcp.tool
    def instance_switch(instance_id: str) -> dict:
        """切换到指定实例。instance_id 来自 instance_list 返回。切换后后续 MCP 调用将发往该实例。"""
        return get_broker_client().set_current(instance_id)

    @mcp.tool
    def instance_info(instance_id: str) -> dict:
        """获取指定实例详情。instance_id 来自 instance_list。返回 binary_path,base_addr,processor 等。"""
        instances = get_broker_client().list_instances()
        current = get_broker_client().get_current()
        current_id = (current or {}).get("instance_id")
        for inst in instances:
            if inst.get("instance_id") == instance_id:
                return {**inst, "is_current": inst.get("instance_id") == current_id}
        return {"error": f"实例不存在: {instance_id}"}


def route_to_ida(request: dict) -> JsonRpcResponse | None:
    """将请求路由到当前 IDA 实例（通过 Broker）"""
    broker = get_broker_client()
    if not broker.has_instances():
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "没有活动的 IDA 实例。请启动 IDA 并按 Ctrl+Alt+M 连接。",
            },
            "id": request.get("id"),
        }
    current = broker.get_current()
    instance_id = (current or {}).get("instance_id") if current and not current.get("error") else None
    response = broker.send_request(request, instance_id)
    if response is None:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "IDA 请求超时"},
            "id": request.get("id"),
        }
    return response


def setup_dispatch_proxy(mcp, original_dispatch, ida_tools, ida_tool_schemas):
    """设置代理 dispatch，路由请求到 IDA 或本地处理"""
    def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
        if not isinstance(request, dict):
            request = json.loads(request)
        
        method = request.get("method", "")
        
        # 本地协议方法
        if method in {"initialize", "ping"} or method.startswith("notifications/"):
            return original_dispatch(request)
        
        # tools/call - 判断是否 IDA 工具
        if method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "") if isinstance(params, dict) else ""
            
            if tool_name in ida_tools:
                return route_to_ida(request)
            
            return original_dispatch(request)
        
        # tools/list - 返回所有工具，用预计算的正确 schema 替换 IDA 工具
        if method == "tools/list":
            response = original_dispatch(request)
            tools = response.get("result", {}).get("tools", []) if response else []
            for i, tool in enumerate(tools):
                if tool.get("name") in ida_tool_schemas:
                    tools[i] = ida_tool_schemas[tool["name"]]
            
            broker = get_broker_client()
            current = broker.get_current()
            if current and not current.get("error"):
                print(f"[MCP] tools/list: {len(tools)} 个工具 (IDA: {current.get('name', '')})", file=sys.stderr)
            else:
                print(f"[MCP] tools/list: {len(tools)} 个工具 (等待 IDA 连接)", file=sys.stderr)
            return response
        
        # resources 相关
        if method == "resources/list":
            return original_dispatch(request)
        if method == "resources/templates/list":
            return original_dispatch(request)
        if method == "resources/read":
            if not get_broker_client().has_instances():
                return cast(
                    JsonRpcResponse,
                    {"jsonrpc": "2.0", "result": {"contents": []}, "id": request.get("id")},
                )
            return route_to_ida(request)
        
        # prompts 相关
        if method in {"prompts/list", "prompts/get"}:
            return original_dispatch(request)
        
        # 其他请求转发到 IDA
        return route_to_ida(request)

    mcp.registry.dispatch = dispatch_proxy


def run_broker(port: int):
    """启动 Broker 服务器，阻塞主线程"""
    from .server import IDAHttpServer
    server = IDAHttpServer(port=port)
    server.start()
    print("[MCP] Broker 已启动，按 Ctrl+C 停止", file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
