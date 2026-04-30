"""IDA HTTP+SSE server

Listens on an HTTP port and accepts IDA plugin connections.
Uses SSE to push MCP requests to IDA.
"""

import json
import queue
import socketserver
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse
import sys


@dataclass
class IDAInstance:
    """IDA instance information"""
    client_id: str
    instance_id: str
    instance_type: str = "gui"
    name: str = ""
    binary_path: str = ""
    idb_path: str = ""
    arch_info: dict = field(default_factory=dict)
    connected_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        result = {
            "client_id": self.client_id,
            "instance_id": self.instance_id,
            "type": self.instance_type,
            "name": self.name,
            "binary_path": self.binary_path,
            "idb_path": self.idb_path,
        }
        if self.arch_info:
            result["processor"] = self.arch_info.get("processor", "")
            result["bitness"] = self.arch_info.get("bitness", 0)
            result["endian"] = self.arch_info.get("endian", "")
            result["file_type"] = self.arch_info.get("file_type", "")
            result["base_addr"] = self.arch_info.get("base_addr", "")
        return result


class IDARegistry:
    """IDA instance registry"""

    def __init__(self):
        self._instances: dict[str, IDAInstance] = {}
        self._lock = threading.RLock()

        # SSE queues: client_id -> Queue
        self._sse_queues: dict[str, queue.Queue] = {}

        # Pending requests: request_id -> {event, response}
        self._pending: dict[str, dict] = {}

        # Callbacks
        self._on_connect: Optional[Callable[[IDAInstance], None]] = None
        self._on_disconnect: Optional[Callable[[str], None]] = None

    def register(self, data: dict) -> Optional[IDAInstance]:
        """Register an IDA instance. When the same instance_id reconnects, replace the old connection to avoid duplicates in the list."""
        with self._lock:
            instance_id = data.get("instance_id", "")
            # If the same instance_id already exists, remove the old connection first (caused by reconnect or repeated clicks)
            for old_client_id, old_inst in list(self._instances.items()):
                if old_inst.instance_id == instance_id:
                    self._instances.pop(old_client_id, None)
                    self._sse_queues.pop(old_client_id, None)
                    print(f"[HTTP] Replacing old connection: {old_inst.name or instance_id} ({old_client_id})", file=sys.stderr)
                    sys.stderr.flush()
                    break

            client_id = str(uuid.uuid4())[:8]
            arch_info = data.get("arch_info", {}) or {}
            # idb_path prefers the top-level field, but is also compatible with being passed via arch_info (the plugin side puts it here to minimize upstream changes)
            idb_path = data.get("idb_path", "") or arch_info.get("idb_path", "")
            instance = IDAInstance(
                client_id=client_id,
                instance_id=instance_id or client_id,
                instance_type=data.get("instance_type", "gui"),
                name=data.get("name", ""),
                binary_path=data.get("binary_path", ""),
                idb_path=idb_path,
                arch_info=arch_info,
            )
            self._instances[client_id] = instance
            self._sse_queues[client_id] = queue.Queue()

            print(f"[HTTP] +++ IDA connected: {instance.name or instance.instance_id} +++", file=sys.stderr)
            sys.stderr.flush()

            if self._on_connect:
                self._on_connect(instance)

            return instance

    def unregister(self, client_id: str):
        """Unregister an IDA instance"""
        with self._lock:
            instance = self._instances.pop(client_id, None)
            self._sse_queues.pop(client_id, None)

            if instance:
                print(f"[HTTP] --- IDA disconnected: {instance.name or instance.instance_id} ---", file=sys.stderr)
                sys.stderr.flush()

                if self._on_disconnect:
                    self._on_disconnect(instance.instance_id)

    def get_by_client_id(self, client_id: str) -> Optional[IDAInstance]:
        """Get an instance by client_id"""
        with self._lock:
            return self._instances.get(client_id)

    def get_by_instance_id(self, instance_id: str) -> Optional[IDAInstance]:
        """Get an instance by instance_id"""
        with self._lock:
            for inst in self._instances.values():
                if inst.instance_id == instance_id:
                    return inst
            return None

    def list_all(self) -> list[dict]:
        """List all instances"""
        with self._lock:
            return [inst.to_dict() for inst in self._instances.values()]

    def has_instances(self) -> bool:
        """Whether there are any instances"""
        with self._lock:
            return len(self._instances) > 0

    def send_request(self, request: dict, instance_id: Optional[str] = None, timeout: float = 60.0) -> Optional[dict]:
        """Send a request to IDA and wait for the response"""
        with self._lock:
            # Determine the target instance
            if instance_id:
                inst = self.get_by_instance_id(instance_id)
            else:
                # If not specified and there is only one instance, route automatically; otherwise return an error
                if len(self._instances) == 1:
                    inst = next(iter(self._instances.values()))
                else:
                    return {
                        "jsonrpc": "2.0",
                        "error": {"code": -32602, "message": "Multiple IDA instances exist or instance_id was not specified, cannot route."},
                        "id": request.get("id")
                    }

            if not inst:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": f"Target instance not found: {instance_id}"},
                    "id": request.get("id")
                }

            client_id = inst.client_id
            sse_queue = self._sse_queues.get(client_id)
            if not sse_queue:
                return None

            # Create request tracking
            request_id = str(uuid.uuid4())[:8]
            event = threading.Event()
            self._pending[request_id] = {"event": event, "response": None}

        # Put into SSE queue
        sse_queue.put({"request_id": request_id, "request": request})

        # Wait for the response
        if event.wait(timeout):
            with self._lock:
                result = self._pending.pop(request_id, {})
                return result.get("response")
        else:
            with self._lock:
                self._pending.pop(request_id, None)
            return None

    def set_response(self, request_id: str, response: dict):
        """Set the response for a request"""
        with self._lock:
            if request_id in self._pending:
                self._pending[request_id]["response"] = response
                self._pending[request_id]["event"].set()

    def get_sse_queue(self, client_id: str) -> Optional[queue.Queue]:
        """Get the SSE queue"""
        with self._lock:
            return self._sse_queues.get(client_id)


# Global registry
REGISTRY = IDARegistry()


class IDARequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler"""

    def log_message(self, format, *args):
        """Redirect logs to stderr"""
        print(f"[HTTP] {args[0]}", file=sys.stderr)
        sys.stderr.flush()

    def _send_json(self, data: dict, status: int = 200):
        """Send a JSON response"""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[dict]:
        """Read the JSON request body"""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            body = self.rfile.read(length)
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        """Handle POST requests"""
        path = urlparse(self.path).path

        if path == "/register":
            self._handle_register()
        elif path == "/unregister":
            self._handle_unregister()
        elif path == "/response":
            self._handle_response()
        elif path == "/api/request":
            self._handle_api_request()
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/events":
            client_id = params.get("client_id", [None])[0]
            if client_id:
                self._handle_sse(client_id)
            else:
                self._send_json({"error": "Missing client_id"}, 400)
        elif path == "/status":
            self._send_json({"instances": REGISTRY.list_all()})
        elif path == "/api/instances":
            self._send_json(REGISTRY.list_all())
        else:
            self._send_json({"error": "Not found"}, 404)

    def _handle_register(self):
        """Handle IDA registration"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        instance = REGISTRY.register(data)
        if instance:
            self._send_json({"success": True, "client_id": instance.client_id})
        else:
            self._send_json({"error": "Registration failed"}, 500)

    def _handle_unregister(self):
        """Handle IDA proactively disconnecting"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        client_id = data.get("client_id")
        if client_id:
            REGISTRY.unregister(client_id)
            self._send_json({"success": True})
        else:
            self._send_json({"error": "Missing client_id"}, 400)

    def _handle_response(self):
        """Handle IDA responses"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        request_id = data.get("request_id")
        response = data.get("response")

        if request_id and response:
            REGISTRY.set_response(request_id, response)
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "Missing request_id or response"}, 400)

    def _handle_api_request(self):
        """POST /api/request - forward an MCP request to IDA and return the response (called by the MCP client)"""
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        request = data.get("request")
        instance_id = data.get("instance_id")
        timeout = float(data.get("timeout", 60.0))
        if not request:
            self._send_json({"error": "Missing request"}, 400)
            return
        if not REGISTRY.has_instances():
            self._send_json({
                "error": "No active IDA instance. Please start IDA and press Ctrl+Alt+M to connect.",
                "response": None,
            })
            return
        response = REGISTRY.send_request(request, instance_id, timeout=timeout)
        self._send_json({"response": response})

    def _handle_sse(self, client_id: str):
        """Handle SSE connection"""
        instance = REGISTRY.get_by_client_id(client_id)
        if not instance:
            self._send_json({"error": "Unknown client_id"}, 404)
            return

        sse_queue = REGISTRY.get_sse_queue(client_id)
        if not sse_queue:
            self._send_json({"error": "No queue"}, 500)
            return

        # Send SSE headers
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        # Send connection established event
        self._send_sse_event("connected", {"client_id": client_id})

        try:
            while True:
                try:
                    # Send a heartbeat every 10 seconds to detect connection state
                    # Note: the heartbeat is one-way; only TCP disconnection (process exit) will fail
                    # When IDA's main thread is stuck the TCP connection still exists, so we won't falsely classify it as disconnected
                    item = sse_queue.get(timeout=10)
                    self._send_sse_event("request", item)
                except queue.Empty:
                    # Send a heartbeat; a write failure will trigger BrokenPipeError
                    self._send_sse_event("ping", {})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            # Unregister on disconnect
            REGISTRY.unregister(client_id)

    def _send_sse_event(self, event: str, data: dict):
        """Send an SSE event"""
        msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(msg.encode("utf-8"))
        self.wfile.flush()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server: each request (including long-lived SSE connections) is handled in its own thread, so a second IDA's /register won't be blocked."""
    daemon_threads = True


class IDAHttpServer:
    """IDA HTTP+SSE server"""

    def __init__(self, port: int = 13337):
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start the server"""
        if self._running:
            return

        try:
            self._server = ThreadedHTTPServer(("127.0.0.1", self.port), IDARequestHandler)
            self._server.timeout = 1
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

            print(f"[HTTP] Server started (multi-threaded): http://127.0.0.1:{self.port}", file=sys.stderr)
            sys.stderr.flush()
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"[HTTP] Port {self.port} is already in use, skipping HTTP server start", file=sys.stderr)
                sys.stderr.flush()
            else:
                raise

    def _serve(self):
        """Serve loop (each accepted connection is dispatched to a new thread by ThreadingMixIn)"""
        while self._running:
            try:
                self._server.handle_request()
            except Exception:
                if self._running:
                    pass

    def stop(self):
        """Stop the server"""
        self._running = False
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    @property
    def registry(self) -> IDARegistry:
        """Get the registry"""
        return REGISTRY
