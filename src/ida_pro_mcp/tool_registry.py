"""Tool definition parser

Parses tool and resource definitions from ida_mcp/api_*.py files,
generates MCP tool schemas for server.py to register.

Does not import any IDA modules; only parses the source code.
"""

import ast
import os
from dataclasses import dataclass, field
from typing import Any, Optional

# Registry exported by the TypedDict parser: {TypeName: {"properties": {...}, "required": [...]}}
_TYPEDDICT_REGISTRY: dict[str, dict] = {}


class TypedDictParser(ast.NodeVisitor):
    """AST parser that extracts TypedDict class definitions from utils.py"""

    def __init__(self):
        self.registry: dict[str, dict] = {}

    def visit_ClassDef(self, node: ast.ClassDef):
        if not node.bases:
            self.generic_visit(node)
            return
        base_names = []
        total_false = False
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.append(base.id)
            elif isinstance(base, ast.Tuple):
                for elt in base.elts:
                    if isinstance(elt, ast.Name):
                        base_names.append(elt.id)
        for kw in (node.keywords or []):
            if kw.arg == "total" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                total_false = True
                break
        if "TypedDict" in base_names:
            schema = self._parse_typeddict_body(node, total_false)
            if schema:
                self.registry[node.name] = schema
        self.generic_visit(node)

    def _parse_typeddict_body(self, node: ast.ClassDef, total_false: bool) -> dict | None:
        properties = {}
        required = []
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                field_name = stmt.target.id
                type_schema, is_required = self._parse_field_annotation(stmt.annotation, total_false)
                if type_schema is not None:
                    properties[field_name] = type_schema
                    if is_required:
                        required.append(field_name)
        if not properties:
            return None
        return {"type": "object", "properties": properties, "required": required}

    def _parse_field_annotation(self, node: ast.expr, default_optional: bool) -> tuple[dict | None, bool]:
        is_required = not default_optional
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                if node.value.id == "Annotated" and isinstance(node.slice, ast.Tuple) and len(node.slice.elts) >= 2:
                    type_node = node.slice.elts[0]
                    desc_node = node.slice.elts[1]
                    desc = ""
                    if isinstance(desc_node, ast.Constant):
                        desc = str(desc_node.value)
                    type_schema = self._type_node_to_schema(type_node)
                    if type_schema and desc:
                        type_schema = {**type_schema, "description": desc}
                    is_req = self._is_required_type(type_node) and not default_optional
                    return type_schema, is_req
                elif node.value.id == "NotRequired":
                    inner = node.slice if not isinstance(node.slice, ast.Tuple) else node.slice.elts[0]
                    type_schema = self._type_node_to_schema(inner)
                    desc = ""
                    if isinstance(inner, ast.Subscript) and isinstance(inner.value, ast.Name) and inner.value.id == "Annotated":
                        if isinstance(inner.slice, ast.Tuple) and len(inner.slice.elts) >= 2 and isinstance(inner.slice.elts[1], ast.Constant):
                            desc = str(inner.slice.elts[1].value)
                            type_schema = self._type_node_to_schema(inner.slice.elts[0])
                    if type_schema and desc:
                        type_schema = {**type_schema, "description": desc}
                    return type_schema, False
            type_schema = self._type_node_to_schema(node)
            return type_schema, is_required
        type_schema = self._type_node_to_schema(node)
        return type_schema, is_required

    def _is_required_type(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id == "NotRequired":
                return False
        return True

    def _collect_union_members(self, node: ast.expr) -> list[ast.expr]:
        """Flatten Union (a | b | c) to list of type nodes."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._collect_union_members(node.left) + self._collect_union_members(
                node.right
            )
        return [node]

    def _type_node_to_schema(self, node: ast.expr) -> dict | None:
        if isinstance(node, ast.Name):
            return self._simple_type_to_schema(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            members = self._collect_union_members(node)
            schemas = []
            for m in members:
                if isinstance(m, ast.Name) and m.id in ("None", "NoneType"):
                    continue
                s = self._type_node_to_schema(m)
                if s and s not in schemas:
                    schemas.append(s)
            if len(schemas) == 1:
                return schemas[0]
            if schemas:
                return {"anyOf": schemas}
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                if node.value.id == "list":
                    inner = node.slice if not isinstance(node.slice, ast.Tuple) else node.slice.elts[0]
                    inner_schema = self._type_node_to_schema(inner)
                    if inner_schema:
                        return {"type": "array", "items": inner_schema}
                elif node.value.id == "dict":
                    return {"type": "object"}
        return {"type": "object"}

    def _simple_type_to_schema(self, name: str) -> dict:
        m = {"str": "string", "int": "integer", "float": "number", "bool": "boolean"}
        if name in m:
            return {"type": m[name]}
        if name in self.registry:
            return dict(self.registry[name])
        return {"type": "object"}


def _load_typeddict_registry():
    """Load the TypedDict registry from utils.py (AST only, does not execute)"""
    global _TYPEDDICT_REGISTRY
    if _TYPEDDICT_REGISTRY:
        return
    script_dir = os.path.dirname(os.path.realpath(__file__))
    utils_path = os.path.join(script_dir, "ida_mcp", "utils.py")
    if not os.path.isfile(utils_path):
        return
    try:
        with open(utils_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        parser = TypedDictParser()
        parser.visit(tree)
        _TYPEDDICT_REGISTRY.update(parser.registry)
    except Exception:
        pass


@dataclass
class ToolParam:
    """Tool parameter definition"""
    name: str
    type_str: str  # raw type string
    description: str
    required: bool = True
    default: Any = None


@dataclass
class ToolDef:
    """Tool definition"""
    name: str
    description: str
    params: list[ToolParam] = field(default_factory=list)
    return_type: str = "Any"
    is_unsafe: bool = False
    source_file: str = ""


@dataclass
class ResourceDef:
    """Resource definition"""
    uri: str
    name: str
    description: str
    return_type: str = "Any"
    source_file: str = ""


class ToolParser(ast.NodeVisitor):
    """AST parser that extracts functions decorated with @tool and @resource"""

    def __init__(self, source_file: str = ""):
        self.tools: list[ToolDef] = []
        self.resources: list[ResourceDef] = []
        self.source_file = source_file
        self._unsafe_funcs: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit a function definition"""
        decorators = self._get_decorators(node)

        # Check for the @unsafe decorator
        is_unsafe = "unsafe" in decorators

        # Check for the @tool decorator
        if "tool" in decorators:
            tool_def = self._parse_tool(node, is_unsafe)
            if tool_def:
                self.tools.append(tool_def)

        # Check for the @resource decorator
        resource_uri = decorators.get("resource")
        if resource_uri:
            resource_def = self._parse_resource(node, resource_uri)
            if resource_def:
                self.resources.append(resource_def)

        self.generic_visit(node)

    def _get_decorators(self, node: ast.FunctionDef) -> dict[str, Any]:
        """Get the decorators of a function"""
        decorators = {}
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                # @tool, @unsafe, @idasync
                decorators[dec.id] = True
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    # @resource("uri"), @ext("group")
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        decorators[dec.func.id] = dec.args[0].value
                    else:
                        decorators[dec.func.id] = True
        return decorators

    def _parse_tool(self, node: ast.FunctionDef, is_unsafe: bool) -> Optional[ToolDef]:
        """Parse a tool function"""
        name = node.name
        description = ast.get_docstring(node) or f"Call {name}"
        params = self._parse_params(node)
        return_type = self._get_return_type(node)
        
        return ToolDef(
            name=name,
            description=description.strip(),
            params=params,
            return_type=return_type,
            is_unsafe=is_unsafe,
            source_file=self.source_file,
        )
    
    def _parse_resource(self, node: ast.FunctionDef, uri: str) -> Optional[ResourceDef]:
        """Parse a resource function"""
        name = node.name
        description = ast.get_docstring(node) or f"Resource {uri}"
        return_type = self._get_return_type(node)
        
        return ResourceDef(
            uri=uri,
            name=name,
            description=description.strip(),
            return_type=return_type,
            source_file=self.source_file,
        )
    
    def _parse_params(self, node: ast.FunctionDef) -> list[ToolParam]:
        """Parse function parameters"""
        params = []
        defaults_offset = len(node.args.args) - len(node.args.defaults)

        for i, arg in enumerate(node.args.args):
            # Skip the self parameter
            if arg.arg == "self":
                continue

            param_name = arg.arg
            type_str = "Any"
            description = ""

            # Parse the type annotation
            if arg.annotation:
                type_str, description = self._parse_annotation(arg.annotation)

            # Check whether a default value exists
            default_idx = i - defaults_offset
            has_default = default_idx >= 0 and default_idx < len(node.args.defaults)
            default_value = None
            if has_default:
                default_node = node.args.defaults[default_idx]
                default_value = self._get_constant_value(default_node)

            params.append(ToolParam(
                name=param_name,
                type_str=type_str,
                description=description,
                required=not has_default,
                default=default_value,
            ))

        return params

    def _parse_annotation(self, node: ast.expr) -> tuple[str, str]:
        """Parse a type annotation, returning (type_str, description)"""
        # Annotated[type, "description"]
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and node.value.id == "Annotated":
                if isinstance(node.slice, ast.Tuple) and len(node.slice.elts) >= 2:
                    type_node = node.slice.elts[0]
                    desc_node = node.slice.elts[1]
                    type_str = self._node_to_type_str(type_node)
                    description = ""
                    if isinstance(desc_node, ast.Constant):
                        description = str(desc_node.value)
                    return type_str, description
            # Other generic types such as list[str], Optional[int]
            return self._node_to_type_str(node), ""

        # Simple type
        return self._node_to_type_str(node), ""

    def _node_to_type_str(self, node: ast.expr) -> str:
        """Convert an AST node to a type string"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.Subscript):
            base = self._node_to_type_str(node.value)
            if isinstance(node.slice, ast.Tuple):
                args = ", ".join(self._node_to_type_str(e) for e in node.slice.elts)
            else:
                args = self._node_to_type_str(node.slice)
            return f"{base}[{args}]"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            # Union type: int | str
            left = self._node_to_type_str(node.left)
            right = self._node_to_type_str(node.right)
            return f"{left} | {right}"
        elif isinstance(node, ast.Attribute):
            return f"{self._node_to_type_str(node.value)}.{node.attr}"
        return "Any"

    def _get_return_type(self, node: ast.FunctionDef) -> str:
        """Get the return type"""
        if node.returns:
            return self._node_to_type_str(node.returns)
        return "Any"

    def _get_constant_value(self, node: ast.expr) -> Any:
        """Get a constant value"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.List):
            return [self._get_constant_value(e) for e in node.elts]
        elif isinstance(node, ast.Dict):
            return {
                self._get_constant_value(k): self._get_constant_value(v)
                for k, v in zip(node.keys, node.values)
                if k is not None
            }
        elif isinstance(node, ast.Name) and node.id == "None":
            return None
        return None


def parse_api_file(filepath: str) -> tuple[list[ToolDef], list[ResourceDef]]:
    """Parse a single API file"""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"[tool_registry] Parse error {filepath}: {e}")
        return [], []

    parser = ToolParser(source_file=os.path.basename(filepath))
    parser.visit(tree)

    return parser.tools, parser.resources


def parse_all_api_files(api_dir: str) -> tuple[list[ToolDef], list[ResourceDef]]:
    """Parse all api_*.py files under the directory"""
    all_tools: list[ToolDef] = []
    all_resources: list[ResourceDef] = []

    if not os.path.isdir(api_dir):
        print(f"[tool_registry] Directory does not exist: {api_dir}")
        return all_tools, all_resources

    for filename in sorted(os.listdir(api_dir)):
        if filename.startswith("api_") and filename.endswith(".py"):
            # Skip api_instances.py (it is connection management, not an IDA tool)
            if filename == "api_instances.py":
                continue

            filepath = os.path.join(api_dir, filename)
            tools, resources = parse_api_file(filepath)
            all_tools.extend(tools)
            all_resources.extend(resources)

    return all_tools, all_resources


def type_str_to_json_schema(type_str: str) -> dict:
    """Convert a type string to a JSON Schema"""
    _load_typeddict_registry()
    type_str = type_str.strip()

    # Handle Union type (list[str] | str)
    if " | " in type_str:
        parts = [p.strip() for p in type_str.split(" | ")]
        non_none = [p for p in parts if p.lower() not in ("none", "nonetype")]
        if len(non_none) == 1:
            return type_str_to_json_schema(non_none[0])
        return {"anyOf": [type_str_to_json_schema(p) for p in non_none]}

    # Handle Optional[T]
    if type_str.startswith("Optional[") and type_str.endswith("]"):
        inner = type_str[9:-1]
        return type_str_to_json_schema(inner)

    # Handle list[T]
    if type_str.startswith("list[") and type_str.endswith("]"):
        inner = type_str[5:-1]
        return {"type": "array", "items": type_str_to_json_schema(inner)}

    # Handle dict[K, V]
    if type_str.startswith("dict[") and type_str.endswith("]"):
        return {"type": "object"}

    # Basic type mapping
    type_map = {
        "str": {"type": "string"},
        "int": {"type": "integer"},
        "float": {"type": "number"},
        "bool": {"type": "boolean"},
        "None": {"type": "null"},
        "Any": {},
    }

    # Check whether it is a known type
    base_type = type_str.split("[")[0]
    if base_type in type_map:
        return type_map[base_type]

    # Query the TypedDict registry
    if base_type in _TYPEDDICT_REGISTRY:
        return dict(_TYPEDDICT_REGISTRY[base_type])

    return {"type": "object"}


def tool_to_mcp_schema(tool: ToolDef) -> dict:
    """Convert a ToolDef to an MCP tool schema"""
    properties = {}
    required = []

    for param in tool.params:
        prop = type_str_to_json_schema(param.type_str)
        if param.description:
            prop["description"] = param.description
        if param.default is not None:
            prop["default"] = param.default
        properties[param.name] = prop

        if param.required:
            required.append(param.name)

    # Forcibly inject instance_id for seamless routing
    properties["instance_id"] = {
        "type": "string",
        "description": "Required instance_id (or client_id) used to precisely route the request to a specific IDA instance. Call instance_list first to view and select an appropriate client ID."
    }
    required.append("instance_id")

    schema = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
        },
    }

    if required:
        schema["inputSchema"]["required"] = required

    return schema


def resource_to_mcp_schema(resource: ResourceDef) -> dict:
    """Convert a ResourceDef to an MCP resource schema"""
    return {
        "uri": resource.uri,
        "name": resource.name,
        "description": resource.description,
    }


# ============================================================================
# Tests
# ============================================================================

if __name__ == "__main__":
    import sys

    # Get the api directory
    script_dir = os.path.dirname(os.path.realpath(__file__))
    api_dir = os.path.join(script_dir, "ida_mcp")

    print(f"Parsing directory: {api_dir}")
    tools, resources = parse_all_api_files(api_dir)

    print(f"\nFound {len(tools)} tools:")
    for t in tools:
        params_str = ", ".join(f"{p.name}: {p.type_str}" for p in t.params)
        print(f"  - {t.name}({params_str}) -> {t.return_type}")
        if t.is_unsafe:
            print(f"    [UNSAFE]")

    print(f"\nFound {len(resources)} resources:")
    for r in resources:
        print(f"  - {r.uri} -> {r.name}")
