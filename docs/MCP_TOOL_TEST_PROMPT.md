# IDA Pro MCP Tool Complete Test Prompt

> A guide for AI or manual systematic testing of IDA MCP functions, verifying parameter passing, data parsing, and behavioral correctness.

---

## 0. Quick Copy: AI Test Instructions (Send Directly to AI)

```
Please systematically test the IDA Pro MCP tools (user-ida-pro-mcp) following these rules:

1. For each tool, try three parameter formats in sequence: string, object, and array (if the schema supports it)
2. Cover address formats: 0x401000, 401000, sub_401000, symbol names, invalid values
3. Test empty and boundary values: "", [], {}, count=0, excessively long input
4. Record "input → output/error" for each call and determine whether it matches expectations
5. Key checks: get_bytes supports `"addr:size"` string format, list_funcs `"0:50"` means offset:count (list index, not address range)

Priority tools: instance_list, int_convert, list_funcs, decompile, get_bytes, lookup_funcs, rename.
```

---

## 1. Pre-Test Setup

1. **Environment**: IDA Pro has a binary loaded (recommend a small executable like `/bin/ls` or a simple PE)
2. **Connection**: The IDA plugin has started the MCP service and the Broker is running
3. **Tools**: Call `user-ida-pro-mcp` server tools through an MCP client (e.g., Cursor, MCP Inspector)

---

## 2. Testing Principles

- **Parameter format diversity**: Each tool should be tested with `str`, `object`, and `array` input formats (if the schema supports it)
- **Boundary & exception cases**: Empty values, invalid values, excessively long input
- **Address formats**: `0x401000`, `401000` (decimal), `sub_401000`, symbol names
- **Recording**: Record "input → output/error" for each call and determine whether it matches expectations

---

## 3. Test Case Checklist

### 3.1 Instance Management (No IDA Load Required)

| Tool | Test Input | Expected |
|------|-----------|----------|
| `instance_list` | `{}` | Returns instance list, at least contains the current connection |
| `instance_current` | `{}` | Returns current instance id, name, binary_path, etc. |
| `instance_switch` | `{"instance_id": "<valid_id>"}` | Switch succeeds or no error |
| `instance_info` | `{"instance_id": "<valid_id>"}` | Returns detailed info for that instance |

---

### 3.2 Numeric Conversion (No IDA Dependency)

| Tool | Test Input | Expected |
|------|-----------|----------|
| `int_convert` | `{"inputs": "0x41"}` | Returns decimal=65, hex=0x41, ascii="A" |
| `int_convert` | `{"inputs": ["0x41", "255"]}` | Returns two conversion results |
| `int_convert` | `{"inputs": {"text": "0x1000", "size": 32}}` | Parses as 32-bit |
| `int_convert` | `{"inputs": "not_a_number"}` | Returns error, no crash |
| `int_convert` | `{"inputs": ""}` | Handles empty string correctly |

---

### 3.3 Core Queries

| Tool | Test Input | Expected |
|------|-----------|----------|
| `list_funcs` | `{"queries": "main"}` | Returns function list matching "main" |
| `list_funcs` | `{"queries": {"offset": 0, "count": 5}}` | Returns first 5 functions, includes `data` and `next_offset` |
| `list_funcs` | `{"queries": ["*", ""]}` | Two queries, second is full list (empty filter) |
| `list_funcs` | `{"queries": "0:50"}` | Returns first 50 functions (0:50 = offset:count list index, not address range) |
| `list_globals` | `{"queries": "g_"}` | Returns globals with names containing "g_" |
| `imports` | `{"offset": 0, "count": 10}` | Returns first 10 imports |
| `lookup_funcs` | `{"queries": "main"}` | Look up by name |
| `lookup_funcs` | `{"queries": "main, 0x401000"}` | Comma-separated, two queries |
| `lookup_funcs` | `{"queries": ["sub_401000", "start"]}` | Array format |

---

### 3.4 Disassembly & Decompilation

| Tool | Test Input | Expected |
|------|-----------|----------|
| `decompile` | `{"addr": "0x401000"}` | Returns pseudocode or error |
| `decompile` | `{"addr": "start"}` | Resolves by symbol name (if it exists) |
| `decompile` | `{"addr": "401000"}` | Decimal address should resolve |
| `decompile` | `{"addr": "invalid_addr_xyz"}` | Returns clear error, no crash |
| `disasm` | `{"addr": "0x401000"}` | Returns list of assembly lines |

---

### 3.5 Memory Read/Write

| Tool | Test Input | Expected |
|------|-----------|----------|
| `get_bytes` | `{"regions": {"addr": "0x401000", "size": 16}}` | Returns 16 bytes in hex |
| `get_bytes` | `{"regions": [{"addr": "0x401000", "size": 8}, {"addr": "0x402000", "size": 4}]}` | Batch read |
| `get_bytes` | `{"regions": "0x401000:16"}` | Supports `"addr:size"` and `"addr1:size1, addr2:size2"` |
| `get_int` | `{"queries": {"addr": "0x401000", "ty": "u32le"}}` | Returns integer |
| `get_int` | `{"queries": [{"addr": "0x401000", "ty": "i8"}]}` | Signed 8-bit |
| `get_string` | `{"addrs": "0x403000"}` | Returns string at that address |
| `get_string` | `{"addrs": "0x403000, 0x403010"}` | Comma-separated multiple addresses |
| `get_global_value` | `{"queries": "global_var_name"}` | Get value by name or address |

---

### 3.6 Cross-References & Calls

| Tool | Test Input | Expected |
|------|-----------|----------|
| `xrefs_to` | `{"addrs": "0x401000"}` | List of xrefs referencing that address |
| `xrefs_to` | `{"addrs": "0x401000, 0x402000"}` | Multiple addresses |
| `xrefs_to` | `{"addrs": ["0x401000"], "limit": 5}` | Maximum 5 results |
| `callees` | `{"addrs": "0x401000"}` | List of call targets from that function |
| `basic_blocks` | `{"addrs": "0x401000"}` | Basic blocks and successors |

---

### 3.7 Search

| Tool | Test Input | Expected |
|------|-----------|----------|
| `find_regex` | `{"pattern": "error|fail", "limit": 10}` | Matches within strings |
| `find_bytes` | `{"patterns": "48 8B ?? ?? ?? ?? ?? ??"}` | Byte pattern search |
| `find_bytes` | `{"patterns": ["48 8B", "FF 15"]}` | Multiple patterns |

---

### 3.8 Modification Operations (Use Caution — Recommend a Test IDB)

| Tool | Test Input | Expected |
|------|-----------|----------|
| `set_comments` | `{"items": {"addr": "0x401000", "comment": "test"}}` | Success or clear error |
| `rename` | `{"batch": {}}` | Returns empty object, no crash |
| `rename` | `{"batch": {"func": [{"addr": "0x401000", "name": "__test__"}]}}` | Rename result |
| `patch_asm` | `{"items": {"addr": "0x401000", "asm": "nop"}}` | Assembly patch |
| `define_func` | `{"items": {"addr": "0x401050"}}` | Defines function at specified address |

---

### 3.9 Types & Structures

| Tool | Test Input | Expected |
|------|-----------|----------|
| `read_struct` | `{"queries": {"addr": "0x403000"}}` | Reads structure at that address |
| `search_structs` | `{"filter": "FILE*"}` | Structures matching the name |
| `declare_type` | `{"decls": "typedef int my_t;"}` | Declares type |
| `infer_types` | `{"addrs": "0x401000"}` | Type inference |

---

### 3.10 Stack & Debugger (Debugger tools require `--unsafe`)

| Tool | Test Input | Expected |
|------|-----------|----------|
| `stack_frame` | `{"addrs": "0x401000"}` | Stack frame variables |
| `stack_frame` | `{"addrs": "0x401000, 0x402000"}` | Multiple functions |

---

## 4. Parameter & Data Exception Focus Areas

### 4.1 Type Mismatch

- Passing `str` to a parameter that only accepts `object`/`array` → depends on implementation. Verify whether `get_bytes.regions` supports `"addr:size"` strings and JSON strings
- Passing `array` to a parameter that only accepts `str` → depends on implementation; may error or be handled gracefully

### 4.2 Address Formats

- `0x401000`, `401000`, `0x140001000` (64-bit)
- `sub_401000`, `start`, `main` (symbol names)
- `invalid`, `0xGGGG` (illegal) → should return a clear error message

### 4.3 Batch Parameter Formats

- Comma-separated string: `"addr1, addr2"`
- JSON array: `["addr1", "addr2"]`
- Object array: `[{"addr": "0x401000", "size": 16}]`

### 4.4 Empty & Boundary Values

- Empty string `""`
- Empty array `[]`
- Empty object `{}`
- `count=0`, `limit=0`
- Excessively large `count`/`limit`

---

## 5. Execution Method & Recording Template

**Execution method**: Call MCP tools item-by-item per Section 3 and record:

```
Tool name: ____________
Input: ____________
Output/Error: ____________
Conclusion: ✓ Pass / ✗ Fail / ⚠ Unexpected but acceptable
Notes: ____________
```

**Summary**: At the end of testing, compile:
- Pass / fail counts
- List of discovered issues (with reproduction steps)
- Improvement suggestions (parameter formats, error messages, schema documentation)

---

## 6. Quick Regression Test Cases (Minimum Set)

If time is limited, at minimum execute:

1. `instance_list` + `instance_current`
2. `int_convert` (one each of str / array / object)
3. `list_funcs` (one each of str and object)
4. `decompile` (valid address + invalid address)
5. `get_bytes` (object and array)
6. `lookup_funcs` (comma-separated string)
7. `rename` (empty batch)
8. `get_bytes` with str `"0x401000:16"` and JSON string (e.g., `"[{\"addr\":\"0x401000\",\"size\":16}]"`) → should successfully return byte data
