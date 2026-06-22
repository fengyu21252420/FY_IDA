# FY_IDA Python API

FY_IDA v0.27.0-alpha.1 and later expose a lightweight script API through environment variables, the headless JSON report model, and a JSON action file for saved annotations.

## Headless Scripts

Run a script after analysis:

```powershell
target\release\fy_ida.exe --headless --python-script examples\scripts\list_imports.py C:\path\sample.exe
```

The script receives:

- `FYIDA_REPORT_JSON`: UTF-8 JSON report path.
- `FYIDA_INPUT_PATH`: analyzed input path.
- `FYIDA_INPUT_KIND`: `PE` or `Raw Binary`.
- `FYIDA_SCRIPT_PATH`: Python script path being executed.
- `FYIDA_SCRIPT_DIR`: directory containing the Python script.
- `FYIDA_ACTIONS_JSON`: writable JSON file where scripts can queue annotation actions.
- `FYIDA_AUTOMATION_LABEL`: `script` for direct scripts, or a plugin label.
- `FYIDA_AUTOMATION_KIND`: `script` or `plugin`.

The JSON report contains input metadata, sections, functions, strings, imports, exports, relocations, xrefs, PDB records/symbols/types, the current type library, optional headless search results, current annotations, and structured Python automation results. In v0.23.0-alpha.1 and later, xrefs include recovered x64 RIP-relative or absolute memory references to strings, import IAT thunks, relocations, and data sections. In v0.24.0-alpha.1 and later, resolved IAT indirect calls and import-thunk jumps also contribute import API edges to the generated call graph and pseudo-C/IR call targets. In v0.25.0-alpha.1 and later, `analysis.call_graph_node_records` and `analysis.call_graph_edge_records` expose detailed call graph nodes and edges in JSON, and `--export call-graph` emits text/CSV call graph rows. In v0.26.0-alpha.1 and later, `analysis.cfg_records` exposes function CFGs with blocks, edges, and per-block instructions; `--export cfg` emits text/CSV CFG rows, and headless search can match `cfg_block`, `cfg_instruction`, and `cfg_edge` records. In v0.27.0-alpha.1 and later, `analysis.instruction_records` exposes a flat decoded-instruction list with function and basic-block context; `--export instructions` emits text/CSV instruction rows, and headless search can match `instruction` records directly.

Successful Python runs are recorded under `automation.runs` with label, kind, plugin metadata, script path, status, exit code, elapsed time, stdout, stderr, and output-truncation flags. Annotation actions are recorded under `automation.actions`, summarized by `automation.action_count`, applied to report `annotations`, and saved by `--save-project`. Use `--export automation --export-format text` or `--export automation --export-format csv` to emit only automation run/action records.

## Helper Module

The example helper module at `examples\python\fyida.py` wraps `FYIDA_REPORT_JSON` into a small object API:

```python
import fyida

project = fyida.current_project()
for func in project.functions():
    print(hex(func.start_va), func.name)

for string in project.strings("http"):
    print(hex(string.address), string.value)
    for xref in project.xrefs_to(string.address):
        print("xref from", hex(xref.from_va))

for edge in project.call_graph_edges("CreateFileW"):
    print(hex(edge.caller_va), "calls", hex(edge.callee_va), edge.label)

for block in project.basic_blocks():
    print(hex(block.function_start), hex(block.start_va), block.instruction_count)

for instruction in project.instructions(query="call"):
    print(hex(instruction.address), instruction.mnemonic, instruction.operands)

project.set_name(0x140001000, "entry_main")
project.set_comment(0x140001004, "references URL string")
project.set_function_comment(0x140001000, "entry wrapper")
project.add_bookmark(0x140001000)
project.mark_code(0x140001000)
```

Example scripts add `examples\python` to `sys.path` before importing the helper. `examples\scripts\find_string_xrefs.py` searches strings and prints their xrefs; `examples\scripts\list_instructions.py` prints flat decoded instruction rows; `examples\scripts\list_call_graph.py` prints call graph edges; `examples\scripts\list_cfg.py` prints function CFG blocks, edges, and instruction previews; set `FYIDA_QUERY` or pass a first script argument when running these scripts directly. `examples\scripts\batch_rename_import_callers.py` demonstrates queuing names, function comments, and bookmarks for functions that reference imports; `project.xrefs_to(import.thunk_va)` includes recovered IAT memory references when the decoded x64 instruction targets the import thunk.

To persist script-requested annotations into a FY_IDA project file, run:

```powershell
target\release\fy_ida.exe --headless analyze --python-script examples\scripts\batch_rename_import_callers.py --save-project out.fyida.json C:\path\sample.exe
```

Writable helper methods append JSON actions to `FYIDA_ACTIONS_JSON`. FY_IDA currently supports `set_name`, `set_comment`, `set_function_comment`, `add_bookmark`, `mark_code`, and `mark_data`.

## Plugins

Plugins are JSON manifests plus Python scripts:

```json
{
  "id": "import-summary",
  "name": "Import Summary",
  "version": "0.1.0",
  "description": "Prints imported APIs.",
  "script": "import_summary.py",
  "menu": "Tools/Import Summary"
}
```

Run all manifests in a directory:

```powershell
target\release\fy_ida.exe --headless --plugins-dir examples\plugins\import-summary C:\path\sample.exe
```

You can also point `--plugins-dir` at a plugin root. FY_IDA recursively discovers nested `plugin.json` manifests:

```powershell
target\release\fy_ida.exe --headless --plugins-dir examples\plugins C:\path\sample.exe
```

Run selected plugin IDs:

```powershell
target\release\fy_ida.exe --headless --plugins-dir examples\plugins\import-summary --plugin import-summary C:\path\sample.exe
target\release\fy_ida.exe --headless --plugins-dir examples\plugins --plugin malware-triage C:\path\sample.exe
```

Plugin scripts additionally receive:

- `FYIDA_PLUGIN_ID`
- `FYIDA_PLUGIN_NAME`
- `FYIDA_PLUGIN_VERSION`

When `--plugin <ID>` is provided and no matching manifest is found, FY_IDA reports the missing ID instead of silently running nothing.

## GUI Console

The GUI Python Console tab runs the text in its editor through the local `python` executable. It passes:

- `FYIDA_SELECTED_FILE`
- `FYIDA_CURRENT_VA`
- `FYIDA_CURRENT_FUNCTION`

This API is process-based rather than embedded. It keeps the Windows single-exe core usable without bundling a Python runtime. Annotation actions are applied after each successful headless script/plugin process; GUI console runs do not currently write saved-project annotations.
