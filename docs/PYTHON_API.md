# FY_IDA Python API

FY_IDA v0.20.0-alpha.1 and later expose a lightweight script API through environment variables and the headless JSON report model.

## Headless Scripts

Run a script after analysis:

```powershell
target\release\fy_ida.exe --headless --python-script examples\scripts\list_imports.py C:\path\sample.exe
```

The script receives:

- `FYIDA_REPORT_JSON`: UTF-8 JSON report path.
- `FYIDA_INPUT_PATH`: analyzed input path.
- `FYIDA_INPUT_KIND`: `PE` or `Raw Binary`.
- `FYIDA_AUTOMATION_LABEL`: `script` for direct scripts, or a plugin label.
- `FYIDA_AUTOMATION_KIND`: `script` or `plugin`.

The JSON report contains input metadata, sections, functions, strings, imports, exports, relocations, xrefs, PDB records/symbols/types, the current type library, optional headless search results, and structured Python automation results.

Successful Python runs are also recorded under `automation.runs` with label, kind, plugin metadata, script path, status, exit code, elapsed time, stdout, stderr, and output-truncation flags. Use `--export automation --export-format text` or `--export automation --export-format csv` to emit only those run records.

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

Run selected plugin IDs:

```powershell
target\release\fy_ida.exe --headless --plugins-dir examples\plugins\import-summary --plugin import-summary C:\path\sample.exe
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

This first API is process-based rather than embedded. It keeps the Windows single-exe core usable without bundling a Python runtime.
