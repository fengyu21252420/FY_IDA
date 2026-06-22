# FY_IDA Python API

FY_IDA v0.11.0-alpha.1 exposes a lightweight script API through environment variables and the headless JSON report model.

## Headless Scripts

Run a script after analysis:

```powershell
target\release\fy_ida.exe --headless --python-script examples\scripts\list_imports.py C:\path\sample.exe
```

The script receives:

- `FYIDA_REPORT_JSON`: UTF-8 JSON report path.
- `FYIDA_INPUT_PATH`: analyzed input path.
- `FYIDA_INPUT_KIND`: `PE` or `Raw Binary`.

The JSON report contains input metadata, sections, functions, strings, imports, exports, relocations, xrefs, PDB records/symbols/types, and the current type library.

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

## GUI Console

The GUI Python Console tab runs the text in its editor through the local `python` executable. It passes:

- `FYIDA_SELECTED_FILE`
- `FYIDA_CURRENT_VA`
- `FYIDA_CURRENT_FUNCTION`

This first API is process-based rather than embedded. It keeps the Windows single-exe core usable without bundling a Python runtime.
