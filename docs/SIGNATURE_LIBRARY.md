# FY_IDA Signature Library

FY_IDA supports a small JSON signature-library format for local, user-owned rules. The format is intentionally simple and does not depend on public metadata services.

## Format

```json
{
  "name": "My Local Signatures",
  "version": "0.1.0",
  "rules": [
    {
      "id": "create-process",
      "name": "Process Creation API",
      "kind": "user",
      "library": "Windows API",
      "target": "import",
      "import_name_contains": ["CreateProcess"],
      "confidence": 85,
      "evidence": "Local triage rule"
    }
  ]
}
```

Rule fields:

- `name`: Display name for the match.
- `kind`: Optional classification. Supported values include `user`, `crt-startup`, `security-cookie`, `exception-handling`, `memory-routine`, `runtime-import`, and `pattern`.
- `target`: Optional target scope, `import` or `function`.
- `import_name_contains`: All strings must be present in the import display name.
- `import_dll_contains`: All strings must be present in the import DLL name.
- `function_name_contains`: All strings must be present in the function name.
- `library`, `evidence`, `confidence`: Optional metadata shown in GUI and headless reports.

## CLI

```powershell
target\release\fy_ida.exe --headless --signature-library examples\signatures\runtime_triage.json C:\samples\sample.exe
```

Use `--export-format json` or `--export runtime-signatures --export-format csv` to consume matches from automation.

## GUI

Use `分析 -> 应用签名库...` and select a JSON file. The loaded library is applied to the current analysis and reused for newly opened files during the same session.
