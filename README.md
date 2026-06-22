# FY_IDA

FY_IDA is a planned lightweight Windows x64 reverse-engineering tool inspired by common IDA-style workflows, but intentionally scoped down.

The project targets:

- Windows x64 PE analysis.
- Raw binary analysis.
- Static analysis first.
- PDB symbols and types.
- Function discovery, xrefs, strings, imports, exports, relocations.
- Hex view, linear disassembly, function list, CFG, call graph.
- Python scripting and local plugin automation.
- Later-stage x64 pseudo-C decompilation.

The project intentionally does not copy IDA code, icons, database formats, or proprietary UI assets.

## Current Status

`v0.10.0-alpha.1` contains the first headless export checkpoint. It can start `fy_ida.exe`, open a Windows x64 PE or x64 Raw Binary, show real EntryPoint-near instructions, list discovered functions/strings/imports/exports/relocations/xrefs, save or reopen FY_IDA project files with user annotations, PDB symbol snapshots, project type libraries, and type applications, navigate and search through analysis views, render byte-synchronized Hex rows, display generated function CFG/call graph data, parse PE CodeView PDB records, load external PDB public symbols with demangled names, create struct/enum/function types, import/export C Header definitions, apply types to addresses or functions, and run headless text/JSON/CSV reports, selected CSV exports, batch directory analysis, timeout checks, and JSON error reports.

## Recovery Strategy

Every meaningful iteration should be committed, tagged, and described in [CHANGELOG.md](CHANGELOG.md). Stable checkpoints should be pushed to GitHub and published as GitHub Releases when an executable exists.

Recommended first tag:

```powershell
git tag -a v0.1.0-alpha.0 -m "Initial planning baseline"
```

## Repository Policy

- `main` should stay recoverable.
- Feature work should use short-lived branches such as `iter/pe-loader`.
- Each iteration should update `CHANGELOG.md`.
- Release tags should use `vMAJOR.MINOR.PATCH-alpha.N` until the tool is stable.
