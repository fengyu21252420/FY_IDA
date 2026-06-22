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

`v0.17.0-alpha.1` contains the pseudocode/IR search checkpoint. It can start `fy_ida.exe`, open a Windows x64 PE or x64 Raw Binary, show real EntryPoint-near instructions, list discovered functions/strings/imports/exports/relocations/xrefs, import user-owned FY_IDA JSON signature libraries from the GUI or headless CLI, identify common MSVC/CRT runtime imports, security-cookie helpers, exception handlers, CRT startup clues, and memcpy/memset-style routines, hide runtime/library functions in the GUI function list and call graph, save or reopen FY_IDA project files with user annotations, PDB symbol snapshots, project type libraries, and type applications, navigate and search through analysis views including generated pseudo-C and IR, render byte-synchronized Hex rows, display generated function CFG/call graph data, parse PE CodeView PDB records, load external PDB public symbols with demangled names, create struct/enum/function types, import/export C Header definitions, apply types to addresses or functions, run `fy_ida.exe --headless analyze <file>` or the legacy `--headless <file>` form for text/JSON/CSV reports including runtime-signature data, selected CSV exports, batch directory analysis, timeout checks, JSON error reports, execute Python scripts against the JSON report API, scan plugin manifests, run a basic GUI Python console, and generate initial pseudo-C plus IR output from discovered x64 function CFGs.

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
