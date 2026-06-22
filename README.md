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

`v0.28.0-alpha.1` contains the headless sections/relocations export checkpoint. It can start `fy_ida.exe`, open a Windows x64 PE or x64 Raw Binary, show real EntryPoint-near instructions, list discovered functions/strings/imports/exports/relocations/xrefs, recover x64 RIP-relative and absolute memory targets as string/import-IAT/relocation/data xrefs, resolve `call qword ptr [rip+IAT]` and import-thunk `jmp qword ptr [rip+IAT]` patterns into import API call graph edges, export PE section metadata and relocation records through dedicated text/CSV exports and the Python helper, export flat decoded instruction records through JSON/text/CSV and the Python helper, export detailed function CFG records with basic blocks, edges, and decoded block instructions through JSON/text/CSV and the Python helper, export detailed call graph node/edge records through JSON/text/CSV and the Python helper, import user-owned FY_IDA JSON signature libraries from the GUI or headless CLI, identify common MSVC/CRT runtime imports, security-cookie helpers, exception handlers, CRT startup clues, and memcpy/memset-style routines, hide runtime/library functions in the GUI function list and call graph, save or reopen FY_IDA project files with user annotations, PDB symbol snapshots, project type libraries, and type applications, navigate and search through analysis views including generated pseudo-C and IR, render byte-synchronized Hex rows, display generated function CFG/call graph data, parse PE CodeView PDB records, load external PDB public symbols with demangled names, create struct/enum/function types, import/export C Header definitions, apply types to addresses or functions, run `fy_ida.exe --headless analyze <file>` or the legacy `--headless <file>` form for text/JSON/CSV reports including sections, relocations, instruction, CFG, and runtime-signature data, write FY_IDA project files with `--save-project`, apply Python-requested names/comments/bookmarks/manual code-data annotations into those saved projects, export automation action rows, use the example `fyida` Python helper for sections/functions/instructions/strings/imports/exports/xrefs/CFG/call-graph/type queries and annotation methods including import-caller scripts, recursively scan plugin manifests with explicit selected-plugin validation, run a basic GUI Python console, and generate initial pseudo-C plus IR output from discovered x64 function CFGs.

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
