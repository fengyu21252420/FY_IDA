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

`v0.5.0-alpha.1` contains the first project database and manual annotation checkpoint. It can start `fy_ida.exe`, open a Windows x64 PE or x64 Raw Binary, show real EntryPoint-near instructions, list discovered functions/strings/imports/exports/relocations/xrefs, and save or reopen FY_IDA project files with user names, comments, bookmarks, and manual code/data markings.

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
