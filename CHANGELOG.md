# Changelog

All notable changes to FY_IDA should be documented in this file.

Version format during early development: `vMAJOR.MINOR.PATCH-alpha.N`.

## v0.6.0-alpha.1 - 2026-06-23

### Added

- Added navigation history to `ProjectState` with back/forward stacks for GUI jumps.
- Added toolbar and shortcut support for navigation back/forward (`Esc`, `Alt+Left`, `Alt+Right`).
- Added symbolic quick jump resolution for function names, user names, imports, exports, and string keywords in addition to VA/RVA/File Offset input.
- Added clickable structured search results that jump back into the disassembly view.
- Added global search coverage for direct addresses, byte sequences, user names, address comments, function comments, bookmarks, manual code/data definitions, functions, strings, imports, exports, and xrefs.
- Added a real byte-backed Hex View centered on the current file offset, with VA/FO labels and clickable row navigation.
- Added clickable xref source/target addresses in the right-side cross-reference panel.
- Added unit coverage for navigation history back/forward behavior.

### Changed

- Updated the workspace version to `0.6.0-alpha.1`.
- Updated GUI, CLI, startup log, and README status text for the GUI analysis-experience checkpoint.

### Fixed

- Toolbar back/forward controls now perform real navigation instead of acting as placeholders.
- Hex View now renders loaded input bytes instead of static PE/Raw summary placeholder rows.

### Known Issues

- Search results are clickable text rows rather than a sortable/filterable result table.
- Hex View is synchronized around the current address but does not yet support byte selection or copy.
- Navigation history tracks address jumps only; full tab/layout restoration remains a future UI-state task.
- The function graph, call graph, and saved docking layout remain future milestones.

### Recovery

- Source tag: `v0.6.0-alpha.1`.
- Roll back with: `git checkout v0.6.0-alpha.1`.

## v0.5.0-alpha.1 - 2026-06-23

### Added

- Added a FY_IDA-owned `.fyida.json` project file format with schema version, app version, source path, file size, SHA-256 hash, load kind, load parameters, function summaries, and user annotations.
- Added project save, save-as, and open support in the GUI.
- Added SHA-256 source hashing and project-open hash mismatch warnings.
- Added user annotation storage for names, address comments, function comments, bookmarks, and manual code/data definitions.
- Added undo/redo support for rename, comments, bookmarks, and manual code/data definition commands.
- Added GUI actions and shortcuts for save, undo/redo, rename, comments, bookmarks, and manual code/data marking.
- Added annotation-aware function/name lists, disassembly comments, bookmark list, annotation panel, search, and project status display.
- Added unit coverage for project save/load round-trip, annotation undo/redo, SHA-256 persistence, and Raw/PE project state.

### Changed

- Updated the workspace version to `0.5.0-alpha.1`.
- Updated GUI, CLI, and README status text for the project database and manual annotation checkpoint.

### Fixed

- The toolbar and edit menu now call real annotation actions instead of disabled placeholders.

### Known Issues

- The first project format is JSON-based for readability and migration safety; a SQLite backend remains planned for later schema evolution.
- Project files reopen the original input path and warn on hash mismatch, but they do not yet embed original binary bytes.
- Function comments are created from the common comment dialog when the current address is a function entry; richer comment editing UI is still future work.
- Manual code/data definitions are persisted and displayed, but they do not yet change the analyzer output.

### Recovery

- Source tag: `v0.5.0-alpha.1`.
- Roll back with: `git checkout v0.5.0-alpha.1`.

## v0.4.1-alpha.1 - 2026-06-23

### Added

- Added a Raw Binary image model with user-supplied base address, entry address, x64 architecture, and VA/File Offset mapping helpers.
- Added Raw Binary loading with parameter validation and clear Chinese errors for empty files or out-of-range entry points.
- Added x64 Raw Binary entry-point disassembly through the existing `iced-x86` backend.
- Added Raw Binary static analysis for entry function discovery, direct call/jump xrefs, and ASCII/UTF-16LE string extraction.
- Added GUI Raw Binary file selection with base/entry/arch parameter dialog, Raw properties, Raw segment display, Raw Hex View rows, and Raw-aware quick jump.
- Added headless Raw Binary support through `--raw --base <addr> --entry <addr> --arch x64 <file>`.
- Added unit coverage for Raw mapping, Raw disassembly, Raw analysis, invalid Raw entry validation, and Raw project state.

### Changed

- Updated the workspace version to `0.4.1-alpha.1`.
- Updated GUI, CLI, and README status text for Raw Binary support.
- Corrected function summary instruction counts so decoding after a terminating `ret` is not counted as part of the function body.

### Fixed

- The “打开 Raw Binary” GUI path now loads files through the Raw Binary pipeline instead of falling through to PE parsing errors.

### Known Issues

- Raw Binary GUI currently supports only x64 with a simple base/entry dialog.
- Raw Binary analysis has no imports, exports, relocations, or section metadata because the format is user-supplied bytes only.
- Project database save/load, manual annotations, CFG graph rendering, and call graph rendering remain future milestones.

### Recovery

- Source tag: `v0.4.1-alpha.1`.
- Roll back with: `git checkout v0.4.1-alpha.1`.

## v0.4.0-alpha.1 - 2026-06-23

### Added

- Added PE Data Directory parsing for export, import, and base relocation analysis entry points.
- Added a `StaticAnalysis` model with discovered function summaries, ASCII/UTF-16LE strings, imports, exports, relocations, and direct code xrefs.
- Added basic recursive function discovery from the x64 EntryPoint through direct call targets.
- Added direct call/jump target metadata to decoded x64 instructions.
- Added GUI lists for real functions, names, strings, imports, exports, and basic xrefs.
- Added GUI search across functions, strings, imports, exports, and direct code xrefs.
- Added headless static-analysis summary output for command-line verification.
- Added unit coverage for functions, strings, imports, exports, relocations, and xrefs from a synthetic PE image.

### Changed

- Updated the workspace version to `0.4.0-alpha.1`.
- Updated GUI, CLI, and README status text for the basic static analysis checkpoint.
- Limited first-pass string extraction to NUL-terminated strings in non-executable sections to reduce false positives.

### Fixed

- Headless and GUI analysis now share one structured analysis path instead of displaying independent placeholder data.

### Known Issues

- Function discovery is still intentionally conservative and only follows direct call targets from x64 code.
- Data xrefs for strings/imports are not yet recovered from RIP-relative memory operands.
- Raw Binary loading, project database save/load, CFG graph rendering, and call graph rendering remain future milestones.

### Recovery

- Source tag: `v0.4.0-alpha.1`.
- Roll back with: `git checkout v0.4.0-alpha.1`.

## v0.3.0-alpha.1 - 2026-06-23

### Added

- Added a `fyida_disasm` crate backed by `iced-x86` for x64 instruction decoding.
- Added PE EntryPoint disassembly from mapped `.text` bytes with address, machine-code bytes, mnemonic, and operands.
- Added GUI disassembly rows that show real x64 EntryPoint instructions after opening a supported PE.
- Added headless EntryPoint disassembly output for command-line verification.
- Added unit tests for x64 decoding, invalid-instruction placeholder rows, and non-x64 PE error messaging.

### Changed

- Updated the workspace version to `0.3.0-alpha.1`.
- Updated GUI and CLI version text for the x64 disassembly MVP.
- Extended the loader API so callers can receive parsed PE metadata and original file bytes from one read.

### Fixed

- Invalid x64 instruction bytes now render as clear `db` placeholder rows instead of stopping analysis.
- Loading a failed/non-PE file no longer leaves the previous disassembly rows visible in the GUI.

### Known Issues

- Function discovery, imports, exports, relocations, strings, and xrefs are still future milestones.
- Disassembly is linear near the PE EntryPoint and does not yet follow control flow.
- Non-x64 PE files are loaded at the PE Header level but are not disassembled.

### Recovery

- Source tag: `v0.3.0-alpha.1`.
- Roll back with: `git checkout v0.3.0-alpha.1`.

## v0.2.0-alpha.1 - 2026-06-23

### Added

- Added a PE Loader MVP that parses DOS Header, NT Header, COFF File Header, Optional Header, ImageBase, EntryPoint, Machine, Subsystem, Characteristics, and Section Table data.
- Added VA/RVA/File Offset mapping helpers with unit test coverage.
- Added GUI PE summary output for basic header fields and section lists.
- Added clear Chinese error handling for non-PE files.
- Added headless PE summary output for command-line verification.

### Changed

- Updated the workspace version to `0.2.0-alpha.1`.
- Replaced file-open placeholders with PE parsing results in the GUI and logs.

### Fixed

- File selection no longer reports successful analysis for unsupported non-PE inputs.

### Known Issues

- x64 disassembly, imports, exports, relocations, strings, and xrefs are still future milestones.
- Raw Binary loading is still not implemented in this checkpoint.

### Recovery

- Source tag: `v0.2.0-alpha.1`.
- Roll back with: `git checkout v0.2.0-alpha.1`.

## v0.1.0-alpha.2 - 2026-06-23

### Added

- Added a Rust workspace for the FY_IDA application.
- Added `fyida_app`, `fyida_core`, `fyida_loader`, `fyida_analysis`, `fyida_ui`, and `fyida_cli` crates.
- Added the first runnable `fy_ida.exe` GUI shell with Chinese menus, toolbar, left navigation, central workspace, right information panel, bottom panel, and status bar.
- Added file selection through the GUI and command-line preselection, showing the selected file as not yet analyzed.
- Added placeholder disassembly, hex, pseudocode, graph, xref, output, search, and Python console views.
- Added basic CLI help and headless placeholder output.

### Changed

- Updated the repository status from planning-only to the first runnable GUI checkpoint.

### Fixed

- Nothing fixed yet.

### Known Issues

- PE, Raw Binary, x64 disassembly, xref, string, import, and export analysis are still placeholders.
- File opening records metadata only and does not parse binary contents yet.
- Project save/load and real docking customization are not implemented yet.

### Recovery

- Source tag: `v0.1.0-alpha.2`.
- Roll back with: `git checkout v0.1.0-alpha.2`.

## v0.1.0-alpha.1 - 2026-06-23

### Added

- Added the FY Classic Chinese UI design document.
- Defined the main window layout, Chinese menus, docking panels, toolbars, shortcuts, colors, and first GUI acceptance criteria.

### Changed

- Established the UI direction as an IDA-familiar reverse-engineering workflow with FY_IDA-owned visual design.

### Fixed

- Nothing fixed yet.

### Known Issues

- No application code exists yet.
- UI design is documented but not implemented.

### Recovery

- Planned recoverable tag: `v0.1.0-alpha.1`.

## v0.1.0-alpha.0 - 2026-06-23

### Added

- Added the initial product and engineering plan.
- Added the repository recovery strategy.
- Added the initial Git/GitHub workflow documentation.
- Added a repository README and ignore rules.

### Changed

- No code yet. This is the planning baseline.

### Fixed

- Nothing fixed yet.

### Known Issues

- No application code exists yet.
- GitHub remote creation still depends on an authenticated GitHub path on this machine.

### Recovery

- Planned recoverable tag: `v0.1.0-alpha.0`.
