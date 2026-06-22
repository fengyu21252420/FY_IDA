# Changelog

All notable changes to FY_IDA should be documented in this file.

Version format during early development: `vMAJOR.MINOR.PATCH-alpha.N`.

## v0.10.0-alpha.1 - 2026-06-23

### Added

- Added a report-based headless output layer for PE and Raw Binary analysis.
- Added `--export-format text|json|csv` for headless reports.
- Added `--export all|summary|functions|strings|imports|exports|xrefs|types` for selected CSV/text-oriented exports.
- Added `--output <OUTPUT>` to write headless reports to files.
- Added JSON reports with input metadata, SHA-256, sections, functions, strings, imports, exports, relocations, xrefs, CFG/call-graph counts, PDB records, PDB symbols, PDB types, and type-library summaries.
- Added CSV exports for summaries, functions, strings, imports, exports, xrefs, and types.
- Added `--batch-dir <DIR>` and `--recursive` for batch directory analysis.
- Added batch text/JSON/CSV summaries with per-file status, elapsed time, analysis counts, and nested JSON reports for successful files.
- Added `--timeout-ms <MS>` timeout reporting for single-file and batch headless runs.
- Added `--error-report <REPORT>` to write JSON error reports for failed single-file or batch runs.

### Changed

- Updated the workspace version to `0.10.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the headless/export checkpoint.
- Reworked the CLI crate around a stable serializable report model while keeping the GUI positional file behavior intact.

### Fixed

- Headless output can now be consumed by scripts without scraping console text when JSON or CSV output is selected.

### Known Issues

- Timeout handling is cooperative and reports overruns after an analysis call returns; it does not preempt or kill in-progress analysis.
- Batch raw mode applies the same Raw Binary base/entry/arch options to every file in the directory.
- JSON batch reports include nested per-file reports and can become large on big directories.
- Export filtering currently affects CSV/text-oriented output; JSON single-file reports include the complete report model.

### Recovery

- Source tag: `v0.10.0-alpha.1`.
- Roll back with: `git checkout v0.10.0-alpha.1`.

## v0.9.0-alpha.1 - 2026-06-23

### Added

- Added a schema v3 internal type model covering integers, pointers, arrays, structs, unions, enums, typedefs, opaque records, and function prototypes.
- Added project-level type applications for addresses and functions, with persistence in FY_IDA project files.
- Added a built-in minimal Windows/CRT type library with common aliases, pointer types, and CRT function prototypes.
- Added lightweight C Header import for typedefs, structs, unions, enums, and function prototypes.
- Added C Header export for the current project type library.
- Added GUI Type menu actions for local types, new structs, new enums, function prototypes, C Header import/export, type-library import, and applying a type to the current address or function.
- Added real Local Types and Structures panels in the right sidebar.
- Added applied type and function prototype display in the property panel and disassembly row comments.
- Added type-library and type-application matches to global search.
- Added headless `--type-header <HEADER>` and `--export-types <HEADER>` support for importing/exporting type libraries.
- Added unit coverage for type-library persistence, C Header import/export, and type applications.

### Changed

- Updated the workspace version to `0.9.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and project schema metadata for the type-system checkpoint.
- Saved projects now include project type libraries and type applications in addition to PDB symbol snapshots.
- PDB UDT summaries are merged into the local project type list after PDB loading.

### Fixed

- The GUI Local Types and Structures tabs now show real project data instead of placeholders.
- Reopened projects can restore saved user/Header/PDB type entries and address/function type applications.

### Known Issues

- C Header import is a lightweight parser for common declarations; it does not perform full preprocessing, macro expansion, or complete C semantic analysis.
- PDB type recovery is still summary-level UDT recovery; full TPI/IPI struct layouts, enums, classes, and prototypes remain future work.
- Type applications are metadata overlays only; they do not yet drive decompiler type propagation or stack-variable recovery.
- Function prototype editing stores and displays prototypes, but argument/local-variable modeling remains future work.

### Recovery

- Source tag: `v0.9.0-alpha.1`.
- Roll back with: `git checkout v0.9.0-alpha.1`.

## v0.8.0-alpha.1 - 2026-06-23

### Added

- Added PE Debug Directory / CodeView parsing for RSDS and NB10 PDB records, including PDB path, GUID, age, signature, RVA, and file offset metadata.
- Added external PDB loading through the Rust `pdb` crate, with public/code/data/procedure/UDT symbol extraction.
- Added MSVC and Rust demangle support for recovered PDB symbol display names.
- Added PDB symbol overlays for discovered function names and call graph nodes.
- Added PDB-derived function entries for executable public/procedure symbols not reached by the current recursive descent analyzer.
- Added PDB symbols to the GUI Names list, quick jump, global search, and disassembly row comments.
- Added automatic GUI PDB candidate lookup from PE CodeView paths and same-directory PDB filenames.
- Added manual GUI PDB loading through the File menu.
- Added `--pdb <PDB>` headless support for PE analysis.
- Added PDB record, symbol, and type summaries to headless output.
- Added schema v2 project snapshots for PDB debug info, symbols, UDT summaries, and module/source hints.
- Added project reopen support for restoring saved PDB symbol snapshots when the original PDB is unavailable.
- Added unit coverage for CodeView PDB record parsing, project PDB snapshot persistence, and MSVC demangling.

### Changed

- Updated the workspace version to `0.8.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and project schema metadata for the PDB/symbol checkpoint.
- Added `pdb`, `msvc-demangler`, and `rustc-demangle` dependencies.

### Fixed

- Saved FY_IDA projects can now retain symbol information recovered from PDB loading instead of relying only on automatic analysis names.

### Known Issues

- PDB type recovery is currently limited to UDT symbol summaries; full TPI/IPI struct, union, enum, class layout, and function prototype recovery remain future work.
- Source path recovery is currently based on module and object-file hints; full line-program source file enumeration remains future work.
- PDB matching checks GUID/age when CodeView data is present, but still allows manual loading of non-matching PDB files for inspection.
- PDB symbol overlays only rename exact-address function entries; richer thunk/import/library classification is still planned.

### Recovery

- Source tag: `v0.8.0-alpha.1`.
- Roll back with: `git checkout v0.8.0-alpha.1`.

## v0.7.0-alpha.1 - 2026-06-23

### Added

- Added basic block, function CFG, CFG edge, call graph node, and call graph edge models to `StaticAnalysis`.
- Added CFG generation for discovered PE and Raw Binary functions using decoded x64 branch, fallthrough, and return flow.
- Added direct-call graph construction from discovered function callsites.
- Added CFG and call graph summary lines to GUI analysis logs and headless output.
- Added a real GUI Function Graph tab with clickable basic block summaries, instruction previews, CFG edges, and zoom/pan/reset controls.
- Added a real GUI Call Graph tab with clickable function nodes, direct-call edges, callsites, and zoom/pan/reset controls.
- Added clickable graph navigation back into the disassembly view.
- Added unit coverage for CFG true/false/fallthrough edges and call graph generation from PE/Raw samples.

### Changed

- Updated the workspace version to `0.7.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and function-list summaries for the CFG/call graph checkpoint.

### Fixed

- The Function Graph and Call Graph center tabs now display real analysis data instead of placeholders.

### Known Issues

- CFG generation is based on the current conservative linear decode per discovered function; recursive intra-function block discovery and jump table expansion remain future work.
- The graph views are high-density clickable summaries with zoom/pan controls, not yet a full freeform node-layout canvas.
- Call graph edges currently cover direct calls discovered by the x64 decoder; indirect calls, import thunk resolution, library filtering, and thunk classification remain future work.

### Recovery

- Source tag: `v0.7.0-alpha.1`.
- Roll back with: `git checkout v0.7.0-alpha.1`.

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
