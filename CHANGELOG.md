# Changelog

All notable changes to FY_IDA should be documented in this file.

Version format during early development: `vMAJOR.MINOR.PATCH-alpha.N`.

## v0.24.0-alpha.1 - 2026-06-23

### Added

- Added an `IndirectBranch` instruction-flow classification for x64 indirect branch instructions.
- Added import API call graph edges for resolved `call qword ptr [rip+IAT]` memory operands.
- Added import-thunk call graph edges for resolved `jmp qword ptr [rip+IAT]` thunks.
- Added import API external-node names to the call graph so pseudo-C and IR call targets can show DLL/API names.
- Added unit coverage for indirect branch memory targets, IAT indirect calls, import-thunk edges, external import nodes, and pseudo-C import names.

### Changed

- Updated the workspace version to `0.24.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, Python API docs, and CHANGELOG metadata for the import-call graph checkpoint.
- Indirect branch instructions now terminate conservative function decoding and CFG fallthrough, improving import-thunk boundaries.
- The GUI call graph labels external nodes backed by import names as "导入 API".

### Known Issues

- Import call graph recovery still requires the IAT memory operand to resolve to a parsed import thunk VA.
- Register-computed indirect calls and non-IAT virtual dispatch remain unresolved.
- Headless JSON currently exports call graph counts but not detailed call graph node/edge rows.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.24.0-alpha.1`.
- Roll back with: `git checkout v0.24.0-alpha.1`.

## v0.23.0-alpha.1 - 2026-06-23

### Added

- Added x64 decoded-instruction memory target metadata for RIP-relative and absolute memory operands.
- Added PE memory-xref classification for string, import IAT thunk, relocation, and data-section targets.
- Added Raw Binary memory-xref classification for string and data targets.
- Added unit coverage for memory-target extraction and PE/Raw memory xrefs.

### Changed

- Updated the workspace version to `0.23.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, Python API docs, and CHANGELOG metadata for the memory-xref checkpoint.
- Xref views, search, headless reports, and Python helpers can now see data-oriented xrefs in addition to direct code calls and jumps.

### Fixed

- RIP-relative x64 references to strings and import IAT thunks are now recovered as xrefs, improving import-caller automation such as `examples/scripts/batch_rename_import_callers.py`.

### Known Issues

- Memory xrefs do not yet track read/write direction or register-computed indirect memory targets.
- Import-caller recovery still depends on discovered functions reaching the instruction that references the IAT thunk.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.23.0-alpha.1`.
- Roll back with: `git checkout v0.23.0-alpha.1`.

## v0.22.0-alpha.1 - 2026-06-23

### Added

- Added Python annotation actions through `FYIDA_ACTIONS_JSON` for names, address comments, function comments, bookmarks, and manual code/data definitions.
- Added headless `--save-project <PROJECT>` for saving a single-file analysis report and applied Python annotations as a FY_IDA project file.
- Added JSON report `annotations`, automation `action_count`, and `automation.actions` records.
- Added text/CSV automation exports for action rows alongside run rows.
- Added helper methods in `examples/python/fyida.py` for `set_name`, `set_comment`, `set_function_comment`, `add_bookmark`, `mark_code`, and `mark_data`.
- Added `examples/scripts/batch_rename_import_callers.py` to queue import-caller renames, function comments, and bookmarks.
- Added CLI unit coverage for `--save-project`, Python action parsing/application, automation action exports, and project serialization with script annotations.

### Changed

- Updated the workspace version to `0.22.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, Python API docs, and CHANGELOG metadata for the Python annotation-action checkpoint.

### Known Issues

- `--save-project` currently supports single-file headless analysis only, not batch directory reports.
- Python automation still uses the local `python` executable instead of an embedded interpreter.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.22.0-alpha.1`.
- Roll back with: `git checkout v0.22.0-alpha.1`.

## v0.21.0-alpha.1 - 2026-06-23

### Added

- Added an example `fyida` Python report helper module for functions, strings, imports, exports, relocations, xrefs, type queries, function lookup, and suspicious-import matching.
- Added `examples/scripts/find_string_xrefs.py` for string keyword searches with xref context.
- Added an example `malware-triage` plugin that scores suspicious imports, strings, and xrefs from the headless report.
- Added `FYIDA_SCRIPT_PATH` and `FYIDA_SCRIPT_DIR` environment variables for Python scripts and plugins.
- Added recursive plugin-root scanning for nested `plugin.json` manifests.
- Added CLI unit coverage for nested plugin manifest discovery.

### Changed

- Updated the workspace version to `0.21.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, Python API docs, and CHANGELOG metadata for the Python helper/examples checkpoint.
- Updated the existing import-list script and import-summary plugin to use the shared example Python helper.

### Known Issues

- The Python helper is an example module loaded by sample scripts/plugins; FY_IDA still does not embed or install a Python package globally.
- Python automation remains process-based through the local `python` executable.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.21.0-alpha.1`.
- Roll back with: `git checkout v0.21.0-alpha.1`.

## v0.20.0-alpha.1 - 2026-06-23

### Added

- Added structured JSON `automation` reports for successful headless Python scripts and plugins.
- Added `--export automation` for text and CSV automation run output.
- Added automation run metadata for label, kind, plugin ID/name/version, script path, status, exit code, elapsed time, stdout, stderr, and output truncation flags.
- Added `FYIDA_AUTOMATION_LABEL`, `FYIDA_AUTOMATION_KIND`, `FYIDA_PLUGIN_ID`, `FYIDA_PLUGIN_NAME`, and `FYIDA_PLUGIN_VERSION` environment variables for Python automation.
- Added batch `automation_runs` counts for successful file reports.
- Added CLI unit coverage for automation export parsing, structured JSON/text/CSV automation output, and missing selected-plugin IDs.

### Changed

- Updated the workspace version to `0.20.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, Python API docs, and CHANGELOG metadata for the structured-Python-automation checkpoint.
- Selected plugin IDs now fail clearly when no plugin directory is provided or no scanned manifest matches instead of silently running no plugin.

### Known Issues

- Python automation still uses the local `python` executable instead of an embedded interpreter.
- Automation stdout/stderr are bounded in reports to avoid oversized JSON/CSV output.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.20.0-alpha.1`.
- Roll back with: `git checkout v0.20.0-alpha.1`.

## v0.19.0-alpha.1 - 2026-06-23

### Added

- Added `--search <QUERY>` for headless single-file and batch analysis.
- Added `--export search` for text and CSV search-result output.
- Added JSON `search` reports with query, result count, category, optional address, label, and bounded snippet fields.
- Added report-level search coverage for functions, strings, imports, exports, relocations, xrefs, runtime signatures, PDB records/symbols/types, type libraries, pseudocode, IR, sections, direct addresses, and byte patterns.
- Added batch `search_results` counts when headless batch analysis is run with `--search`.
- Added unit coverage for search argument parsing, IR/runtime/type search matches, byte-pattern VA mapping, and CSV search escaping.

### Changed

- Updated the workspace version to `0.19.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the headless-search checkpoint.
- Python scripts and plugins now receive the search report in `FYIDA_REPORT_JSON` when `--search` is provided.

### Known Issues

- Headless search results are report rows, not interactive jump targets; GUI search remains the interactive navigation path.
- Byte-pattern search reports at most the first 64 byte hits and the total exported search result set is bounded to avoid oversized reports.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.19.0-alpha.1`.
- Roll back with: `git checkout v0.19.0-alpha.1`.

## v0.18.0-alpha.1 - 2026-06-23

### Added

- Added `--export pseudocode` and `--export ir` for headless text and CSV output.
- Added pseudocode line-address preservation in the headless report model through `line_addresses`.
- Added selected text output for summary, functions, strings, imports, exports, xrefs, runtime signatures, pseudocode, IR, and types.
- Added CSV exports for generated pseudo-C lines and generated IR instructions.
- Added unit coverage for pseudocode/IR export-kind parsing, CSV output, and IR text output.

### Changed

- Updated the workspace version to `0.18.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the pseudocode/IR headless-export checkpoint.
- Summary text/CSV output now includes the generated pseudocode function count.

### Known Issues

- Pseudocode and IR are still first-pass generated views; SSA, stack-variable modeling, and richer type propagation remain future work.
- Pseudocode CSV address fields are intentionally blank for generated header/brace lines that do not correspond to one source instruction address.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.18.0-alpha.1`.
- Roll back with: `git checkout v0.18.0-alpha.1`.

## v0.17.0-alpha.1 - 2026-06-23

### Added

- Added GUI global-search coverage for generated pseudo-C lines.
- Added GUI global-search coverage for generated IR instructions, including op, arguments, and source comments.
- Added clickable pseudocode/IR search results that navigate back to the source disassembly address.
- Added bounded search snippets so long generated lines stay readable in the search-results panel.
- Added unit coverage for IR search text assembly and snippet bounding.

### Changed

- Updated the workspace version to `0.17.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the pseudocode/IR-search checkpoint.

### Known Issues

- Pseudocode/IR search is currently GUI-side; headless exports already contain the generated pseudocode/IR model but do not yet provide a dedicated search command.
- Search results are still rendered as clickable rows rather than a sortable table.

### Recovery

- Source tag: `v0.17.0-alpha.1`.
- Roll back with: `git checkout v0.17.0-alpha.1`.

## v0.16.0-alpha.1 - 2026-06-23

### Added

- Added the formal `fy_ida.exe --headless analyze <FILE>` entry form requested by the development plan.
- Added CLI parsing helpers that distinguish GUI preselected files, legacy headless file input, and the new `analyze` command shape.
- Added CLI unit coverage for legacy `--headless <FILE>`, new `--headless analyze <FILE>`, batch `--headless analyze --batch-dir <DIR>`, and invalid command-like input.

### Changed

- Updated the workspace version to `0.16.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the formal-headless-analyze checkpoint.
- Kept the older `fy_ida.exe --headless <FILE>` form working for existing scripts while documenting the planned `analyze <FILE>` form.

### Known Issues

- The CLI still uses top-level options rather than a full nested clap subcommand tree, so `analyze` is parsed as a compatibility command token.
- GitHub Release creation remains dependent on an available GitHub release tool or authenticated API path in the local environment.

### Recovery

- Source tag: `v0.16.0-alpha.1`.
- Roll back with: `git checkout v0.16.0-alpha.1`.

## v0.15.0-alpha.1 - 2026-06-23

### Added

- Added a GUI "隐藏运行库函数" toggle in the View menu and left navigation panel.
- Added runtime/library-function filtering to the Functions list, including a visible hidden-count summary.
- Added runtime/library-function filtering to the Names list, hiding matching function and runtime-signature rows while preserving import/runtime import entries.
- Added call-graph filtering that hides runtime/library nodes and removes edges connected to hidden nodes.
- Added runtime classification text to the current Function Graph header when the selected function is recognized as runtime/library code.
- Added unit coverage for runtime-function filtering helpers and left-panel filter matching.

### Changed

- Updated the workspace version to `0.15.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the runtime-library-filtering checkpoint.
- The existing left-panel filter box now applies to the Functions and Names lists.

### Known Issues

- Runtime/library filtering is GUI-session state and is not yet persisted into project files or user preferences.
- Filtering currently targets function and pattern runtime signatures; imported runtime APIs remain visible so analysts can still inspect external API usage.
- Headless reports still export the full analysis model; runtime-function filtering is currently a GUI navigation feature.

### Recovery

- Source tag: `v0.15.0-alpha.1`.
- Roll back with: `git checkout v0.15.0-alpha.1`.

## v0.14.0-alpha.1 - 2026-06-23

### Added

- Added a FY_IDA-owned JSON signature-library format with local rules for import-name, import-DLL, and function-name matching.
- Added signature-library validation and application APIs in `fyida_analysis`.
- Added `--signature-library <JSON>` to headless analysis, supporting repeated local library imports.
- Added GUI signature-library import through the Analysis menu, with immediate application to the current analysis and reuse for newly opened files in the same session.
- Added a sample signature library at `examples/signatures/runtime_triage.json`.
- Added `docs/SIGNATURE_LIBRARY.md` with format and usage notes.

### Changed

- Updated the workspace version to `0.14.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the local-signature-library checkpoint.
- User signature matches are exported through the existing runtime-signature JSON/text/CSV report fields.

### Known Issues

- Local signature rules currently support exact contains-style metadata matching; byte-pattern and function-body hash signatures remain future work.
- GUI-loaded signature libraries are session-local and are not yet persisted into FY_IDA project files.
- Signature rules can annotate and search matches, but graph folding/filtering of library functions remains future work.

### Recovery

- Source tag: `v0.14.0-alpha.1`.
- Roll back with: `git checkout v0.14.0-alpha.1`.

## v0.13.0-alpha.1 - 2026-06-23

### Added

- Added a runtime signature model to `StaticAnalysis` with kind, target, library, evidence, and confidence metadata.
- Added conservative MSVC/CRT runtime recognition for security-cookie helpers, CRT startup helpers, exception-handling helpers, memory routines, and runtime DLL imports.
- Added a small instruction-pattern heuristic for memcpy/memset-style memory routines.
- Added runtime-signature output to headless JSON, text, CSV summary, and dedicated CSV exports.
- Added runtime-signature labels to the GUI function list, names list, property panel, disassembly row comments, and global search.
- Added unit coverage for common MSVC runtime-name classification.

### Changed

- Updated the workspace version to `0.13.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the runtime-signature checkpoint.
- PDB function-name overlays now refresh runtime signatures in addition to pseudo-C/IR names.

### Known Issues

- Runtime recognition is rule-based and intentionally conservative; it does not yet import external user signature libraries.
- Pattern matching can only flag simple movs/stos-style memory routines and does not yet hash or compare full function bodies.
- Library filtering/folding in graph views remains future work; current UI labels expose the classification but do not hide runtime functions.

### Recovery

- Source tag: `v0.13.0-alpha.1`.
- Roll back with: `git checkout v0.13.0-alpha.1`.

## v0.12.0-alpha.1 - 2026-06-23

### Added

- Added a first-pass pseudo-C and IR model derived from discovered function CFGs.
- Added pseudo-C generation for direct/indirect calls, conditional branches, unconditional jumps, returns, simple assignments, zeroing idioms, and condition comments.
- Added IR records with address, operation, arguments, and original-instruction comments.
- Added pseudo-C and IR output to `StaticAnalysis` and headless JSON reports.
- Added `Pseudocode` count to headless text output.
- Added real GUI Pseudocode and IR center tabs with clickable addresses back into the disassembly view.
- Added PDB refresh support so pseudocode function names are regenerated after PDB symbol overlays.

### Changed

- Updated the workspace version to `0.12.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the decompiler/IR checkpoint.

### Known Issues

- The decompiler is intentionally first-pass output; it does not yet perform SSA, variable recovery, stack-variable modeling, expression folding, or structured loop reconstruction.
- Branch conditions are emitted as annotated instruction comments instead of recovered high-level boolean expressions.
- Type applications are not yet propagated into pseudo-C declarations.

### Recovery

- Source tag: `v0.12.0-alpha.1`.
- Roll back with: `git checkout v0.12.0-alpha.1`.

## v0.11.0-alpha.1 - 2026-06-23

### Added

- Added `--python-script <PY>` to run a Python script after headless analysis.
- Added a headless Python report API through `FYIDA_REPORT_JSON`, `FYIDA_INPUT_PATH`, and `FYIDA_INPUT_KIND`.
- Added `--plugins-dir <DIR>` plugin manifest scanning and `--plugin <ID>` selection.
- Added plugin manifest support with `id`, `name`, `version`, `description`, `script`, and optional `menu` fields.
- Added plugin/script stdout and stderr capture into headless report messages.
- Added a basic GUI Python Console tab that runs local Python code with `FYIDA_SELECTED_FILE`, `FYIDA_CURRENT_VA`, and `FYIDA_CURRENT_FUNCTION`.
- Added `docs/PYTHON_API.md` with script and plugin usage.
- Added example Python script and example plugin manifest/script under `examples/`.

### Changed

- Updated the workspace version to `0.11.0-alpha.1`.
- Updated GUI, CLI, startup log, README status text, and CHANGELOG metadata for the Python/plugin checkpoint.

### Known Issues

- Python execution is process-based through the local `python` executable; FY_IDA does not yet embed or bundle a Python runtime.
- Scripts can read the report JSON but cannot yet mutate the open GUI project model or saved project annotations directly.
- GUI plugin menu registration is represented in manifests and report messages; full dynamic GUI menu binding remains future work.
- Plugin isolation is limited to process execution and captured output; no sandboxing is provided.

### Recovery

- Source tag: `v0.11.0-alpha.1`.
- Roll back with: `git checkout v0.11.0-alpha.1`.

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
