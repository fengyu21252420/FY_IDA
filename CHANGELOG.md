# Changelog

All notable changes to FY_IDA should be documented in this file.

Version format during early development: `vMAJOR.MINOR.PATCH-alpha.N`.

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
