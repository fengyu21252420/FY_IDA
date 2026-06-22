# GitHub Workflow

This document defines the recovery-focused GitHub workflow for FY_IDA.

## Repository

- Name: `FY_IDA`
- Visibility: private
- Owner: personal GitHub account
- Main branch: `main`

## Iteration Rules

Each meaningful iteration must do all of the following:

1. Build or verify the current state when possible.
2. Update `CHANGELOG.md`.
3. Commit with a clear message.
4. Tag recoverable versions.
5. Push commits and tags to GitHub.
6. Create a GitHub Release when there is a useful executable or milestone artifact.

## Branch Strategy

- `main`: stable and recoverable checkpoints.
- `iter/<short-name>`: active implementation branch for one iteration.
- `fix/<short-name>`: small bug fix branch.
- `experiment/<short-name>`: risky experiments that may be discarded.

## Commit Message Style

Use short imperative messages:

```text
docs: add initial development plan
app: scaffold egui shell
loader: parse PE headers
analysis: add string scanner
```

## Version Tags

Early versions should use alpha tags:

```text
v0.1.0-alpha.0  planning baseline
v0.1.0-alpha.1  Rust workspace and GUI shell
v0.2.0-alpha.1  PE loader
v0.3.0-alpha.1  x64 disassembly
v0.4.0-alpha.1  functions, strings, imports, xrefs
```

Create an annotated tag:

```powershell
git tag -a v0.1.0-alpha.0 -m "Initial planning baseline"
git push origin main --tags
```

## Release Notes Template

```md
## Summary

Short description of this checkpoint.

## Added

- New features.

## Changed

- Behavior or structure changes.

## Fixed

- Bugs fixed.

## Known Issues

- Current limitations.

## Recovery

- Source tag: `vX.Y.Z-alpha.N`
- Roll back with: `git checkout vX.Y.Z-alpha.N`
```

## Recovery Commands

Inspect available checkpoints:

```powershell
git tag --list
```

Restore files from a known tag into a new branch:

```powershell
git switch -c recover/from-v0.1.0-alpha.0 v0.1.0-alpha.0
```

Undo a bad commit on `main` without rewriting history:

```powershell
git revert <bad_commit_sha>
git push origin main
```

Hard reset should only be used after manually backing up current work.

## Remote Setup

Preferred remote URL after the private GitHub repository exists:

```powershell
git remote add origin https://github.com/<github-username>/FY_IDA.git
git push -u origin main --tags
```

If GitHub CLI is installed and authenticated:

```powershell
gh repo create FY_IDA --private --source . --remote origin --push
git push origin --tags
```

