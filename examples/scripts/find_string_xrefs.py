import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

import fyida

project = fyida.current_project()
query = os.environ.get("FYIDA_QUERY") or (sys.argv[1] if len(sys.argv) > 1 else "http")
matches = project.strings(query)

print(f"{project.input.path}: {len(matches)} strings matching {query!r}")
for string in matches[:32]:
    print(f"{string.address:016X} {string.encoding} {string.value}")
    xrefs = project.xrefs_to(string.address)
    if not xrefs:
        print("  no xrefs")
        continue
    for xref in xrefs[:8]:
        print(f"  <- {xref.from_va:016X} {xref.kind} {xref.label}")
