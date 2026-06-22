import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

import fyida

project = fyida.current_project()
renamed = 0

for item in project.imports():
    api_name = item.name or item.display_name.split("!")[-1]
    for xref in project.xrefs_to(item.thunk_va):
        function = project.function_at(xref.from_va)
        if function is None:
            continue
        new_name = f"uses_{fyida.safe_name(api_name)}_{function.start_va:016X}"
        project.set_name(function.start_va, new_name)
        project.set_function_comment(function.start_va, f"References import {item.display_name}")
        project.add_bookmark(function.start_va)
        renamed += 1

print(f"Queued {renamed} import-caller rename/comment/bookmark actions.")
