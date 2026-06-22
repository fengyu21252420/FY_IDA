import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

import fyida

project = fyida.current_project()
imports = project.imports()
print(f"{project.input.path}: {len(imports)} imports")
for item in imports[:16]:
    print(item.display_name)
