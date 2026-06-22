import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

import fyida

project = fyida.current_project()

print("Import Summary")
for item in project.imports()[:10]:
    print(f"- {item.display_name}")
