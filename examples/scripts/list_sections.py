import os
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
HELPER_DIR = SCRIPT_DIR.parent / "python"
sys.path.insert(0, str(HELPER_DIR))

import fyida  # noqa: E402


def main():
    project = fyida.current_project()
    query = os.environ.get("FYIDA_QUERY") or (sys.argv[1] if len(sys.argv) > 1 else None)
    sections = project.sections(query)

    print(f"sections, {len(sections)}")
    for section in sections:
        print(
            f"{section.name} "
            f"VA {section.va:016X} RVA {section.rva:08X} "
            f"FO {section.file_offset:08X} raw 0x{section.raw_size:X} "
            f"{section.permissions}"
        )


if __name__ == "__main__":
    main()
