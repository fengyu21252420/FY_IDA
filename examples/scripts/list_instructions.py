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
    instructions = project.instructions(query=query)

    print(f"instructions, {len(instructions)}")
    for instruction in instructions[:256]:
        branch = instruction.get("branch_target")
        target = f" -> {branch:016X}" if branch is not None else ""
        print(
            f"{instruction.function_start:016X} "
            f"{instruction.address:016X} "
            f"{instruction.mnemonic} {instruction.operands} "
            f"[{instruction.flow}]{target}"
        )


if __name__ == "__main__":
    main()
