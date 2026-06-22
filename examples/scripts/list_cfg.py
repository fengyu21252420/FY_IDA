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
    cfgs = project.cfgs(query)

    print(f"cfgs, {len(cfgs)}")
    for cfg in cfgs[:32]:
        function_start = cfg.function_start
        blocks = cfg.get("blocks", [])
        edges = cfg.get("edges", [])
        print(f"function {function_start:016X}, blocks {len(blocks)}, edges {len(edges)}")
        for block in blocks[:16]:
            print(
                f"  block {block['start_va']:016X}-{block['end_va']:016X}, "
                f"insns {block['instruction_count']}, calls {block['call_count']}"
            )
            for instruction in block.get("instructions", [])[:4]:
                branch = instruction.get("branch_target")
                target = f" -> {branch:016X}" if branch is not None else ""
                print(
                    f"    {instruction['address']:016X} "
                    f"{instruction['mnemonic']} {instruction['operands']} "
                    f"[{instruction['flow']}]{target}"
                )
        for edge in edges[:32]:
            print(f"  edge {edge['from_va']:016X} -> {edge['to_va']:016X} {edge['kind']}")


if __name__ == "__main__":
    main()
