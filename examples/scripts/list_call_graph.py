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
    edges = project.call_graph_edges(query)

    print(f"call_graph_edges, {len(edges)}")
    for edge in edges[:128]:
        print(
            f"{edge.caller_va:016X} -> {edge.callee_va:016X} "
            f"@ {edge.callsite_va:016X} {edge.label}"
        )


if __name__ == "__main__":
    main()
