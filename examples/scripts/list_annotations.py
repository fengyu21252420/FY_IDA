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
    names = project.names(query)
    comments = project.comments(query)
    function_comments = project.function_comments(query)
    bookmarks = project.bookmarks(query)
    manual_definitions = project.manual_definitions(query)

    print(f"names, {len(names)}")
    for item in names[:64]:
        print(f"{item.address:016X} {item.name}")

    print(f"comments, {len(comments)}")
    for item in comments[:64]:
        print(f"{item.address:016X} {item.text}")

    print(f"function_comments, {len(function_comments)}")
    for item in function_comments[:64]:
        print(f"{item.function_start:016X} {item.text}")

    print(f"bookmarks, {len(bookmarks)}")
    for item in bookmarks[:64]:
        print(f"{item.address:016X}")

    print(f"manual_definitions, {len(manual_definitions)}")
    for item in manual_definitions[:64]:
        print(f"{item.address:016X} {item.kind}")


if __name__ == "__main__":
    main()
