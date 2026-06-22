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
    records = project.pdb_records(query)
    symbols = project.pdb_symbols(query)
    types = project.pdb_types(query)

    print(f"pdb_records, {len(records)}")
    for record in records[:32]:
        guid = record.get("guid") or ""
        age = record.get("age")
        age_text = f" age {age}" if age is not None else ""
        print(
            f"{record.format} {record.path} {guid}{age_text} "
            f"RVA {record.debug_rva:08X} FO {record.debug_file_offset:08X}"
        )

    print(f"pdb_symbols, {len(symbols)}")
    for symbol in symbols[:64]:
        address = symbol.get("address")
        prefix = f"{address:016X} " if address is not None else ""
        print(f"{prefix}[{symbol.kind}] {symbol.name} ({symbol.source})")

    print(f"pdb_types, {len(types)}")
    for type_item in types[:64]:
        print(f"[{type_item.kind}] {type_item.name} ({type_item.source})")


if __name__ == "__main__":
    main()
