import json
import os
from pathlib import Path


class Record:
    def __init__(self, data):
        self._data = data or {}

    def __getattr__(self, name):
        try:
            return self._data[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __getitem__(self, name):
        return self._data[name]

    def get(self, name, default=None):
        return self._data.get(name, default)

    def to_dict(self):
        return dict(self._data)


class Project:
    def __init__(self, report):
        self.report = report
        self.input = Record(report.get("input", {}))
        self.analysis = report.get("analysis", {})
        self.type_library = report.get("type_library", {})
        self.search = report.get("search")
        self.automation = report.get("automation", {})

    def functions(self):
        return self._records("functions")

    def strings(self, query=None):
        return self._filter_records("strings", query, "value", "encoding")

    def imports(self, query=None):
        return self._filter_records("imports", query, "display_name", "dll", "name")

    def exports(self, query=None):
        return self._filter_records("exports", query, "name")

    def relocations(self):
        return self._records("relocations")

    def xrefs(self):
        return self._records("xrefs")

    def xrefs_to(self, address):
        target = parse_address(address)
        return [xref for xref in self.xrefs() if xref.get("to_va") == target]

    def xrefs_from(self, address):
        source = parse_address(address)
        return [xref for xref in self.xrefs() if xref.get("from_va") == source]

    def function_at(self, address):
        target = parse_address(address)
        for function in self.functions():
            start = function.get("start_va")
            end = start + function.get("size", 0)
            if start is not None and start <= target < end:
                return function
        return None

    def types(self, query=None):
        records = [Record(item) for item in self.type_library.get("types", [])]
        if not query:
            return records
        needle = query.casefold()
        return [
            item
            for item in records
            if needle in " ".join(
                str(item.get(field, "")) for field in ("name", "kind", "source", "signature")
            ).casefold()
        ]

    def suspicious_imports(self, names):
        needles = [name.casefold() for name in names]
        matches = []
        for item in self.imports():
            display = item.get("display_name", "").casefold()
            if any(needle in display for needle in needles):
                matches.append(item)
        return matches

    def _records(self, key):
        return [Record(item) for item in self.analysis.get(key, [])]

    def _filter_records(self, key, query, *fields):
        records = self._records(key)
        if not query:
            return records
        needle = query.casefold()
        return [
            item
            for item in records
            if needle in " ".join(str(item.get(field, "")) for field in fields).casefold()
        ]


def current_project(path=None):
    report_path = Path(path or os.environ["FYIDA_REPORT_JSON"])
    with report_path.open("r", encoding="utf-8") as handle:
        return Project(json.load(handle))


def parse_address(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 16 if any(c in text.lower() for c in "abcdef") else 10)
    raise TypeError(f"unsupported address value: {value!r}")
