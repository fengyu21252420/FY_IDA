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
        self.actions_path = os.environ.get("FYIDA_ACTIONS_JSON")

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

    def cfgs(self, query=None):
        records = self._records("cfg_records")
        if not query:
            return records
        needle = query.casefold()
        return [
            item
            for item in records
            if needle in hex(item.get("function_start", 0)).casefold()
            or any(
                needle in hex(block.get(field, 0)).casefold()
                for block in item.get("blocks", [])
                for field in ("start_va", "end_va")
            )
            or any(
                needle in str(edge.get("kind", "")).casefold()
                or needle in hex(edge.get("from_va", 0)).casefold()
                or needle in hex(edge.get("to_va", 0)).casefold()
                for edge in item.get("edges", [])
            )
        ]

    def cfg_for(self, address):
        target = parse_address(address)
        for cfg in self.cfgs():
            if cfg.get("function_start") == target:
                return cfg
            for block in cfg.get("blocks", []):
                start = block.get("start_va")
                end = block.get("end_va")
                if start is not None and end is not None and start <= target < end:
                    return cfg
        return None

    def basic_blocks(self, function_start=None):
        blocks = []
        for cfg in self._selected_cfgs(function_start):
            for block in cfg.get("blocks", []):
                item = dict(block)
                item["function_start"] = cfg.get("function_start")
                blocks.append(Record(item))
        return blocks

    def cfg_edges(self, function_start=None, query=None):
        edges = []
        for cfg in self._selected_cfgs(function_start):
            for edge in cfg.get("edges", []):
                item = dict(edge)
                item["function_start"] = cfg.get("function_start")
                edges.append(Record(item))
        if not query:
            return edges
        needle = query.casefold()
        return [
            item
            for item in edges
            if needle in str(item.get("kind", "")).casefold()
            or needle in hex(item.get("from_va", 0)).casefold()
            or needle in hex(item.get("to_va", 0)).casefold()
        ]

    def instructions(self, function_start=None, query=None):
        instructions = self._records("instruction_records")
        if function_start is not None:
            target = parse_address(function_start)
            instructions = [
                item
                for item in instructions
                if item.get("function_start") == target
                or item.get("block_start") == target
                or item.get("address") == target
            ]
        if not instructions:
            instructions = []
            for cfg in self._selected_cfgs(function_start):
                for block in cfg.get("blocks", []):
                    for instruction in block.get("instructions", []):
                        item = dict(instruction)
                        item["function_start"] = cfg.get("function_start")
                        item["block_start"] = block.get("start_va")
                        item["block_end"] = block.get("end_va")
                        instructions.append(Record(item))
        if not query:
            return instructions
        needle = query.casefold()
        return [
            item
            for item in instructions
            if needle
            in " ".join(
                str(item.get(field, ""))
                for field in ("bytes", "mnemonic", "operands", "flow")
            ).casefold()
        ]

    def call_graph_nodes(self, query=None):
        return self._filter_records("call_graph_node_records", query, "name")

    def call_graph_edges(self, query=None):
        records = self._records("call_graph_edge_records")
        if not query:
            return records
        needle = query.casefold()
        return [
            item
            for item in records
            if needle in str(item.get("label", "")).casefold()
            or needle in hex(item.get("caller_va", 0)).casefold()
            or needle in hex(item.get("callee_va", 0)).casefold()
            or needle in hex(item.get("callsite_va", 0)).casefold()
        ]

    def callees_from(self, address):
        source = parse_address(address)
        return [edge for edge in self.call_graph_edges() if edge.get("caller_va") == source]

    def callers_to(self, address):
        target = parse_address(address)
        return [edge for edge in self.call_graph_edges() if edge.get("callee_va") == target]

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

    def set_name(self, address, name):
        self._append_action({"action": "rename", "address": parse_address(address), "name": name})

    def set_comment(self, address, text):
        self._append_action({"action": "comment", "address": parse_address(address), "text": text})

    def set_function_comment(self, function_start, text):
        self._append_action(
            {
                "action": "function_comment",
                "function_start": parse_address(function_start),
                "text": text,
            }
        )

    def add_bookmark(self, address):
        self._append_action({"action": "bookmark", "address": parse_address(address)})

    def mark_code(self, address):
        self._append_action(
            {"action": "manual_definition", "address": parse_address(address), "kind": "code"}
        )

    def mark_data(self, address):
        self._append_action(
            {"action": "manual_definition", "address": parse_address(address), "kind": "data"}
        )

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

    def _selected_cfgs(self, function_start):
        if function_start is None:
            return self.cfgs()
        cfg = self.cfg_for(function_start)
        return [cfg] if cfg is not None else []

    def _append_action(self, action):
        if not self.actions_path:
            raise RuntimeError("FYIDA_ACTIONS_JSON is not set; this run cannot write actions")
        path = Path(self.actions_path)
        if path.exists() and path.read_text(encoding="utf-8").strip():
            actions = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(actions, dict):
                actions = actions.get("actions", [])
        else:
            actions = []
        actions.append(action)
        path.write_text(json.dumps(actions, indent=2), encoding="utf-8")


def safe_name(text):
    cleaned = []
    for character in str(text):
        if character.isalnum() or character == "_":
            cleaned.append(character)
        else:
            cleaned.append("_")
    result = "".join(cleaned).strip("_")
    return result or "item"


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
