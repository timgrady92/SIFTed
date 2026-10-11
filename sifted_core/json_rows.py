"""Bounded JSON Lines and complete traversal of Volatility's result trees."""
import json

MAX_RECORD_BYTES = 64 * 1024 * 1024


def json_lines(handle):
    while True:
        line = handle.readline(MAX_RECORD_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_RECORD_BYTES:
            raise ValueError("JSON Lines record exceeds 64 MiB; output is incomplete.")
        if line.strip():
            yield json.loads(line)


def tree_rows(roots, check=lambda: None):
    pending = [(row, 0) for row in reversed(roots)]
    while pending:
        check()
        row, depth = pending.pop()
        if not isinstance(row, dict) or not isinstance(row.get("__children", []), list):
            raise ValueError("Invalid structured result row.")
        children = row.get("__children", [])
        visible = {key: value for key, value in row.items() if key != "__children"}
        if "__children" in row:
            visible["__depth"] = depth
        yield visible
        pending.extend((child, depth + 1) for child in reversed(children))
