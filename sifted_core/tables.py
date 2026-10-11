"""Streaming structured results into a disposable, signature-keyed page cache."""
import csv
import json
import sqlite3
from pathlib import Path

from .tool_base import signature
from .json_rows import json_lines, tree_rows

CSV_FIELD_LIMIT = 16 * 1024 * 1024
csv.field_size_limit(CSV_FIELD_LIMIT)


class ResultTables:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)

    def page(self, source, offset=0, limit=100, max_bytes=1024 ** 3):
        source = str(Path(source).resolve())
        before = signature(source)
        if before[2] > max_bytes:
            raise ValueError("File exceeds the table import limit.")
        is_jsonl = source.lower().endswith(".jsonl")
        key = json.dumps(before)
        with sqlite3.connect(self.path, timeout=30) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS table_sources(path TEXT PRIMARY KEY, signature TEXT, columns TEXT, total INTEGER)")
            db.execute("CREATE TABLE IF NOT EXISTS table_rows(path TEXT, position INTEGER, data TEXT, PRIMARY KEY(path,position))")
            db.execute("BEGIN IMMEDIATE")
            cached = db.execute("SELECT signature,columns,total FROM table_sources WHERE path=?", (source,)).fetchone()
            if not cached or cached[0] != key:
                db.execute("DELETE FROM table_rows WHERE path=?", (source,))
                try:
                    with (open(source, "rb") if is_jsonl else open(source, newline="", encoding="utf-8-sig", errors="replace")) as handle:
                        if is_jsonl:
                            reader = (row for root in json_lines(handle) for row in tree_rows([root]))
                            columns = []
                        else:
                            reader = csv.reader(handle)
                            columns = next(reader, None)
                            if columns is None:
                                raise ValueError("No CSV data found.")
                        total = 0
                        batch = []
                        for position, row in enumerate(reader):
                            if is_jsonl:
                                for column in row:
                                    if column not in columns:
                                        columns.append(column)
                            batch.append((source, position, json.dumps(row)))
                            total += 1
                            if len(batch) == 1000:
                                db.executemany("INSERT INTO table_rows VALUES (?,?,?)", batch)
                                batch.clear()
                        if batch:
                            db.executemany("INSERT INTO table_rows VALUES (?,?,?)", batch)
                    if signature(source) != before:
                        raise ValueError("Result changed while indexing; try again after the run finishes.")
                except csv.Error as exc:
                    raise ValueError(f"Unable to parse CSV: {exc}") from exc
                db.execute("INSERT OR REPLACE INTO table_sources VALUES (?,?,?,?)", (source, key, json.dumps(columns), total))
            else:
                columns, total = json.loads(cached[1]), cached[2]
            rows = [json.loads(row[0]) for row in db.execute(
                "SELECT data FROM table_rows WHERE path=? AND position>=? ORDER BY position LIMIT ?",
                (source, max(0, offset), max(0, limit)))]
        if is_jsonl:
            def cell(value):
                if value is None:
                    return ""
                return json.dumps(value) if isinstance(value, (dict, list)) else str(value)
            rows = [[cell(row.get(key)) for key in columns] for row in rows]
        return {"columns": columns, "rows": rows}, total, total > offset + len(rows)
