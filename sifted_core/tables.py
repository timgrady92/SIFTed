"""Streaming CSV import into a disposable, signature-keyed pagination cache."""
import csv
import json
import sqlite3
from pathlib import Path

from .adapters import signature


class CsvTables:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)

    def page(self, source, offset=0, limit=100, max_bytes=1024 ** 3):
        source = str(Path(source).resolve())
        before = signature(source)
        if before[2] > max_bytes:
            raise ValueError("File exceeds the CSV table import limit.")
        key = json.dumps(before)
        with sqlite3.connect(self.path, timeout=30) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS csv_sources(path TEXT PRIMARY KEY, signature TEXT, columns TEXT, total INTEGER)")
            db.execute("CREATE TABLE IF NOT EXISTS csv_rows(path TEXT, position INTEGER, data TEXT, PRIMARY KEY(path,position))")
            db.execute("BEGIN IMMEDIATE")
            cached = db.execute("SELECT signature,columns,total FROM csv_sources WHERE path=?", (source,)).fetchone()
            if not cached or cached[0] != key:
                db.execute("DELETE FROM csv_rows WHERE path=?", (source,))
                try:
                    with open(source, newline="", encoding="utf-8-sig", errors="replace") as handle:
                        reader = csv.reader(handle)
                        columns = next(reader, None)
                        if columns is None:
                            raise ValueError("No CSV data found.")
                        total = 0
                        batch = []
                        for position, row in enumerate(reader):
                            batch.append((source, position, json.dumps(row)))
                            total += 1
                            if len(batch) == 1000:
                                db.executemany("INSERT INTO csv_rows VALUES (?,?,?)", batch)
                                batch.clear()
                        if batch:
                            db.executemany("INSERT INTO csv_rows VALUES (?,?,?)", batch)
                    if signature(source) != before:
                        raise ValueError("CSV changed while indexing; try again after the run finishes.")
                except csv.Error as exc:
                    raise ValueError(f"Unable to parse CSV: {exc}") from exc
                db.execute("INSERT OR REPLACE INTO csv_sources VALUES (?,?,?,?)", (source, key, json.dumps(columns), total))
            else:
                columns, total = json.loads(cached[1]), cached[2]
            rows = [json.loads(row[0]) for row in db.execute(
                "SELECT data FROM csv_rows WHERE path=? AND position>=? ORDER BY position LIMIT ?",
                (source, max(0, offset), max(0, limit)))]
        return {"columns": columns, "rows": rows}, total, total > offset + len(rows)
