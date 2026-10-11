"""Read-only, streaming execution of SQLECmd map queries on private SQLite captures.

This is SIFTed's executor, not the native SQLECmd executable. It can also be run as
a standalone managed subprocess, so cancellation and resource limits remain owned
by the ordinary worker.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

import yaml

ENGINE_VERSION = "1"
MAX_VALUE_BYTES = 16 * 1024 * 1024


class MapLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("Map aliases are not supported.")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("Map keys must be unique text values.")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_map(content):
    value = yaml.load(content, Loader=MapLoader)
    if not isinstance(value, dict):
        raise ValueError("SQLite map must be a mapping.")
    required = {
        "Id",
        "Description",
        "CSVPrefix",
        "FileName",
        "IdentifyQuery",
        "IdentifyValue",
        "Queries",
    }
    if not required.issubset(value):
        raise ValueError(
            "SQLite map is missing fields: "
            + ", ".join(sorted(required - value.keys()))
        )
    for name in required - {"IdentifyValue", "Queries"}:
        if not isinstance(value[name], str) or not value[name].strip():
            raise ValueError("SQLite map field must be nonempty text: " + name)
    if not isinstance(value["IdentifyValue"], (str, int, float)) or isinstance(
        value["IdentifyValue"], bool
    ):
        raise ValueError("SQLite map IdentifyValue must be text or a number.")
    if not isinstance(value["Queries"], list) or not value["Queries"]:
        raise ValueError("SQLite map must declare at least one query.")
    for query in value["Queries"]:
        if not isinstance(query, dict) or any(
            not isinstance(query.get(name), str) or not query[name].strip()
            for name in ("Name", "Query", "BaseFileName")
        ):
            raise ValueError("SQLite map query requires Name, Query and BaseFileName.")
        blobs = query.get("BlobColumns") or []
        if not isinstance(blobs, list):
            raise ValueError("SQLite map BlobColumns must be a list.")
        seen = set()
        for blob in blobs:
            if (
                not isinstance(blob, dict)
                or not isinstance(blob.get("BlobColumn"), str)
                or not blob["BlobColumn"]
            ):
                raise ValueError("SQLite blob configuration requires a BlobColumn.")
            if blob["BlobColumn"] in seen:
                raise ValueError("SQLite blob columns must be unique.")
            seen.add(blob["BlobColumn"])
            extension = blob.get("BlobExtension") or "blob"
            if not isinstance(extension, str) or not re.fullmatch(
                r"[A-Za-z0-9_]{1,20}", extension
            ):
                raise ValueError(
                    "SQLite blob extension must contain only letters, numbers or underscores."
                )
            if blob.get("NameColumn") is not None and not isinstance(
                blob["NameColumn"], str
            ):
                raise ValueError("SQLite blob NameColumn must be text.")
    return value


def available_maps(directory):
    good, rejected = {}, {}
    for path in sorted(Path(directory).rglob("*.smap")):
        name = path.relative_to(directory).as_posix()
        try:
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
                raise ValueError("Map must be a regular file without symbolic links.")
            if path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("Map exceeds the supported size.")
            content = path.read_text(encoding="utf-8-sig")
            good[name] = {"content": content, "map": load_map(content)}
        except (OSError, ValueError, yaml.YAMLError) as exc:
            rejected[name] = str(exc)
    return good, rejected


def readonly_connection(path, query_seconds):
    connection = sqlite3.connect(
        "file:" + quote(str(Path(path).resolve()), safe="/") + "?mode=ro",
        uri=True,
        timeout=1,
    )
    connection.execute("PRAGMA query_only=ON")
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES)
    connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4 * 1024 * 1024)
    allowed = {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_RECURSIVE,
    }

    def authorize(action, arg1, arg2, database, trigger):
        if action == sqlite3.SQLITE_PRAGMA:
            # FTS5 checks this read-only counter when opening an existing index.
            return (
                sqlite3.SQLITE_OK
                if (arg1 or "").casefold() == "data_version" and arg2 is None
                else sqlite3.SQLITE_DENY
            )
        if (
            action not in allowed
            or action == sqlite3.SQLITE_FUNCTION
            and (arg2 or "").casefold() in {"load_extension", "writefile", "readfile"}
        ):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    connection.set_authorizer(authorize)
    expires = [time.monotonic() + query_seconds]
    connection.set_progress_handler(lambda: int(time.monotonic() > expires[0]), 10000)
    return connection, expires


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")[:60] or "query"


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while data := handle.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def prepare_capture(path):
    """Let SQLite recover a captured rollback journal before read-only analysis."""
    present = Path(str(path) + "-journal").is_file()
    if present:
        uri = "file:" + quote(str(Path(path).resolve()), safe="/") + "?mode=rw"
        with closing(sqlite3.connect(uri, uri=True, timeout=1)) as connection:
            connection.execute("PRAGMA query_only=ON")
            # This fixed read permits SQLite's own hot-journal recovery. Map SQL
            # never runs on this connection, and only private captures reach it.
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return present


def execute_request(request, output):
    os.environ["TZ"] = "UTC"
    time.tzset()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    records, failures, captures = [], [], []
    seen = set()
    maps = {
        name: load_map(Path(path).read_text(encoding="utf-8-sig"))
        for name, path in request["maps"].items()
    }
    for input_index, item in enumerate(request["inputs"]):
        digest = file_digest(item["working_path"])
        # Main-file deduplication is only valid without transaction sidecars.
        if request["deduplicate"] and not item["has_sidecars"] and digest in seen:
            records.append({"source": item["source"], "status": "deduplicated"})
            continue
        seen.add(digest)
        try:
            journal = prepare_capture(item["working_path"])
            captures.append(
                {
                    "source": item["source"],
                    "captured_sha256": digest,
                    "analysis_sha256": file_digest(item["working_path"])
                    if journal
                    else digest,
                    "rollback_journal_present": journal,
                }
            )
            connection, expires = readonly_connection(
                item["working_path"], request["query_seconds"]
            )
        except sqlite3.Error as exc:
            failures.append(item["source"] + ": " + str(exc))
            records.append(
                {"source": item["source"], "status": "error", "error": str(exc)}
            )
            continue
        try:
            for map_index, name in enumerate(item["maps"]):
                profile = maps[name]
                context = {
                    "source": item["source"],
                    "map": name,
                    "map_id": profile["Id"],
                }
                try:
                    expires[0] = time.monotonic() + request["query_seconds"]
                    value = connection.execute(profile["IdentifyQuery"]).fetchone()
                    if value is None or str(value[0]) != str(profile["IdentifyValue"]):
                        records.append({**context, "status": "not_matched"})
                        continue
                except sqlite3.Error as exc:
                    failures.append(name + " identification: " + str(exc))
                    records.append({**context, "status": "error", "error": str(exc)})
                    continue
                for query_index, query in enumerate(profile["Queries"]):
                    result = {**context, "query": query["Name"], "status": "error"}
                    try:
                        expires[0] = time.monotonic() + request["query_seconds"]
                        cursor = connection.execute(query["Query"])
                        if not cursor.description:
                            raise ValueError("Map query must return a table.")
                        columns = [column[0] for column in cursor.description]
                        if len(columns) != len(set(columns)) or "SourceFile" in columns:
                            raise ValueError(
                                "Map query has duplicate or reserved SourceFile columns."
                            )
                        stem = (
                            f"{input_index:04d}_{map_index:03d}_{query_index:03d}_"
                            + safe_name(profile["CSVPrefix"])
                            + "_"
                            + safe_name(query["BaseFileName"])
                        )
                        relative = stem + ".csv"
                        blobs = {
                            b["BlobColumn"]: b for b in query.get("BlobColumns") or []
                        }
                        if not blobs.keys() <= set(columns):
                            raise ValueError(
                                "Map blob column is absent from query results."
                            )
                        count = 0
                        with (output / relative).open(
                            "x", encoding="utf-8", newline=""
                        ) as handle:
                            writer = csv.writer(handle)
                            writer.writerow([*columns, "SourceFile"])
                            for row in cursor:
                                if time.monotonic() > expires[0]:
                                    raise ValueError(
                                        "Map query exceeded its execution timeout."
                                    )
                                count += 1
                                cells = []
                                for column_index, (column, value) in enumerate(
                                    zip(columns, row)
                                ):
                                    if isinstance(value, bytes) and column in blobs:
                                        extension = (
                                            blobs[column].get("BlobExtension") or "blob"
                                        )
                                        name_column = blobs[column].get("NameColumn")
                                        label = ""
                                        if name_column in columns:
                                            label = "_" + safe_name(
                                                str(row[columns.index(name_column)])
                                            )
                                        blob_name = f"blobs/{stem}_{count:08d}_{column_index:03d}{label}.{extension}"
                                        (output / "blobs").mkdir(exist_ok=True)
                                        (output / blob_name).write_bytes(value)
                                        cells.append(blob_name)
                                    else:
                                        cells.append(
                                            value.hex()
                                            if isinstance(value, bytes)
                                            else value
                                        )
                                writer.writerow([*cells, item["source"]])
                        result.update(
                            status="success", file=relative, entry_count=count
                        )
                    except (sqlite3.Error, ValueError, OSError) as exc:
                        result["error"] = str(exc)
                        failures.append(name + " / " + query["Name"] + ": " + str(exc))
                    records.append(result)
        finally:
            connection.close()
    summary = {
        "engine": "SIFTed SQLite maps",
        "engine_version": ENGINE_VERSION,
        "sqlite_version": sqlite3.sqlite_version,
        "timezone": "UTC",
        "queries": records,
        "captures": captures,
        "errors": failures,
    }
    (output / "map-summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="SIFTed SQLite maps version " + ENGINE_VERSION
    )
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    request = json.loads(Path(args.request).read_text())
    workspace = Path(args.request).parent
    for item in request["inputs"]:
        item["working_path"] = str(workspace / item["working_path"])
    request["maps"] = {
        name: str(workspace / path) for name, path in request["maps"].items()
    }
    try:
        summary = execute_request(request, args.output)
    except (ValueError, OSError, sqlite3.Error, yaml.YAMLError) as exc:
        print("SQLite mapped analysis failed: " + str(exc), file=sys.stderr)
        return 1
    for error in summary["errors"]:
        print(error, file=sys.stderr)
    print(
        f"Completed {len(summary['queries'])} map/query outcomes using SQLite {sqlite3.sqlite_version}."
    )
    return int(bool(summary["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
