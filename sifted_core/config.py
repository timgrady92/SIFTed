"""One configuration boundary for web and worker processes."""
import json
import os
from pathlib import Path

from .tool_base import Settings

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(overrides=None):
    overrides = overrides or {}

    def value(name, default):
        return overrides.get(name, os.environ.get(name, default))

    def roots(name, default):
        paths = value(name, default)
        if isinstance(paths, str):
            paths = [p.strip() for p in paths.split(",") if p.strip()]
        return [str(Path(p).expanduser().resolve()) for p in paths]

    input_roots = roots("SIFTED_INPUT_ROOTS", "/cases")
    output_roots = roots("SIFTED_OUTPUT_ROOTS", "/cases")
    if not input_roots or not output_roots:
        raise ValueError("Input and output roots must be explicitly configured.")
    binaries = value("SIFTED_BINARIES", {})
    if isinstance(binaries, str):
        binaries = json.loads(binaries)
    if not isinstance(binaries, dict):
        raise ValueError("SIFTED_BINARIES must be an object mapping tool IDs to executable prefixes.")
    settings = Settings(
        input_roots=input_roots, output_roots=output_roots,
        symbol_roots=roots("SIFTED_SYMBOL_ROOTS", []),
        plugin_path=str(value("SIFTED_PLUGIN_CATALOG", BASE_DIR / "data/volatility_plugins.json")),
        foremost_config=str(value("SIFTED_FOREMOST_CONFIG", "/etc/foremost.conf")),
        scalpel_config=str(value("SIFTED_SCALPEL_CONFIG", "/etc/scalpel/scalpel.conf")),
        ez_root=str(value("SIFTED_EZ_ROOT", "/opt/zimmermantools")), binaries=binaries,
        timeout_seconds=int(value("SIFTED_TOOL_TIMEOUT_SECONDS", 14400)),
        max_output_bytes=int(value("SIFTED_MAX_OUTPUT_BYTES", 10 * 1024 ** 3)),
    )
    browse_roots = roots("SIFTED_ALLOWED_PATHS", input_roots + output_roots)
    result_limit = int(value("SIFTED_RESULT_FILE_LIMIT", 12))
    if not browse_roots or result_limit < 1:
        raise ValueError("Browsing roots must be configured and result limit must be positive.")
    return {"DATABASE_PATH": str(Path(value("SIFTED_DATABASE_PATH", BASE_DIR / "data/sifted.sqlite3")).expanduser().resolve()),
            "SETTINGS": settings,
            "BROWSE_ROOTS": browse_roots,
            "RESULT_FILE_LIMIT": result_limit,
            "TESTING": overrides.get("TESTING", False)}
