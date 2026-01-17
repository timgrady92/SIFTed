"""
Pytest configuration and shared fixtures for SIFTed tool validation tests.

This module provides fixtures for:
- Sample file paths (forensic artifacts for testing)
- Temporary output directories
- Tool execution helpers
- CSV validation utilities
"""

import csv
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

# Path to the samples directory
SAMPLES_DIR = Path(__file__).parent / "samples"


@dataclass
class ToolResult:
    """Result of running a forensic tool."""

    exit_code: int
    stdout: str
    stderr: str
    command: list[str]
    output_dir: Path

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def get_output_file(self, filename: str) -> Optional[Path]:
        """Get path to an output file if it exists."""
        path = self.output_dir / filename
        return path if path.exists() else None

    def get_csv_data(self, filename: str) -> list[dict]:
        """Read CSV output file and return as list of dicts."""
        path = self.get_output_file(filename)
        if not path:
            return []
        with open(path, newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))


# =============================================================================
# Tool availability fixtures
# =============================================================================


@pytest.fixture(scope="session")
def tool_availability():
    """Check which tools are available on the system."""
    tools = {
        # Eric Zimmerman tools
        "amcacheparser": shutil.which("AmcacheParser") or shutil.which("amcacheparser"),
        "appcompatcacheparser": shutil.which("AppCompatCacheParser")
        or shutil.which("appcompatcacheparser"),
        "lecmd": shutil.which("LECmd") or shutil.which("lecmd"),
        "jlecmd": shutil.which("JLECmd") or shutil.which("jlecmd"),
        "sbecmd": shutil.which("SBECmd") or shutil.which("sbecmd"),
        "rbcmd": shutil.which("RBCmd") or shutil.which("rbcmd"),
        "evtxecmd": shutil.which("EvtxECmd") or shutil.which("evtxecmd"),
        "mftecmd": shutil.which("MFTECmd") or shutil.which("mftecmd"),
        "recmd": shutil.which("RECmd") or shutil.which("recmd"),
        "sqlecmd": shutil.which("SQLECmd") or shutil.which("sqlecmd"),
        # Other tools
        "exiftool": shutil.which("exiftool"),
        "foremost": shutil.which("foremost"),
        "bulk_extractor": shutil.which("bulk_extractor"),
        "scalpel": shutil.which("scalpel"),
        "volatility3": shutil.which("vol") or shutil.which("vol3"),
    }
    return tools


def requires_tool(tool_name: str):
    """Decorator to skip tests if a tool is not installed."""
    tool_path = shutil.which(tool_name) or shutil.which(tool_name.lower())
    return pytest.mark.skipif(
        not tool_path, reason=f"{tool_name} not found in PATH"
    )


# =============================================================================
# Sample file fixtures
# =============================================================================


@pytest.fixture(scope="session")
def samples_dir():
    """Path to the samples directory."""
    return SAMPLES_DIR


@pytest.fixture(scope="session")
def evtx_sample(samples_dir):
    """Path to sample EVTX file(s)."""
    path = samples_dir / "evtx"
    if not path.exists() or not any(path.glob("*.evtx")):
        pytest.skip("EVTX sample not available")
    return path


@pytest.fixture(scope="session")
def registry_sample(samples_dir):
    """Path to sample registry hive(s)."""
    path = samples_dir / "registry"
    # Registry hives don't have extensions, check for common names
    has_hives = any(
        (path / name).exists()
        for name in ["SYSTEM", "SOFTWARE", "NTUSER.DAT", "SAM", "SECURITY", "Amcache.hve"]
    )
    if not path.exists() or not has_hives:
        pytest.skip("Registry sample not available")
    return path


@pytest.fixture(scope="session")
def lnk_sample(samples_dir):
    """Path to sample LNK file(s)."""
    path = samples_dir / "lnk"
    if not path.exists() or not any(path.glob("*.lnk")):
        pytest.skip("LNK sample not available")
    return path


@pytest.fixture(scope="session")
def sqlite_sample(samples_dir):
    """Path to sample SQLite database(s)."""
    path = samples_dir / "sqlite"
    if not path.exists():
        pytest.skip("SQLite sample not available")
    return path


@pytest.fixture(scope="session")
def mft_sample(samples_dir):
    """Path to sample $MFT file."""
    path = samples_dir / "mft"
    if not path.exists():
        pytest.skip("MFT sample not available")
    return path


@pytest.fixture(scope="session")
def image_sample(samples_dir):
    """Path to sample image file(s) with EXIF data."""
    path = samples_dir / "images"
    if not path.exists():
        pytest.skip("Image sample not available")
    return path


@pytest.fixture(scope="session")
def jumplist_sample(samples_dir):
    """Path to sample Jump List file(s)."""
    path = samples_dir / "jumplist"
    if not path.exists():
        pytest.skip("Jump List sample not available")
    return path


@pytest.fixture(scope="session")
def recyclebin_sample(samples_dir):
    """Path to sample Recycle Bin $I file(s)."""
    path = samples_dir / "recyclebin"
    if not path.exists():
        pytest.skip("Recycle Bin sample not available")
    return path


@pytest.fixture(scope="session")
def shellbags_sample(samples_dir):
    """Path to sample registry hives for ShellBags."""
    path = samples_dir / "shellbags"
    if not path.exists():
        pytest.skip("ShellBags sample not available")
    return path


# =============================================================================
# Output directory fixtures
# =============================================================================


@pytest.fixture
def tmp_output(tmp_path):
    """Temporary directory for tool output."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


# =============================================================================
# Tool execution helpers
# =============================================================================


def run_tool(
    binary: str,
    source_path: Path,
    output_dir: Path,
    input_flag: str = "-f",
    extra_args: Optional[list[str]] = None,
    csv_name: Optional[str] = None,
    timeout: int = 120,
) -> ToolResult:
    """
    Run a forensic tool and capture its output.

    Args:
        binary: Tool binary name or path
        source_path: Path to input file/directory
        output_dir: Directory for output files
        input_flag: Input flag (-f for file, -d for directory)
        extra_args: Additional command-line arguments
        csv_name: Custom CSV output filename (--csvf)
        timeout: Maximum execution time in seconds

    Returns:
        ToolResult with exit code, stdout, stderr, and output paths
    """
    # Find the binary
    binary_path = shutil.which(binary) or shutil.which(binary.lower())
    if not binary_path:
        raise FileNotFoundError(f"Tool not found: {binary}")

    # Build command
    command = [
        binary_path,
        input_flag,
        str(source_path),
        "--csv",
        str(output_dir),
    ]

    if csv_name:
        command.extend(["--csvf", csv_name])

    if extra_args:
        command.extend(extra_args)

    # Run the tool
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    return ToolResult(
        exit_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        command=command,
        output_dir=output_dir,
    )


def run_exiftool(
    source_path: Path,
    output_dir: Path,
    output_format: str = "csv",
    recursive: bool = False,
    timeout: int = 60,
) -> ToolResult:
    """
    Run ExifTool and capture its output.

    Args:
        source_path: Path to input file/directory
        output_dir: Directory for output files
        output_format: Output format (csv, json, txt)
        recursive: Process directories recursively
        timeout: Maximum execution time in seconds

    Returns:
        ToolResult with exit code, stdout, stderr, and output paths
    """
    binary_path = shutil.which("exiftool")
    if not binary_path:
        raise FileNotFoundError("exiftool not found")

    # Determine output file extension
    ext_map = {"csv": "csv", "json": "json", "txt": "txt"}
    ext = ext_map.get(output_format, "csv")
    output_file = output_dir / f"metadata.{ext}"

    # Build command
    command = [binary_path]

    if output_format == "csv":
        command.append("-csv")
    elif output_format == "json":
        command.append("-json")

    if recursive:
        command.append("-r")

    command.append(str(source_path))

    # Run and capture output
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    # Write output to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    return ToolResult(
        exit_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        command=command,
        output_dir=output_dir,
    )


# =============================================================================
# CSV validation helpers
# =============================================================================


def assert_csv_has_columns(csv_path: Path, required_columns: list[str]):
    """Assert that a CSV file contains the required columns."""
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        missing = set(required_columns) - set(fieldnames)
        assert not missing, f"CSV missing columns: {missing}"


def assert_csv_has_rows(csv_path: Path, min_rows: int = 1):
    """Assert that a CSV file contains at least min_rows data rows."""
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) >= min_rows, f"Expected at least {min_rows} rows, got {len(rows)}"


def find_csv_row(csv_path: Path, column: str, value: str) -> Optional[dict]:
    """Find a row in a CSV where column matches value."""
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get(column) == value:
                return row
    return None


def csv_column_contains(csv_path: Path, column: str, value: str) -> bool:
    """Check if any row in the CSV has column containing value."""
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if value in (row.get(column) or ""):
                return True
    return False
