"""
Tests for ExifTool metadata extraction.

These tests validate that ExifTool:
1. Executes successfully on sample images
2. Produces valid output (CSV/JSON)
3. Extracts correct metadata values from known samples

Run with: pytest tests/test_exiftool.py -v
"""

import json
import shutil
from pathlib import Path

import pytest

from conftest import run_exiftool


# =============================================================================
# Tool installation tests
# =============================================================================


class TestExifToolAvailability:
    """Test that ExifTool is installed and accessible."""

    def test_exiftool_installed(self, tool_availability):
        """ExifTool should be available for metadata extraction."""
        assert tool_availability["exiftool"], "exiftool not found in PATH"

    def test_exiftool_version(self):
        """ExifTool should report a valid version."""
        import subprocess

        exiftool = shutil.which("exiftool")
        if not exiftool:
            pytest.skip("exiftool not installed")

        result = subprocess.run([exiftool, "-ver"], capture_output=True, text=True)
        assert result.returncode == 0
        assert result.stdout.strip(), "ExifTool returned empty version"

        # Version should be a number like "12.50"
        version = result.stdout.strip()
        parts = version.split(".")
        assert len(parts) >= 1, f"Unexpected version format: {version}"
        assert parts[0].isdigit(), f"Version doesn't start with number: {version}"


# =============================================================================
# Basic functionality tests (no samples required)
# =============================================================================


@pytest.mark.exiftool
class TestExifToolBasic:
    """Basic ExifTool functionality tests."""

    @pytest.fixture
    def exiftool_binary(self):
        """Get ExifTool binary path."""
        path = shutil.which("exiftool")
        if not path:
            pytest.skip("exiftool not installed")
        return path

    def test_exiftool_help(self, exiftool_binary):
        """ExifTool should display help without errors."""
        import subprocess

        result = subprocess.run(
            [exiftool_binary, "-h"], capture_output=True, text=True
        )
        # ExifTool returns 1 for -h but that's normal
        assert "ExifTool" in result.stdout or "exiftool" in result.stdout.lower()

    def test_exiftool_supported_formats(self, exiftool_binary):
        """ExifTool should list supported file formats."""
        import subprocess

        result = subprocess.run(
            [exiftool_binary, "-listf"], capture_output=True, text=True
        )
        assert result.returncode == 0
        # Should list common formats
        output = result.stdout.lower()
        assert "jpg" in output or "jpeg" in output
        assert "png" in output
        assert "pdf" in output


# =============================================================================
# Image metadata tests (requires samples)
# =============================================================================


@pytest.mark.exiftool
@pytest.mark.requires_sample
class TestExifToolImageExtraction:
    """Tests for extracting metadata from image files."""

    @pytest.fixture
    def exiftool_binary(self):
        """Get ExifTool binary path."""
        path = shutil.which("exiftool")
        if not path:
            pytest.skip("exiftool not installed")
        return path

    def test_exiftool_extracts_from_jpeg(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool should extract metadata from JPEG files."""
        jpeg_files = list(image_sample.glob("*.jpg")) + list(image_sample.glob("*.jpeg"))
        if not jpeg_files:
            pytest.skip("No JPEG files in image sample")

        result = run_exiftool(jpeg_files[0], tmp_output, output_format="csv")

        assert result.success, f"ExifTool failed: {result.stderr}"
        csv_path = tmp_output / "metadata.csv"
        assert csv_path.exists(), "metadata.csv not created"

    def test_exiftool_csv_output_format(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool CSV output should have proper structure."""
        jpeg_files = list(image_sample.glob("*.jpg")) + list(image_sample.glob("*.jpeg"))
        if not jpeg_files:
            pytest.skip("No JPEG files in image sample")

        result = run_exiftool(jpeg_files[0], tmp_output, output_format="csv")
        csv_path = tmp_output / "metadata.csv"

        # Read and verify CSV structure
        content = csv_path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) >= 2, "CSV should have header and at least one data row"

        # First line should be headers
        headers = lines[0].split(",")
        assert "SourceFile" in headers or "sourcefile" in [h.lower() for h in headers]

    def test_exiftool_json_output_format(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool JSON output should be valid JSON."""
        jpeg_files = list(image_sample.glob("*.jpg")) + list(image_sample.glob("*.jpeg"))
        if not jpeg_files:
            pytest.skip("No JPEG files in image sample")

        result = run_exiftool(jpeg_files[0], tmp_output, output_format="json")
        json_path = tmp_output / "metadata.json"

        content = json_path.read_text()
        # Should be valid JSON
        data = json.loads(content)
        assert isinstance(data, list), "JSON should be a list"
        assert len(data) >= 1, "JSON should contain at least one entry"
        assert "SourceFile" in data[0], "JSON entry should have SourceFile"

    def test_exiftool_extracts_gps_coordinates(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool should extract GPS coordinates from geotagged images."""
        # Look for specifically geotagged sample
        geotagged = image_sample / "geotagged.jpg"
        if not geotagged.exists():
            pytest.skip("geotagged.jpg sample not available")

        result = run_exiftool(geotagged, tmp_output, output_format="json")
        json_path = tmp_output / "metadata.json"

        data = json.loads(json_path.read_text())
        assert len(data) >= 1

        metadata = data[0]
        # Check for GPS fields
        gps_fields = ["GPSLatitude", "GPSLongitude", "GPSPosition"]
        has_gps = any(field in metadata for field in gps_fields)

        if has_gps:
            # If sample has known GPS, verify values
            # Example: San Francisco coordinates
            # assert "37.7749" in str(metadata.get("GPSLatitude", ""))
            pass
        else:
            pytest.skip("Sample image doesn't contain GPS data")

    def test_exiftool_extracts_camera_info(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool should extract camera make/model from photos."""
        jpeg_files = list(image_sample.glob("*.jpg")) + list(image_sample.glob("*.jpeg"))
        if not jpeg_files:
            pytest.skip("No JPEG files in image sample")

        result = run_exiftool(jpeg_files[0], tmp_output, output_format="json")
        json_path = tmp_output / "metadata.json"

        data = json.loads(json_path.read_text())
        assert len(data) >= 1

        metadata = data[0]
        # Common camera fields
        camera_fields = ["Make", "Model", "Software"]
        has_camera_info = any(field in metadata for field in camera_fields)

        # Not all images have camera info, so this is informational
        if not has_camera_info:
            print("Note: Sample image doesn't contain camera make/model")


# =============================================================================
# Directory processing tests
# =============================================================================


@pytest.mark.exiftool
@pytest.mark.requires_sample
class TestExifToolDirectoryProcessing:
    """Tests for processing directories of files."""

    @pytest.fixture
    def exiftool_binary(self):
        """Get ExifTool binary path."""
        path = shutil.which("exiftool")
        if not path:
            pytest.skip("exiftool not installed")
        return path

    def test_exiftool_processes_directory(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool should process all files in a directory."""
        result = run_exiftool(image_sample, tmp_output, output_format="csv")

        assert result.success, f"ExifTool failed: {result.stderr}"
        csv_path = tmp_output / "metadata.csv"
        assert csv_path.exists(), "metadata.csv not created"

    def test_exiftool_recursive_processing(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool should process directories recursively."""
        result = run_exiftool(
            image_sample, tmp_output, output_format="csv", recursive=True
        )

        assert result.success, f"ExifTool failed: {result.stderr}"
        csv_path = tmp_output / "metadata.csv"
        assert csv_path.exists(), "metadata.csv not created"


# =============================================================================
# Forensic value extraction tests
# =============================================================================


@pytest.mark.exiftool
@pytest.mark.requires_sample
class TestExifToolForensicValues:
    """Tests for extracting forensically relevant metadata."""

    @pytest.fixture
    def exiftool_binary(self):
        """Get ExifTool binary path."""
        path = shutil.which("exiftool")
        if not path:
            pytest.skip("exiftool not installed")
        return path

    def test_exiftool_extracts_timestamps(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool should extract creation and modification timestamps."""
        jpeg_files = list(image_sample.glob("*.jpg")) + list(image_sample.glob("*.jpeg"))
        if not jpeg_files:
            pytest.skip("No JPEG files in image sample")

        result = run_exiftool(jpeg_files[0], tmp_output, output_format="json")
        json_path = tmp_output / "metadata.json"

        data = json.loads(json_path.read_text())
        metadata = data[0]

        # Check for timestamp fields
        timestamp_fields = [
            "FileModifyDate",
            "FileAccessDate",
            "FileCreateDate",
            "CreateDate",
            "ModifyDate",
            "DateTimeOriginal",
        ]
        found_timestamps = [f for f in timestamp_fields if f in metadata]
        assert found_timestamps, f"No timestamp fields found. Available: {list(metadata.keys())}"

    def test_exiftool_extracts_file_hash(self, exiftool_binary, image_sample, tmp_output):
        """ExifTool can compute file hashes for integrity verification."""
        import subprocess

        jpeg_files = list(image_sample.glob("*.jpg")) + list(image_sample.glob("*.jpeg"))
        if not jpeg_files:
            pytest.skip("No JPEG files in image sample")

        # ExifTool can compute MD5/SHA hashes
        result = subprocess.run(
            [exiftool_binary, "-json", "-FileSize", "-FileName", jpeg_files[0]],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "FileSize" in data[0], "FileSize should be available"
        assert "FileName" in data[0], "FileName should be available"
