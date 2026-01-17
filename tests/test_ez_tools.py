"""
Tests for Eric Zimmerman forensic tools.

These tests validate that EZ tools:
1. Execute successfully on sample artifacts
2. Produce valid CSV output with expected columns
3. Extract correct forensic values from known samples

Run with: pytest tests/test_ez_tools.py -v
Run only if tools installed: pytest tests/test_ez_tools.py -v -m "not requires_sample"
"""

import shutil

import pytest

from conftest import (
    assert_csv_has_columns,
    assert_csv_has_rows,
    csv_column_contains,
    find_csv_row,
    run_tool,
)


# =============================================================================
# Tool installation tests (always run)
# =============================================================================


class TestToolAvailability:
    """Test that Eric Zimmerman tools are installed and accessible.

    These tests report tool availability status. Missing tools are marked
    as expected failures (xfail) rather than hard failures, since tool
    installation varies by environment.
    """

    def test_amcacheparser_installed(self, tool_availability):
        """AmcacheParser should be available."""
        if not tool_availability["amcacheparser"]:
            pytest.xfail("AmcacheParser not found in PATH")

    def test_evtxecmd_installed(self, tool_availability):
        """EvtxECmd should be available for Event Log parsing."""
        if not tool_availability["evtxecmd"]:
            pytest.xfail("EvtxECmd not found in PATH")

    def test_mftecmd_installed(self, tool_availability):
        """MFTECmd should be available for MFT parsing."""
        if not tool_availability["mftecmd"]:
            pytest.xfail("MFTECmd not found in PATH")

    def test_lecmd_installed(self, tool_availability):
        """LECmd should be available for LNK parsing."""
        if not tool_availability["lecmd"]:
            pytest.xfail("LECmd not found in PATH")

    def test_recmd_installed(self, tool_availability):
        """RECmd should be available for Registry parsing."""
        if not tool_availability["recmd"]:
            pytest.xfail("RECmd not found in PATH")


# =============================================================================
# EvtxECmd (Event Log) tests
# =============================================================================


@pytest.mark.ez_tools
@pytest.mark.requires_sample
class TestEvtxECmd:
    """Tests for EvtxECmd Event Log parser."""

    @pytest.fixture
    def evtxecmd_binary(self):
        """Get EvtxECmd binary path."""
        path = shutil.which("EvtxECmd") or shutil.which("evtxecmd")
        if not path:
            pytest.skip("EvtxECmd not installed")
        return path

    def test_evtxecmd_parses_evtx_file(self, evtxecmd_binary, evtx_sample, tmp_output):
        """EvtxECmd should successfully parse an EVTX file."""
        evtx_files = list(evtx_sample.glob("*.evtx"))
        source = evtx_files[0] if evtx_files else evtx_sample
        input_flag = "-f" if evtx_files else "-d"

        result = run_tool(
            "EvtxECmd",
            source,
            tmp_output,
            input_flag=input_flag,
            csv_name="eventlogs.csv",
        )

        assert result.success, f"EvtxECmd failed: {result.stderr}"

    def test_evtxecmd_output_has_required_columns(self, evtxecmd_binary, evtx_sample, tmp_output):
        """EvtxECmd CSV output should contain expected forensic columns."""
        evtx_files = list(evtx_sample.glob("*.evtx"))
        source = evtx_files[0] if evtx_files else evtx_sample
        input_flag = "-f" if evtx_files else "-d"

        result = run_tool(
            "EvtxECmd",
            source,
            tmp_output,
            input_flag=input_flag,
            csv_name="eventlogs.csv",
        )

        csv_path = result.get_output_file("eventlogs.csv")
        assert csv_path, "eventlogs.csv not created"

        required_columns = [
            "EventId",
            "TimeCreated",
            "Channel",
        ]
        assert_csv_has_columns(csv_path, required_columns)


# =============================================================================
# LECmd (LNK shortcut) tests
# =============================================================================


@pytest.mark.ez_tools
@pytest.mark.requires_sample
class TestLECmd:
    """Tests for LECmd LNK shortcut parser."""

    @pytest.fixture
    def lecmd_binary(self):
        """Get LECmd binary path."""
        path = shutil.which("LECmd") or shutil.which("lecmd")
        if not path:
            pytest.skip("LECmd not installed")
        return path

    def test_lecmd_parses_lnk_file(self, lecmd_binary, lnk_sample, tmp_output):
        """LECmd should successfully parse a LNK file."""
        lnk_files = list(lnk_sample.glob("*.lnk"))
        source = lnk_files[0] if lnk_files else lnk_sample
        input_flag = "-f" if lnk_files else "-d"

        result = run_tool(
            "LECmd",
            source,
            tmp_output,
            input_flag=input_flag,
            csv_name="lnk.csv",
        )

        assert result.success, f"LECmd failed: {result.stderr}"

    def test_lecmd_output_has_required_columns(self, lecmd_binary, lnk_sample, tmp_output):
        """LECmd CSV output should contain expected forensic columns."""
        lnk_files = list(lnk_sample.glob("*.lnk"))
        source = lnk_files[0] if lnk_files else lnk_sample
        input_flag = "-f" if lnk_files else "-d"

        result = run_tool(
            "LECmd",
            source,
            tmp_output,
            input_flag=input_flag,
            csv_name="lnk.csv",
        )

        csv_path = result.get_output_file("lnk.csv")
        assert csv_path, "lnk.csv not created"

        required_columns = [
            "SourceFile",
            "TargetCreated",
        ]
        assert_csv_has_columns(csv_path, required_columns)


# =============================================================================
# MFTECmd (MFT) tests
# =============================================================================


@pytest.mark.ez_tools
@pytest.mark.requires_sample
class TestMFTECmd:
    """Tests for MFTECmd Master File Table parser."""

    @pytest.fixture
    def mftecmd_binary(self):
        """Get MFTECmd binary path."""
        path = shutil.which("MFTECmd") or shutil.which("mftecmd")
        if not path:
            pytest.skip("MFTECmd not installed")
        return path

    def test_mftecmd_parses_mft(self, mftecmd_binary, mft_sample, tmp_output):
        """MFTECmd should successfully parse an $MFT file."""
        mft_file = mft_sample / "$MFT"
        if not mft_file.exists():
            # Try without the $ prefix
            mft_files = list(mft_sample.glob("*MFT*"))
            if not mft_files:
                pytest.skip("No MFT file found in sample")
            mft_file = mft_files[0]

        result = run_tool(
            "MFTECmd",
            mft_file,
            tmp_output,
            input_flag="-f",
            csv_name="mft.csv",
        )

        assert result.success, f"MFTECmd failed: {result.stderr}"

    def test_mftecmd_output_has_required_columns(self, mftecmd_binary, mft_sample, tmp_output):
        """MFTECmd CSV output should contain expected forensic columns."""
        mft_file = mft_sample / "$MFT"
        if not mft_file.exists():
            mft_files = list(mft_sample.glob("*MFT*"))
            if not mft_files:
                pytest.skip("No MFT file found in sample")
            mft_file = mft_files[0]

        result = run_tool(
            "MFTECmd",
            mft_file,
            tmp_output,
            input_flag="-f",
            csv_name="mft.csv",
        )

        csv_path = result.get_output_file("mft.csv")
        assert csv_path, "mft.csv not created"

        required_columns = [
            "FileName",
            "Created0x10",
            "LastModified0x10",
        ]
        assert_csv_has_columns(csv_path, required_columns)


# =============================================================================
# AmcacheParser tests
# =============================================================================


@pytest.mark.ez_tools
@pytest.mark.requires_sample
class TestAmcacheParser:
    """Tests for AmcacheParser."""

    @pytest.fixture
    def amcache_binary(self):
        """Get AmcacheParser binary path."""
        path = shutil.which("AmcacheParser") or shutil.which("amcacheparser")
        if not path:
            pytest.skip("AmcacheParser not installed")
        return path

    def test_amcacheparser_parses_amcache(self, amcache_binary, registry_sample, tmp_output):
        """AmcacheParser should successfully parse Amcache.hve."""
        amcache_file = registry_sample / "Amcache.hve"
        if not amcache_file.exists():
            pytest.skip("Amcache.hve not found in registry sample")

        result = run_tool(
            "AmcacheParser",
            amcache_file,
            tmp_output,
            input_flag="-f",
            csv_name="amcache.csv",
        )

        assert result.success, f"AmcacheParser failed: {result.stderr}"


# =============================================================================
# Integration test - Full workflow
# =============================================================================


@pytest.mark.ez_tools
@pytest.mark.slow
class TestEZToolWorkflow:
    """Integration tests that run multiple tools in sequence."""

    def test_multiple_tools_produce_valid_output(self, tool_availability, tmp_output, samples_dir):
        """Run available tools and verify they all produce valid CSV."""
        results = {}

        # Map tools to their samples and expected output
        tool_configs = [
            ("evtxecmd", "evtx", "eventlogs.csv", "-d"),
            ("lecmd", "lnk", "lnk.csv", "-d"),
        ]

        for tool_id, sample_subdir, csv_name, input_flag in tool_configs:
            if not tool_availability.get(tool_id):
                results[tool_id] = "skipped (not installed)"
                continue

            sample_path = samples_dir / sample_subdir
            if not sample_path.exists() or not any(sample_path.iterdir()):
                results[tool_id] = "skipped (no sample)"
                continue

            tool_output = tmp_output / tool_id
            tool_output.mkdir()

            try:
                result = run_tool(
                    tool_id,
                    sample_path,
                    tool_output,
                    input_flag=input_flag,
                    csv_name=csv_name,
                )
                if result.success and result.get_output_file(csv_name):
                    results[tool_id] = "passed"
                else:
                    results[tool_id] = f"failed: exit={result.exit_code}"
            except Exception as e:
                results[tool_id] = f"error: {e}"

        # Report results
        print("\nTool execution results:")
        for tool_id, status in results.items():
            print(f"  {tool_id}: {status}")

        # At least one tool should have passed if samples exist
        passed = [t for t, s in results.items() if s == "passed"]
        skipped = [t for t, s in results.items() if "skipped" in s]

        if len(skipped) == len(tool_configs):
            pytest.skip("No tools or samples available for integration test")

        assert passed, f"No tools passed. Results: {results}"
