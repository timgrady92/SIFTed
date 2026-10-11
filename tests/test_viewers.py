"""Result viewers must preserve text and reject incomplete structured data."""
import pytest
from sifted_core.viewers import parse_json_table, parse_strings_table


def test_strings_offsets_and_spaces_are_preserved(tmp_path):
    source = tmp_path / "strings.txt"
    source.write_text("     1a first string with spaces\n     ff second string\n")
    data, total, more = parse_strings_table(source, row_offset=1, row_limit=1)
    assert total == 2 and not more
    assert data["rows"] == [["2", "ff", "second string"]]


@pytest.mark.parametrize("content", ['[{"PID": 123}]\ntruncated output', 'tool banner\n[{"PID": 123}]'])
def test_json_viewer_rejects_mixed_diagnostics_and_corruption(tmp_path, content):
    source = tmp_path / "output.json"
    source.write_text(content)
    with pytest.raises(ValueError, match="Unable to parse JSON"):
        parse_json_table(source)


def test_json_viewer_paginates_valid_output_and_enforces_size_limit(tmp_path):
    source = tmp_path / "output.json"
    source.write_text('[{"PID": 123, "Name": "first"}, {"PID": 456, "Name": "second"}]')
    data, total, more = parse_json_table(source, row_offset=1, row_limit=1)
    assert total == 2 and not more and data["rows"] == [["second", "456"]]
    with pytest.raises(ValueError, match="too large"):
        parse_json_table(source, max_bytes=10)
