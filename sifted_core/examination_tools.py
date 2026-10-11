"""Bounded, fixed-argv text, hexadecimal, and PDF examination."""
from pathlib import Path

from .tool_base import OUTPUT, Plan, Step, ToolAdapter, ValidationError, executable, integer


EXAMINATION_TOOL_IDS = ("head", "xxd", "pdfinfo", "pdftotext")
TEXT_LIMIT = 64 * 1024
HEX_LIMIT = 64 * 1024
PDF_PAGE_LIMIT = 50


class ExaminationAdapter(ToolAdapter):
    def __init__(self, tool_id):
        self.tool_id = tool_id
        self.parameter_names = {"head": {"byte_limit"}, "xxd": {"byte_limit", "byte_offset"},
                                "pdfinfo": set(), "pdftotext": {"first_page", "last_page"}}[tool_id]

    def build(self, p, source, output, settings, preview=False):
        tool = self.tool_id
        args = executable(tool, [tool], settings, not preview)
        params = {}
        if tool in {"pdfinfo", "pdftotext"} and source != "<source_path>":
            with Path(source).open("rb") as handle:
                if b"%PDF-" not in handle.read(1024):
                    raise ValidationError("PDF examination requires a file with a PDF header.")
        if tool == "head":
            params["byte_limit"] = integer(p, "byte_limit", TEXT_LIMIT, 1, TEXT_LIMIT)
            args += ["-c", str(params["byte_limit"]), "--", source]
        elif tool == "xxd":
            params["byte_limit"] = integer(p, "byte_limit", 4096, 1, HEX_LIMIT)
            params["byte_offset"] = integer(p, "byte_offset", 0)
            args += ["-g", "1", "-c", "16", "-s", str(params["byte_offset"]), "-l", str(params["byte_limit"]), source]
        elif tool == "pdfinfo":
            args += ["-isodates", "-enc", "UTF-8", source]
        else:
            first = integer(p, "first_page", 1, 1, PDF_PAGE_LIMIT)
            last = integer(p, "last_page", 5, first, PDF_PAGE_LIMIT)
            args += ["-f", str(first), "-l", str(last), "-enc", "UTF-8", "-layout", "-nopgbrk", source, "-"]
            params.update(first_page=first, last_page=last)
        filename = tool + ".txt"
        return Plan(tool, source, output,
                    [Step(args, tool, OUTPUT + "/" + filename, min(settings.timeout_seconds, 90), max_stdout_bytes=512 * 1024)],
                    parameters=params, expected_files=[filename])
