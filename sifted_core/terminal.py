"""Self-contained Bash recipes derived from validated execution plans.

Managed worker commands are audit records. Terminal recipes also supply the
directories, configuration and private captures those commands depend on.
"""
import hashlib
import json
import shlex
from pathlib import Path

from .tool_base import OUTPUT, WORKSPACE

TOOL_NOTES = {
    "strings": "-a scans the whole file; -e selects character encoding; -n sets minimum length; -t x reports hexadecimal byte offsets.",
    "exiftool": "-csv/-json select the report format; -r visits subdirectories; -G1 identifies tag groups; -s uses tag names.",
    "bulk-extractor": "-o writes feature reports; -x all disables default scanners when a focus is selected; -e enables each selected scanner.",
    "artifact-triage": "log2timeline builds the Plaso storage file; psort exports l2tcsv using the selected display time zone.",
    "volatility": "Global options precede the exact plugin name; plugin options follow it. -r selects the renderer; -o holds extracted files.",
    "eric-zimmerman": "dotnet runs the installed parser DLL; -f selects a file (-d for shellbag hive directories); --csv selects the export folder.",
    "head": "-c limits the number of bytes read; -- separates options from the evidence filename.",
    "xxd": "-s is a byte offset; -l limits bytes; -g 1 groups individual bytes; -c 16 sets bytes per line.",
    "pdfinfo": "-isodates prints ISO date values; -enc UTF-8 selects the report encoding.",
    "pdftotext": "-f/-l select first/last pages; -layout preserves layout; the final - writes text to stdout.",
    "foremost": "-t selects built-in file parsers; -c supplies the included configuration; -i selects evidence; -o selects output.",
    "scalpel": "-c supplies the selected header/footer rules; -o selects output; -O, when selected, disables extension-based grouping.",
    "mmls": "-B adds partition sizes in bytes; Start remains a sector coordinate for subsequent TSK -o options.",
    "fls": "-r/-p select recursive paths; -d, when selected, lists deleted entries; optional final address selects a directory inode.",
    "istat": "The final address is the metadata record (inode or NTFS MFT entry); this examines metadata rather than file contents.",
    "icat": "The final address selects file content; NTFS entry-type-id addresses select a specific stream. > writes the recovered bytes.",
    "blkstat": "The final address selects one filesystem data unit and reports its allocation state.",
    "blkcat": "The final address and count select filesystem data units; stdout contains raw bytes, not a text report.",
    "blkls": "-A selects unallocated units in the final inclusive range; stdout contains only their raw bytes.",
    "blkcalc": "-d maps an original filesystem unit into the unallocated stream; -u maps an unallocated-stream index back.",
}


def shell_token(value, source):
    for token, variable in ((OUTPUT, "output"), (WORKSPACE, "workspace")):
        if value == token or value.startswith(token + "/"):
            return '"$' + variable + value[len(token):].replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`") + '"'
    return '"$source"' if value == source else shlex.quote(value)


def command_text(argv, source, stdout=None, stderr=None, stdin=None):
    words, index = [], 0
    while index < len(argv):
        word = shell_token(argv[index], source)
        if argv[index].startswith("-") and "=" not in argv[index] and index + 1 < len(argv) and not argv[index + 1].startswith("-"):
            index += 1
            word += " " + shell_token(argv[index], source)
        words.append(word)
        index += 1
    if stdin:
        words += ["< " + shlex.quote(stdin)]
    if stdout:
        words += ["> " + shell_token(stdout, source)]
    if stderr:
        words += ["2> " + shell_token(stderr, source)]
    lines, line = [], ""
    for word in words:
        if line and len(line) + len(word) + 1 > 88:
            lines.append(line + " \\")
            line = "  " + word
        else:
            line += (" " if line else "") + word
    return "\n".join([*lines, line])


def write_text(name, content):
    """Quoted heredocs never expand evidence/configuration as shell code."""
    delimiter = "SIFT_CONFIG_" + hashlib.sha256(content.encode()).hexdigest()[:16]
    while delimiter in content.splitlines():
        delimiter += "_"
    target = shell_token(WORKSPACE + "/" + name, "")
    parent = shell_token(WORKSPACE + "/" + str(Path(name).parent), "")
    text = f"mkdir -p -- {parent}\ncat > {target} <<'{delimiter}'\n{content}"
    if not content.endswith("\n"):
        text += "\n"
    text += delimiter + "\n"
    if not content.endswith("\n"):
        text += f"truncate -s -1 -- {target}\n"
    return text


def standalone_source(name):
    return Path(__file__).with_name(name).read_text(encoding="utf-8")


def recipe(plan):
    note = ("Copy the complete Bash snippet into the SIFT terminal. Each paste creates a fresh results folder "
            "beside the chosen output path (or under ~/sifted-terminal when no output is chosen). "
            "It includes required configuration and private evidence copies; SIFTed does not need to be running. "
            "Native reports are retained; SIFTed's case records and additional derived tables are produced only in the app.")
    if plan.source == "<source_path>":
        return {"terminal_command": "Select an existing evidence path to generate a runnable terminal snippet.",
                "terminal_ready": False, "terminal_note": note}

    parser = plan.parameters.get("parser_id")
    configs = {name: value for name, value in plan.configs.items() if name != "volatility-installation.json"}
    steps = [(step.argv, step.stdout, step.stderr, step) for step in plan.steps]
    if parser == "sqlecmd":
        configs["sqlite-maps.py"] = standalone_source("sqlite_maps.py")
        steps = [(["python3", WORKSPACE + "/sqlite-maps.py", *step.argv[2:]], step.stdout, step.stderr, step)
                 for step in plan.steps]
        note += " SQLite maps use the included Python executor and SIFT's PyYAML; the native Linux SQLECmd binary cannot run these queries."
    elif parser:
        configs["validate-native.py"] = standalone_source("zimmerman_exports.py")
        configs["native-parameters.json"] = json.dumps({**plan.parameters, "input_copies": plan.input_copies}, indent=2)
    elif plan.operation == "filetype":
        configs["filetype-report.py"] = standalone_source("filetype_report.py")
        configs["filetype-request.json"] = json.dumps({"source": plan.source, "argv": plan.steps[0].argv,
                                                     "parameters": plan.parameters}, indent=2)
        steps = [(["python3", WORKSPACE + "/filetype-report.py", WORKSPACE + "/filetype-request.json",
                   OUTPUT + "/filetypes.csv"], None, None, plan.steps[0])]

    body = ["# Run the selected workflow using the tools installed on this SIFT workstation.",
            "# A child Bash shell keeps these settings out of your interactive shell.",
            "set -euo pipefail", "umask 077", "export TZ=UTC", "export LC_ALL=C.UTF-8",
            "source=" + shlex.quote(plan.source)]
    if plan.output_path == "<output_dir>":
        body += ['output_parent="$HOME/sifted-terminal"', "output_name=" + shlex.quote(parser or plan.tool)]
    else:
        body += ["output_parent=" + shlex.quote(str(Path(plan.output_path).parent)),
                 "output_name=" + shlex.quote(Path(plan.output_path).name.encode("utf-8")[:100].decode("utf-8", errors="ignore"))]
    required = list(dict.fromkeys([argv[0] for argv, _, _, _ in steps] +
                                  ([plan.steps[0].argv[0]] if plan.operation == "filetype" else []) +
                                  (["python3"] if parser else []) +
                                  ["mktemp", "mkdir", "sha256sum", "find", "sort", "xargs", "stat", "timeout", "cat", "truncate"] +
                                  (["cp", "chmod", "cmp"] if plan.input_copies else [])))
    body += ["\n# Check prerequisites before creating any output."]
    body += [command_text(["for", "required", "in", *required], plan.source) + "; do",
             '  command -v -- "$required" >/dev/null || { printf \'Required command is unavailable: %s\\n\' "$required" >&2; exit 1; }',
             "done"]
    if parser == "sqlecmd":
        body += ["python3 -c 'import sqlite3, yaml; assert hasattr(sqlite3.Connection, \"setlimit\"), \"Python 3.11 or newer is required\"'"]
    body += ['[[ -f "$source" || -d "$source" ]] || { printf \'%s\\n\' \'Evidence path is unavailable.\' >&2; exit 1; }',
             'case "$output_parent/" in "$source/"*) printf \'%s\\n\' \'Choose an output parent outside the evidence directory.\' >&2; exit 1 ;; esac',
             '\n# Fresh folders make the same snippet safe to paste again.',
             'mkdir -p -- "$output_parent"',
             'root=$(mktemp -d -- "$output_parent/$output_name.terminal.XXXXXXXX")',
             'output="$root/results"', 'workspace="$root/work"', 'mkdir -- "$workspace"',
             'printf \'Terminal run: %s\\n\' "$root"',
             "finish() {", "  code=$?", "  trap - EXIT",
             '  if [[ -s "$root/input-before.sha256" ]] && ! sha256sum --check --status "$root/input-before.sha256"; then',
             '    printf \'%s\\n\' \'Evidence changed; treat results as incomplete.\' >&2', "    code=1", "  fi",
             '  printf \'SIFT_TERMINAL_RESULTS=%s\\n\' "$output"', '  exit "$code"', "}", "trap finish EXIT",
             '\n# Record original input hashes; recheck them when the script finishes.']
    paths = list(dict.fromkeys(plan.input_paths + plan.parameters.get("selected_inputs", []) +
                              list(plan.input_copies) + plan.auxiliary_paths))
    if Path(plan.source).is_file() and plan.source not in paths:
        paths.insert(0, plan.source)
    if paths:
        body += [command_text(["sha256sum", "--", *paths], plan.source) + ' > "$root/input-before.sha256"']
    else:
        body += ['find "$source" -type f -print0 | sort -z | xargs -0 -r sha256sum -- > "$root/input-before.sha256"']
    if plan.input_copies:
        body += ["\n# Replay registry logs / SQLite sidecars only on private captures."]
        for source, relative in plan.input_copies.items():
            target = WORKSPACE + "/" + relative
            body += ["mkdir -p -- " + shell_token(str(Path(target).parent), plan.source),
                     command_text(["cp", "--reflink=auto", "--preserve=timestamps", "--", source, target], plan.source),
                     "chmod 600 -- " + shell_token(target, plan.source),
                     command_text(["cmp", "--", source, target], plan.source)]
    if configs:
        body += ["\n# Exact selected rules, maps and standalone reporting helpers."]
        body += [write_text(name, content) for name, content in configs.items()]
    if plan.tool == "volatility":
        body += ["\n# Ensure automatic symbol downloads have a writable directory.",
                 "mkdir -p -- " + shlex.quote(plan.parameters["managed_symbols"])]
    if plan.tool in {"mmls", "fsstat", "fls", "istat", "icat", "blkstat", "blkcat", "blkls", "blkcalc"}:
        body += ["\n# -o is a partition offset in sectors; inode and block addresses are filesystem-relative.",
                 "# Raw TSK reports are retained. Check mmls sector size before choosing an offset."]
    if plan.tool in {"foremost", "scalpel"}:
        body += ["\n# Carving recovers contiguous byte ranges; review audit.txt and validate recovered files."]
    if plan.parameters.get("ignore_transaction_logs"):
        body += ["\n# Transaction logs are explicitly ignored (--nl); replayed changes may be missing."]
    if plan.tool in TOOL_NOTES and parser != "sqlecmd":
        body += ["\n# " + TOOL_NOTES[plan.tool]]
    if parser == "sqlecmd":
        body += ["\n# The map's IdentifyQuery checks the schema; its data queries then produce CSV and configured blobs."]
    if plan.tool == "blkcalc" and plan.parameters["direction"] == "original_to_unallocated":
        body += ["# Raw blkcalc index bases can vary by build. In mapping_units.txt, count preceding '<unit>|f' rows",
                 "# from zero to establish the selected unit's unallocated-stream index."]
    if plan.create_output_directory or plan.operation == "filetype":
        body += ['mkdir -p -- "$output"']
    body += ['cd -- "$workspace"', "failed=0"]
    for index, (argv, stdout, stderr, step) in enumerate(steps):
        body += ["\n# " + step.label.replace("\n", " ").replace("\r", " ")]
        for path in dict.fromkeys([path for path in (stdout, stderr) if path]):
            body += ["mkdir -p -- " + shell_token(str(Path(path).parent), plan.source)]
        command = command_text(["timeout", "--signal=TERM", "--kill-after=5s", str(step.timeout) + "s", *argv], plan.source,
                               stdout, stderr, stdin="/dev/null")
        body += ["if " + command + "; then", "  :", "else", "  code=$?",
                 f"  printf 'Step {index + 1} failed (exit %s); inspect retained output.\\n' \"$code\" >&2",
                 "  failed=1" if step.continue_on_error else '  exit "$code"', "fi"]
        if step.max_stdout_bytes and stdout:
            target = shell_token(stdout, plan.source)
            body += [f'if [[ $(stat -c %s -- {target}) -gt {step.max_stdout_bytes} ]]; then',
                     "  printf '%s\\n' 'Captured output exceeds the selected limit; treat results as incomplete.' >&2", "  failed=1", "fi"]
    if parser and parser != "sqlecmd":
        body += ["\n# Native parsers can report errors while exiting zero; validate diagnostics and CSVs.",
                 'if ! python3 "$workspace/validate-native.py" "$workspace/native-parameters.json" "$output"; then failed=1; fi']
    body += ['\nexit "$failed"']
    content = "\n".join(body) + "\n"
    delimiter = "SIFT_TERMINAL_" + hashlib.sha256(content.encode()).hexdigest()[:16]
    while delimiter in content.splitlines():
        delimiter += "_"
    return {"terminal_command": f"bash <<'{delimiter}'\n{content}{delimiter}\n",
            "terminal_ready": True, "terminal_note": note}
