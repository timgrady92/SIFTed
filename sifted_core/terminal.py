"""Analyst-facing native CLI examples, separate from worker orchestration.

Validated plans supply the selected evidence and native arguments. Presentation
removes managed execution details and teaches the corresponding terminal task.
"""
import hashlib
import json
import shlex
from pathlib import Path

from .sqlite_maps import load_map
from .tool_base import OUTPUT, WORKSPACE
from .zimmerman import REGISTRY, resource_root

TOOL_NOTES = {
    "strings": "-a scans the whole file; -e selects character encoding; -n sets minimum length; -t x reports hexadecimal byte offsets.",
    "exiftool": "-csv/-json select the report format; -r visits subdirectories; -G1 identifies tag groups; -s uses tag names.",
    "bulk-extractor": "-o writes feature reports; -x all disables default scanners when a focus is selected; -e enables each selected scanner.",
    "artifact-triage": "log2timeline builds the Plaso storage file; psort exports l2tcsv using the selected display time zone.",
    "volatility": "Global options precede the plugin name; plugin options follow it. -r selects the report format; -o holds extracted files. -s adds symbol directories. The writable directory under ~/.local/share lets Volatility download symbols without changing its system installation.",
    "eric-zimmerman": "dotnet runs the installed parser DLL; -f selects a file and -d selects a directory; --csv selects the export folder. Read the parser's terminal diagnostics along with its CSV reports.",
    "head": "-c limits the number of bytes read; -- separates options from the evidence filename.",
    "xxd": "-s is a byte offset; -l limits bytes; -g 1 groups individual bytes; -c 16 sets bytes per line.",
    "pdfinfo": "-isodates prints ISO date values; -enc UTF-8 selects the report encoding.",
    "pdftotext": "-f/-l select first/last pages; -layout preserves layout; the final - writes text to stdout.",
    "foremost": "-t selects built-in file parsers; -i selects the raw evidence; -o selects the recovery folder. Review audit.txt and the recovered files.",
    "scalpel": "The configuration lists extension, case sensitivity, maximum size, header and footer. -c selects these rules; -o selects output; -O disables extension-based grouping. Review audit.txt and the recovered files.",
    "mmls": "-B adds partition sizes in bytes. Read the sector size and Start column before choosing a filesystem offset.",
    "fsstat": "-o selects the filesystem's starting sector; -b specifies the image sector size when needed.",
    "fls": "-r/-p list recursive paths; -d lists deleted entries; an optional final address selects a directory inode.",
    "istat": "The final address is the metadata record (inode or NTFS MFT entry); this examines metadata rather than file contents.",
    "icat": "The final address selects file content; NTFS entry-type-id addresses select a specific stream. > saves the recovered bytes.",
    "blkstat": "The final address selects one filesystem data unit and reports its allocation state.",
    "blkcat": "The final address and count select filesystem data units; > saves their raw bytes.",
    "blkls": "-A selects unallocated units in the final inclusive range; > saves their raw bytes.",
    "blkcalc": "-d maps an original filesystem unit into the unallocated stream; -u maps an unallocated-stream index back. Native index conventions can vary; use blkls -A -l to check the allocation order.",
}


def shell_token(value, source):
    if value == "{symbol_dirs}":
        return '"$symbol_dirs"'
    for token, variable in ((OUTPUT, "results"), (WORKSPACE, "results")):
        if value == token or value.startswith(token + "/"):
            suffix = value[len(token):]
            return '"$' + variable + suffix.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`") + '"'
    if source and value in {source, source + "/."}:
        return '"$evidence' + value[len(source):] + '"'
    return shlex.quote(value)


def command_text(argv, source, stdout=None):
    words, index = [], 0
    while index < len(argv):
        word = shell_token(argv[index], source)
        if argv[index].startswith("-") and "=" not in argv[index] and index + 1 < len(argv) and not argv[index + 1].startswith("-"):
            index += 1
            word += " " + shell_token(argv[index], source)
        words.append(word)
        index += 1
    if stdout:
        words += ["> " + shell_token(stdout, source)]
    lines, line = [], ""
    for word in words:
        if line and len(line) + len(word) + 1 > 88:
            lines.append(line + " \\")
            line = "  " + word
        else:
            line += (" " if line else "") + word
    return "\n".join([*lines, line])


def native_argv(argv):
    """Use installed command names, retaining necessary interpreter arguments."""
    command = Path(argv[0]).name
    if command.startswith("python"):
        command = "python3"
    return [command, *argv[1:]]


def without_options(argv, options):
    result, index = [], 0
    while index < len(argv):
        value = argv[index]
        if value in options:
            index += options[value] + 1
        else:
            result.append(value)
            index += 1
    return result


def heredoc(content, prefix):
    delimiter = prefix + "_" + hashlib.sha256(content.encode()).hexdigest()[:12]
    while delimiter in content.splitlines():
        delimiter += "_"
    return delimiter


def captured_evidence(plan, body):
    """Show ordinary evidence copies when a native parser may replay sidecars."""
    target = OUTPUT + "/evidence"
    body += ["# Work on a copy with its transaction logs or SQLite sidecars.",
             "mkdir -- " + shell_token(target, plan.source)]
    if Path(plan.source).is_dir():
        # Preserve the original folder layout, including adjacent transaction logs.
        body += [command_text(["cp", "-a", "--", plan.source + "/.", target + "/"], plan.source),
                 command_text(["chmod", "-R", "u+w", "--", target], plan.source)]
        renames = []
        for source, destination in plan.input_copies.items():
            relative = Path(source).relative_to(plan.source)
            expected = relative.with_name(Path(destination).name)
            if relative != expected:
                renames += [command_text(["mv", "--", target + "/" + relative.as_posix(),
                                          target + "/" + expected.as_posix()], plan.source)]
        if renames:
            body += ["# Linux registry parsers expect uppercase .LOG1/.LOG2 names beside the hive.", *renames]
        return target
    for source in plan.input_copies:
        destination = Path(plan.input_copies[source]).name
        body += [command_text(["cp", "-p", "--", source, target + "/" + destination], plan.source)]
    body += [command_text(["chmod", "-R", "u+w", "--", target], plan.source)]
    return target + "/" + Path(plan.source).name


def sqlite_commands(plan, body):
    database = captured_evidence(plan, body)
    # sqlite3 is the native workstation CLI, independent of the app's map engine.
    body += ["export TZ=UTC", "# Inspect the tables and schema before querying the database."]
    selected = plan.parameters["selected_inputs"]
    request = json.loads(plan.configs["sqlite-request.json"])
    for index, source in enumerate(selected):
        path = database + "/" + str(Path(source).relative_to(plan.source)) if Path(plan.source).is_dir() else database
        suffix = f"-{index + 1}" if len(selected) > 1 else ""
        body += [command_text(["sqlite3", "-readonly", path, ".tables"], plan.source),
                 command_text(["sqlite3", "-readonly", path, ".schema"], plan.source, OUTPUT + "/schema" + suffix + ".sql")]
        task = next(task for task in request["inputs"] if task["source"] == source)
        for map_index, name in enumerate(task["maps"]):
            profile = load_map(plan.configs["maps/" + name])
            query = profile["Queries"][0]
            sql = query["Query"].rstrip().removesuffix(";") + ";\n"
            delimiter = heredoc(sql, "SQL")
            body += ["# SQL example: " + query["Name"].replace("\n", " ").replace("\r", " "),
                     command_text(["sqlite3", "-readonly", "-bail", "-header", "-csv", path], plan.source,
                                  OUTPUT + f"/query{suffix}-{map_index + 1}.csv") + " <<'" + delimiter + "'",
                     sql + delimiter]


def zimmerman_commands(plan, body, settings):
    parser = plan.parameters["parser_id"]
    first = plan.steps[0]
    source = captured_evidence(plan, body) if parser in REGISTRY else plan.source
    args = without_options(native_argv(first.argv), {"--debug": 0, "--dt": 1, "--csv": 1,
                                                   "--bn": 1, "--maps": 1, "-f": 1, "-d": 1})
    args += ["-d" if Path(plan.source).is_dir() else "-f", source, "--csv", OUTPUT]
    if parser in {"recmd", "evtxecmd"}:
        # Use the profiles that come with the native installation, not snapshots.
        root = resource_root(first.argv, parser, settings)
        if parser == "recmd":
            body += ["# --bn selects an installed registry batch profile."]
            args += ["--bn", str(root / "BatchExamples" / (plan.parameters["batch"] + ".reb"))]
        else:
            args += ["--maps", str(root / "Maps")]
    body += [command_text(args, plan.source)]


def file_commands(plan, body):
    args = native_argv(plan.steps[0].argv)
    if plan.parameters["mode"] != "brief":
        args = without_options(args, {"-b": 0})
    args = [plan.source if word == "{selected_file}" else word for word in args]
    if Path(plan.source).is_dir():
        depth = [] if plan.parameters["recursive"] else ["-maxdepth", "1"]
        args = ["find", plan.source, *depth, "-type", "f", "-exec", *["{}" if word == plan.source else word for word in args], "+"]
    body += [command_text(args, plan.source, OUTPUT + "/filetypes.txt")]


def volatility_commands(plan, body):
    body += ['symbols="$HOME/.local/share/volatility3/symbols"',
             'mkdir -p -- "$symbols"',
             "symbol_dirs=" + (shlex.quote(plan.parameters["symbol_path"] + ";") if plan.parameters["symbol_path"] else "") + '"$symbols"']
    for step in plan.steps:
        name = step.label
        folder = OUTPUT + "/" + name
        args = without_options(native_argv(step.argv), {"--save-config": 1, "-s": 1, "-o": 1})
        plugin_index = args.index(name)
        global_args = ["-s", "{symbol_dirs}", "-o", folder]
        args[plugin_index:plugin_index] = global_args
        suffix = "txt" if plan.parameters["renderer"] == "pretty" else plan.parameters["renderer"]
        body += ["mkdir -- " + shell_token(folder, plan.source), command_text(args, plan.source, folder + "/result." + suffix)]


def recipe(plan, settings=None):
    note = "Run these commands in Bash on SIFT. Change the evidence path and options to use them on another case. "
    note += "A fresh results directory keeps repeated runs separate; the parentheses keep shell variables local. "
    if plan.source == "<source_path>":
        return {"terminal_command": "Select an existing evidence path to generate runnable CLI commands.",
                "terminal_ready": False, "terminal_note": note}
    parser = plan.parameters.get("parser_id")
    name = parser or plan.tool
    body = ["(", "set -e", "evidence=" + shlex.quote(plan.source)]
    if plan.output_path == "<output_dir>":
        body += ['results_parent="$HOME/forensic-results"']
    else:
        body += ["results_parent=" + shlex.quote(str(Path(plan.output_path).parent))]
    body += ['mkdir -p -- "$results_parent"',
             'results=$(mktemp -d -- "$results_parent/' + name + '.XXXXXXXX")', ""]
    if parser == "sqlecmd":
        sqlite_commands(plan, body)
        note += "sqlite3 -readonly opens the copied database for inspection; .tables lists tables, .schema shows SQL definitions, and -header -csv exports query results. "
        note += "The SQL example is the first query from each selected profile. Check it against the schema before using it on other databases. "
        note += "This teaches native SQLite inspection; SIFTed's map matching, deduplication and blob exports are app features. The installed Linux SQLECmd cannot execute queries on this workstation."
    elif parser:
        zimmerman_commands(plan, body, settings)
        note += TOOL_NOTES[plan.tool]
        if plan.parameters.get("ignore_transaction_logs"):
            note += " --nl ignores registry transaction logs; replayed changes may be missing."
    elif plan.operation == "filetype":
        file_commands(plan, body)
        note += "file identifies content; --mime-type reports MIME types and -b omits filenames. find -exec applies it to files in a directory. Compare the reported types with the filename extensions; mismatch filtering and CSV formatting are app features."
    elif plan.tool == "volatility":
        volatility_commands(plan, body)
        note += TOOL_NOTES[plan.tool]
    else:
        if plan.tool == "scalpel":
            config = "\n".join(line for line in plan.configs["scalpel.conf"].splitlines() if line and not line.startswith("#")) + "\n"
            delimiter = heredoc(config, "CARVING_RULES")
            body += ["# Define the selected header/footer rules in a local configuration.",
                     'cat > "$results/scalpel.conf" <<\'' + delimiter + "'", config + delimiter]
        for step in plan.steps:
            args = native_argv(step.argv)
            if plan.tool == "foremost":
                args = without_options(args, {"-c": 1})
            # Carvers create their own output directory; keep configuration separate.
            if plan.tool in {"foremost", "scalpel", "bulk-extractor"}:
                directory = "/features" if plan.tool == "bulk-extractor" else "/carved"
                args = [OUTPUT + directory if arg == OUTPUT else arg for arg in args]
            body += [command_text(args, plan.source, step.stdout)]
        note += TOOL_NOTES.get(plan.tool, "")
        if plan.tool in {"foremost", "scalpel"}:
            note += " Carving requires a complete raw byte stream; export image containers to raw first."
        if plan.tool in {"fsstat", "fls", "istat", "icat", "blkstat", "blkcat", "blkls", "blkcalc"}:
            note += " -o is measured in image sectors, not bytes; inode and block addresses are relative to that filesystem."
    body += ["", 'printf \'Results: %s\\n\' "$results"', ")", ""]
    return {"terminal_command": "\n".join(body), "terminal_ready": True, "terminal_note": note}
