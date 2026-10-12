"""Analyst-facing native CLI examples, separate from worker orchestration.

Validated plans supply the selected evidence and native arguments. Presentation
removes managed execution details and teaches the corresponding terminal task.
"""
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


def shell_token(value):
    for token in (OUTPUT, WORKSPACE):
        if value == token or value.startswith(token + "/"):
            value = value[len(token):].lstrip("/") or "."
            break
    return shlex.quote(value)


def command_text(argv, stdout=None):
    command = " ".join(shell_token(word) for word in argv)
    if stdout:
        command += " > " + shell_token(stdout)
    return command


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
    delimiter = prefix
    while delimiter in content.splitlines():
        delimiter += "_END"
    return delimiter


def copied_evidence(plan, body):
    """Use ordinary writable copies only for sidecars requiring preparation."""
    parser = plan.parameters["parser_id"]
    target = Path.home() / (parser + "-evidence")
    body += [command_text(["mkdir", "--", str(target)])]
    directory = Path(plan.source).is_dir()
    copies = {}
    for source, destination in plan.input_copies.items():
        relative = Path(source).relative_to(plan.source) if directory else Path(source).name
        copies[source] = target / Path(relative).with_name(Path(destination).name)
    parents = sorted({str(path.parent) for path in copies.values() if path.parent != target})
    if parents:
        body += [command_text(["mkdir", "-p", "--", *parents])]
    for source, destination in copies.items():
        body += [command_text(["cp", "-p", "--", source, str(destination)])]
    body += [command_text(["chmod", "-R", "u+w", "--", str(target)])]
    return str(target) if directory else str(copies[plan.source])


def sqlite_commands(plan, body):
    has_sidecars = set(plan.input_copies) - set(plan.parameters["selected_inputs"])
    database = copied_evidence(plan, body) if has_sidecars else plan.source
    selected = plan.parameters["selected_inputs"]
    request = json.loads(plan.configs["sqlite-request.json"])
    for index, source in enumerate(selected):
        path = str(Path(database) / Path(source).relative_to(plan.source)) if Path(plan.source).is_dir() else database
        suffix = f"-{index + 1}" if len(selected) > 1 else ""
        body += [command_text(["sqlite3", "-readonly", path, ".tables"]),
                 command_text(["sqlite3", "-readonly", path, ".schema"], "schema" + suffix + ".sql")]
        task = next(task for task in request["inputs"] if task["source"] == source)
        for map_index, name in enumerate(task["maps"]):
            query = load_map(plan.configs["maps/" + name])["Queries"][0]
            sql = query["Query"].strip().removesuffix(";") + ";"
            body += [command_text(["sqlite3", "-readonly", "-bail", "-header", "-csv", path, sql],
                                  f"query{suffix}-{map_index + 1}.csv")]
    return bool(has_sidecars)


def zimmerman_commands(plan, body, settings):
    parser = plan.parameters["parser_id"]
    first = plan.steps[0]
    # Native registry parsers read hives and logs without rewriting them. Copies
    # are needed here only when Linux requires different log filename casing.
    rename_logs = parser in REGISTRY and any(Path(source).name != Path(destination).name
                                             for source, destination in plan.input_copies.items())
    source = copied_evidence(plan, body) if rename_logs else plan.source
    args = without_options(native_argv(first.argv), {"--debug": 0, "--dt": 1, "--csv": 1,
                                                   "--bn": 1, "--maps": 1, "-f": 1, "-d": 1})
    args += ["-d" if Path(plan.source).is_dir() else "-f", source, "--csv", parser + "-csv"]
    if parser in {"recmd", "evtxecmd"}:
        root = resource_root(first.argv, parser, settings)
        args += (["--bn", str(root / "BatchExamples" / (plan.parameters["batch"] + ".reb"))]
                 if parser == "recmd" else ["--maps", str(root / "Maps")])
    body += [command_text(args)]
    return rename_logs


def file_commands(plan, body):
    args = native_argv(plan.steps[0].argv)
    if plan.parameters["mode"] != "brief":
        args = without_options(args, {"-b": 0})
    args = [plan.source if word == "{selected_file}" else word for word in args]
    if Path(plan.source).is_dir():
        depth = [] if plan.parameters["recursive"] else ["-maxdepth", "1"]
        args = ["find", plan.source, *depth, "-type", "f", "-exec", *["{}" if word == plan.source else word for word in args], "+"]
    body += [command_text(args, "filetypes.txt")]


def volatility_commands(plan, body):
    symbols = str(Path.home() / ".local/share/volatility3/symbols")
    body += [command_text(["mkdir", "-p", "--", symbols])]
    symbol_dirs = plan.parameters["symbol_path"] + ";" + symbols if plan.parameters["symbol_path"] else symbols
    for step in plan.steps:
        name = step.label
        args = without_options(native_argv(step.argv), {"--save-config": 1, "-s": 1, "-o": 1})
        library = plan.parameters.get('yara_libraries', {}).get(name)
        if library:
            args = [library['path'] if arg == WORKSPACE + '/yara/memory.yar' else arg for arg in args]
        args[args.index(name):args.index(name)] = ["-s", symbol_dirs]
        suffix = "txt" if plan.parameters["renderer"] == "pretty" else plan.parameters["renderer"]
        body += [command_text(args, name + "." + suffix)]


def recipe(plan, settings=None):
    note = "Run from a working results directory in the SIFT terminal. Evidence paths are absolute; reports use the filenames shown in your current directory. Change output names to keep previous results. "
    if plan.operation == "evidence-intake":
        path = shlex.quote(plan.source)
        command = f"sha256sum -- {path}\nfile --mime-type -- {path}"
        if Path(plan.source).is_dir():
            command = f"find {path} -type f -exec sha256sum -- {{}} +"
        return {"terminal_command": command, "terminal_ready": True,
                "terminal_note": "SHA-256 verifies file bytes. A directory manifest also records relative paths and empty directories; its aggregate hash uses SIFTed's documented canonical format."}
    if plan.source == "<source_path>":
        return {"terminal_command": "Select an existing evidence path to generate runnable CLI commands.",
                "terminal_ready": False, "terminal_note": note}
    parser = plan.parameters.get("parser_id")
    body = []
    prepared_copy = False
    if parser == "sqlecmd":
        prepared_copy = sqlite_commands(plan, body)
        note += "sqlite3 -readonly opens the database for inspection; .tables lists tables, .schema shows SQL definitions, and -header -csv exports query results. The SQL example is the first query from each selected profile; check it against the schema. Databases with sidecars are copied together before inspection. SQLite localtime expressions use the workstation's time zone."
    elif parser:
        prepared_copy = zimmerman_commands(plan, body, settings)
        note += TOOL_NOTES[plan.tool]
        if any(Path(source).name != Path(destination).name for source, destination in plan.input_copies.items()):
            note += " Linux registry parsers need uppercase .LOG1/.LOG2 names; the preparation gives working copies those names."
        if plan.parameters.get("ignore_transaction_logs"):
            note += " --nl ignores registry transaction logs; replayed changes may be missing."
    elif plan.operation == "filetype":
        file_commands(plan, body)
        note += "file identifies content; --mime-type reports MIME types and -b omits filenames. find -exec applies it to files in a directory. Compare the reported types with the filename extensions; mismatch filtering and CSV formatting are app features."
    elif plan.tool == 'clamscan':
        args = native_argv(plan.steps[1].argv)
        args = without_options(args, {'--database': 1})
        boundary = args.index('--')
        args[boundary:boundary] = ['--database', plan.parameters['database_directory']]
        body += [command_text(args, 'clamscan.txt')]
        note += 'Exit code 1 means a signature match; 2 means an error. Inspect matches and scan limits. The installed signature set can change; SIFTed records the database hashes used for its run.'
    elif plan.tool == "volatility":
        volatility_commands(plan, body)
        note += TOOL_NOTES[plan.tool] + " Extracted files are written to the current directory."
    else:
        if plan.tool == "scalpel":
            config = "\n".join(line for line in plan.configs["scalpel.conf"].splitlines() if line and not line.startswith("#")) + "\n"
            delimiter = heredoc(config, "SCALPEL_RULES")
            body += ["cat > scalpel.conf <<'" + delimiter + "'", config + delimiter]
        for step in plan.steps:
            args = native_argv(step.argv)
            if plan.tool == "foremost":
                args = without_options(args, {"-c": 1})
            if plan.tool in {"foremost", "scalpel", "bulk-extractor"}:
                directory = "bulk-features" if plan.tool == "bulk-extractor" else plan.tool + "-carved"
                args = [directory if arg == OUTPUT else arg for arg in args]
            body += [command_text(args, step.stdout)]
        note += TOOL_NOTES.get(plan.tool, "")
        if plan.tool in {"foremost", "scalpel"}:
            note += " Carving requires a complete raw byte stream; export image containers to raw first."
        if plan.tool in {"fsstat", "fls", "istat", "icat", "blkstat", "blkcat", "blkls", "blkcalc"}:
            note += " -o is measured in image sectors, not bytes; inode and block addresses are relative to that filesystem."
    if prepared_copy:
        note += " Preparation needs a new working-copy directory; && stops the commands if a preparation step fails."
    return {"terminal_command": (" &&\n" if prepared_copy else "\n").join(body) + "\n",
            "terminal_ready": True, "terminal_note": note}
