"""Run with Volatility's Python, independently of SIFTed's virtual environment."""
import argparse
import hashlib
import inspect
import json
import sys
from pathlib import Path

# A configured `python /path/to/vol.py` can use a source checkout.
if len(sys.argv) > 1:
    sys.path.insert(0, sys.argv[1])

from volatility3 import cli, framework, plugins
from volatility3.framework import constants
from volatility3.framework.configuration import requirements
from volatility3.framework.deprecation import PluginRenameClass


def source_identity(component):
    path = Path(inspect.getfile(component)).resolve()
    with path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return {"path": str(path), "sha256": digest}


def main():
    failures = framework.import_files(plugins, True)
    catalog = {}
    for name, plugin in sorted(framework.list_plugins().items()):
        description = inspect.getdoc(plugin) or name
        if issubclass(plugin, PluginRenameClass):
            continue
        parser = argparse.ArgumentParser(add_help=False)
        cli.CommandLine().populate_requirements_argparse(parser, plugin)
        declarations = {r.name: r for r in plugin.get_requirements()}
        options = []
        for action in parser._actions:
            req = declarations[action.dest]
            if isinstance(req, requirements.URIRequirement):
                kind = "file"
            elif isinstance(req, requirements.BooleanRequirement):
                kind = "boolean"
            elif isinstance(req, requirements.ListRequirement):
                kind = "integer_list" if req.element_type is int else "string_list"
            elif isinstance(req, requirements.IntRequirement):
                kind = "integer"
            else:
                kind = "string"
            options.append({"name": action.dest, "flag": action.option_strings[0],
                            "type": kind, "required": action.required,
                            "default": action.default, "choices": action.choices,
                            "description": action.help})
        catalog[name] = {"description": description, "options": options,
                         "source": source_identity(plugin),
                         "os": name.split(".")[0] if name.startswith(("windows.", "linux.", "mac.")) else "general"}
    print(json.dumps({"version": constants.PACKAGE_VERSION, "plugins": catalog,
                      "cli_source": source_identity(cli),
                      "symbol_paths": constants.SYMBOL_BASEPATHS, "import_failures": failures}))


if __name__ == "__main__":
    main()
