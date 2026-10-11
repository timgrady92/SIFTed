"""Single-worker durable queue with streamed subprocess output and recovery."""
import csv
import fcntl
import hashlib
import json
import logging
import os
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path

from .tool_base import OUTPUT, Plan, Step, allowed, directory_members, resolve_argv, resolve_token, signature
from .disk_tools import image_sources
from .tool_results import process_results
from .adapters import ADAPTERS
from .storage import utc_now

logger = logging.getLogger(__name__)


class ExecutionFailure(RuntimeError):
    def __init__(self, message, code=1, status="error"):
        super().__init__(message)
        self.code = code
        self.status = status


def hash_file(path, check=None):
    before = signature(path)
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            if check:
                check()
            digest.update(chunk)
    if before != signature(path):
        raise ExecutionFailure(f"File changed while hashing: {path}")
    return digest.hexdigest(), before[2]


def workspace_path(workspace, name, area=None):
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or any(p in {".", ".."} for p in relative.parts):
        raise ExecutionFailure("Invalid managed workspace path.")
    if area and relative.parts[0] != area:
        raise ExecutionFailure("Staged inputs must remain in the managed input directory.")
    if not area and relative.parts[0] in {"input", "output", "run.log", "provenance.json"}:
        raise ExecutionFailure("Configuration overlaps a reserved workspace path.")
    path = workspace / relative
    if path.resolve() != path:
        raise ExecutionFailure("Managed workspace path contains a symbolic link.")
    return path


def copy_input(source, target, expected, check):
    """Copy verified evidence into a private working file without changing the original."""
    digest = hashlib.sha256()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as original, target.open("xb") as captured:
        while data := original.read(1024 * 1024):
            check()
            captured.write(data)
            digest.update(data)
    if digest.hexdigest() != expected:
        raise ExecutionFailure("Staged input differs from the verified evidence: " + str(source))
    shutil.copystat(source, target, follow_symlinks=False)
    target.chmod(0o600)


def tree_size(path):
    total = 0
    if path.exists():
        for root, dirs, files in os.walk(path, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
            for name in files:
                item = Path(root) / name
                try:
                    info = item.stat(follow_symlinks=False)
                except FileNotFoundError:
                    # Tools routinely remove journals and other temporary files
                    # while the worker samples attempt storage consumption.
                    continue
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
    return total


def kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def process_identity(pid):
    """Linux start time prevents signalling a recycled PID during recovery."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


class Worker:
    def __init__(self, repository, settings):
        self.repo = repository
        self.settings = settings
        self.stop = threading.Event()

    def workspace(self, run):
        return Path(run["output_path"]).parent / ".sifted-staging" / run["id"]

    def _check(self, run_id, output, deadline, limit):
        if self.stop.is_set():
            raise ExecutionFailure("Worker stopped; captured results were preserved.", 1, "interrupted")
        run = self.repo.run(run_id)
        if run.get("cancel_requested"):
            raise ExecutionFailure("Run cancelled; captured results were preserved.", 130, "cancelled")
        if time.monotonic() >= deadline:
            raise ExecutionFailure("Run exceeded its execution timeout; output is incomplete.", 124)
        if tree_size(output.parent) > limit:
            raise ExecutionFailure("Output storage budget exceeded; output is incomplete.", 1)

    def _execute_step(self, run, step, output, workspace, log, job_deadline):
        argv = resolve_argv(step.argv, output, workspace)
        self.repo.emit(run["id"], "milestone", "Running " + step.label)
        self.repo.update(run["id"], {"current_step": step.label})
        log.write(("\n$ " + shlex.join(argv) + "\n").encode())
        log.flush()
        environment = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        deadline = min(job_deadline, time.monotonic() + step.timeout)
        stdout_file = stderr_file = None
        process = None
        selector = selectors.DefaultSelector()
        diagnostic = bytearray()
        started = utc_now()
        error = None
        termination = None
        code = 1
        stdout_lines = 0
        stdout_bytes = 0
        stdout_last_byte = None
        try:
            if step.stdout:
                target = Path(resolve_token(step.stdout, str(output), str(workspace)))
                if target.resolve().is_relative_to(output.resolve()) is False:
                    raise ExecutionFailure("Adapter stdout escaped its managed output folder.")
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                stdout_file = os.fdopen(descriptor, "wb")
            if step.stderr:
                target = Path(resolve_token(step.stderr, str(output), str(workspace)))
                if not target.resolve().is_relative_to(output.resolve()):
                    raise ExecutionFailure("Adapter stderr escaped its managed output folder.")
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                stderr_file = os.fdopen(descriptor, "wb")
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=environment, cwd=workspace,
                                       shell=False, start_new_session=True)
            self.repo.update(run["id"], {"process": {"pid": process.pid, "start_time": process_identity(process.pid)}})
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            next_check = 0
            captured = 0
            while selector.get_map():
                now = time.monotonic()
                if now >= next_check:
                    self._check(run["id"], output, deadline, run["plan"]["max_output_bytes"])
                    next_check = now + 0.5
                for key, _ in selector.select(timeout=0.2):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured += len(chunk)
                    if captured > run["plan"]["max_output_bytes"]:
                        raise ExecutionFailure("Subprocess output budget exceeded; output is incomplete.")
                    if key.data == "stdout" and stdout_file:
                        stdout_bytes += len(chunk)
                        if step.max_stdout_bytes is not None and stdout_bytes > step.max_stdout_bytes:
                            remaining = max(0, step.max_stdout_bytes - (stdout_bytes - len(chunk)))
                            stdout_file.write(chunk[:remaining])
                            raise ExecutionFailure("Tool exceeded its bounded output limit; captured output is incomplete.")
                        stdout_file.write(chunk)
                        stdout_lines += chunk.count(b"\n")
                        stdout_last_byte = chunk[-1]
                    else:
                        log.write(chunk)
                    if key.data == "stderr" or not stdout_file:
                        diagnostic.extend(chunk)
                        del diagnostic[:-65536]
                    if key.data == "stderr" and stderr_file:
                        stderr_file.write(chunk)
                log.flush()
                if stdout_file:
                    stdout_file.flush()
                if stderr_file:
                    stderr_file.flush()
            # A process may close both pipes and continue working. Keep checking
            # cancellation and budgets until it actually exits.
            while process.poll() is None:
                self._check(run["id"], output, deadline, run["plan"]["max_output_bytes"])
                time.sleep(0.1)
            code = process.returncode
            self._check(run["id"], output, deadline, run["plan"]["max_output_bytes"])
            if code:
                error = diagnostic.decode("utf-8", errors="replace").strip() or f"{step.label} exited with code {code}."
        except subprocess.TimeoutExpired:
            error, code = "Tool exceeded its execution timeout.", 124
        except FileNotFoundError:
            error, code = "Executable disappeared before execution.", 127
        except ExecutionFailure as exc:
            error, code = str(exc), exc.code
            if exc.status != "error":
                termination = exc
        finally:
            # Always terminate descendants, including ones that closed their
            # pipes while their parent exited. The worker never shares this PGID.
            if process:
                kill_group(process)
                process.stdout.close()
                process.stderr.close()
                self.repo.update(run["id"], {"process": None})
            selector.close()
            if stdout_file:
                stdout_file.flush()
                os.fsync(stdout_file.fileno())
                stdout_file.close()
            if stderr_file:
                stderr_file.flush()
                os.fsync(stderr_file.fileno())
                stderr_file.close()
            log.flush()
        result = {"label": step.label, "argv": argv, "return_code": code,
                  "started_at": started, "completed_at": utc_now(), "error": error,
                  "stdout_bytes": stdout_bytes,
                  "stdout_lines": stdout_lines + int(stdout_last_byte is not None and stdout_last_byte != 10)}
        if termination:
            termination.step_result = result
            raise termination
        return result

    def _filetype(self, run, plan, output, workspace, log, deadline):
        source = Path(plan.source)
        if source.is_file():
            files = iter([source])
        elif plan.parameters["recursive"]:
            files = (Path(root) / name for root, dirs, names in os.walk(source, followlinks=False)
                     for name in names)
        else:
            files = (p for p in source.iterdir() if p.is_file())
        output.mkdir(exist_ok=True)
        mime_by_extension = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
                             "pdf": "application/pdf", "zip": "application/zip", "txt": "text/plain",
                             "json": "application/json", "exe": "application/x-dosexec", "dll": "application/x-dosexec",
                             "doc": "application/msword", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                             "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
        count = mismatches = 0
        failures = []
        with open(output / "filetypes.csv", "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Path", "Extension", "Detected Type", "Mismatch"])
            for path in files:
                self._check(run["id"], output, deadline, plan.max_output_bytes)
                if path.is_symlink() or not path.is_file() or not allowed(path, self.settings.input_roots):
                    failures.append("Skipped non-regular or disallowed file: " + str(path))
                    continue
                step = Step([str(path) if arg == "{selected_file}" else arg for arg in plan.steps[0].argv],
                            "Identify " + path.name, OUTPUT + "/identification.tmp", 10)
                result = self._execute_step(run, step, output, workspace, log, deadline)
                temporary = output / "identification.tmp"
                detected = temporary.read_text(errors="replace").strip() if temporary.exists() else ""
                temporary.unlink(missing_ok=True)
                if result["return_code"]:
                    failures.append(result["error"])
                    continue
                ext = path.suffix.lstrip(".").lower()
                expected = mime_by_extension.get(ext)
                mismatch = bool(plan.parameters["mode"] == "mime" and expected and detected != expected)
                mismatches += mismatch
                count += 1
                if not plan.parameters["mismatch_only"] or mismatch:
                    writer.writerow([str(path), ext, detected, "Yes" if mismatch else "No"])
                handle.flush()
        self.repo.emit(run["id"], "milestone", f"Processed {count} files, {mismatches} mismatches")
        return {"file_count": count, "mismatch_count": mismatches}, failures

    def _publish(self, run, workspace, status):
        """Preserve failed output too; outputs never disappear on rollback."""
        output = workspace / "output"
        destination = Path(run["output_path"])
        if not allowed(workspace, self.settings.output_roots) or workspace.resolve() != workspace:
            raise ExecutionFailure("Managed workspace is no longer allowed; attempt retained.")
        if not allowed(destination, self.settings.output_roots) or str(destination.resolve()) != run["output_path"]:
            raise ExecutionFailure("Output destination is no longer allowed; attempt retained.")
        if output.is_symlink():
            raise ExecutionFailure("Tool created a symbolic link as its output directory; attempt retained.")
        files = []
        if output.exists():
            for root, dirs, names in os.walk(output, followlinks=False):
                for name in dirs + names:
                    try:
                        (Path(root) / name).relative_to(output).as_posix().encode("utf-8")
                    except UnicodeEncodeError as exc:
                        raise ExecutionFailure("Tool output contains a non-UTF-8 path; attempt retained.") from exc
                dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
                for name in sorted(names):
                    path = Path(root) / name
                    if path.is_symlink() or not path.is_file():
                        continue
                    digest, size = hash_file(path)
                    relative = path.relative_to(output).as_posix()
                    files.append({"name": relative, "path": str(destination / relative), "sha256": digest,
                                  "size_bytes": size, "run_id": run["id"], "case_id": run.get("case_id"),
                                  "complete": status == "success"})
            if destination.exists():
                # Only an empty folder accepted at enqueue may be replaced.
                destination.rmdir()
            os.replace(output, destination)
            for entry in files:
                with open(entry["path"], "rb") as handle:
                    os.fsync(handle.fileno())
            fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        attempt_log = workspace / "run.log"
        if attempt_log.exists():
            if Path(run["log_path"]).exists():
                raise ExecutionFailure("Log destination already exists; attempt log retained.")
            os.replace(attempt_log, run["log_path"])
        return files

    def run_once(self):
        run = self.repo.claim()
        if not run:
            return None
        workspace = self.workspace(run)
        output = workspace / "output"
        status, exit_code, error = "success", 0, None
        results = []
        extra = {}
        files = []
        workspace_owned = False
        try:
            plan = Plan.from_dict(run["plan"])
            ADAPTERS[plan.tool].validate_execution(plan, self.settings)
            original_input = self.repo.input(run["id"])
            # Revalidate durable requests at execution time, after queue waiting.
            derived_allowed = original_input.get("source_run_id") and allowed(plan.source, self.settings.output_roots)
            if not (allowed(plan.source, self.settings.input_roots) or derived_allowed) or not allowed(plan.output_path, self.settings.output_roots):
                raise ExecutionFailure("Run paths are no longer allowed.")
            if str(Path(plan.output_path).resolve()) != plan.output_path:
                raise ExecutionFailure("Output path changed while queued.")
            if original_input.get("image_paths") and image_sources(plan.source) != original_input["image_paths"]:
                raise ExecutionFailure("Image segment membership changed while queued.")
            for member in original_input.get("related_files", []):
                if not allowed(member["path"], self.settings.input_roots) or signature(member["path"]) != member["signature"]:
                    raise ExecutionFailure("Related input changed or is no longer allowed: " + member["path"])
            if signature(plan.source) != original_input["signature"]:
                raise ExecutionFailure("Input changed while queued; register or select the current evidence again.")
            if original_input["kind"] == "directory" and directory_members(plan.source) != original_input["members"]:
                raise ExecutionFailure("Directory evidence changed while queued; select the current evidence again.")
            if not allowed(workspace, self.settings.output_roots) or workspace.resolve() != workspace:
                raise ExecutionFailure("Managed workspace path is outside allowed roots or contains symbolic links.")
            workspace.mkdir(parents=True, exist_ok=False)
            workspace_owned = True
            os.chmod(workspace, 0o700)
            deadline = time.monotonic() + self.settings.timeout_seconds
            next_integrity_check = 0

            def integrity_check():
                nonlocal next_integrity_check
                if time.monotonic() >= next_integrity_check:
                    self._check(run["id"], output, deadline, plan.max_output_bytes)
                    next_integrity_check = time.monotonic() + 0.25

            if Path(plan.source).is_file():
                self.repo.emit(run["id"], "status", "Verifying input integrity...")
                digest, size = hash_file(plan.source, integrity_check)
                extra.update(input_sha256=digest, input_size_bytes=size)
                if original_input.get("baseline_sha256") and digest != original_input["baseline_sha256"]:
                    raise ExecutionFailure("Input SHA-256 differs from the registered evidence baseline.")
                if original_input.get("related_files"):
                    extra["input_files"] = [{"path": plan.source, "sha256": digest, "size_bytes": size}]
                    for member in original_input["related_files"]:
                        digest, size = hash_file(member["path"], integrity_check)
                        if member.get("baseline_sha256") and digest != member["baseline_sha256"]:
                            raise ExecutionFailure("Related input SHA-256 differs from its registered baseline: " + member["path"])
                        extra["input_files"].append({"path": member["path"], "sha256": digest, "size_bytes": size})
            else:
                self.repo.emit(run["id"], "status", "Verifying directory evidence integrity...")
                hashes = []
                for member in original_input["members"]:
                    integrity_check()
                    if member["kind"] == "file":
                        digest, size = hash_file(Path(plan.source) / member["path"], integrity_check)
                        hashes.append({"path": member["path"], "sha256": digest, "size_bytes": size})
                extra["input_files"] = hashes
            # Fingerprint the installed executable and assembly/script prefixes;
            # version flags vary across tools and are not safe to guess.
            identities = {}
            for step in plan.steps:
                for argument in step.argv:
                    if argument.startswith("-") or not Path(argument).is_absolute():
                        break
                    if argument == plan.source:
                        break
                    path = Path(argument).resolve()
                    if path.is_file() and str(path) not in identities:
                        digest, size = hash_file(path, integrity_check)
                        identities[str(path)] = {"sha256": digest, "size_bytes": size}
            extra["executables"] = identities
            extra["environment"] = {"LC_ALL": "C", "LANG": "C"}
            if plan.input_copies:
                verified = {entry["path"] if Path(entry["path"]).is_absolute() else str(Path(plan.source) / entry["path"]): entry["sha256"]
                            for entry in extra.get("input_files", [])}
                if extra.get("input_sha256"):
                    verified[plan.source] = extra["input_sha256"]
                for source, name in plan.input_copies.items():
                    if source not in verified:
                        raise ExecutionFailure("Staged input has not been verified: " + source)
                    copy_input(source, workspace_path(workspace, name, "input"), verified[source], integrity_check)
            self.repo.update(run["id"], {"command": "\n".join(plan.commands(str(output), str(workspace)))})
            for name, content in plan.configs.items():
                path = workspace_path(workspace, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            if plan.create_output_directory:
                output.mkdir()
            with open(workspace / "run.log", "wb") as log:
                if plan.operation == "filetype":
                    counts, failures = self._filetype(run, plan, output, workspace, log, deadline)
                    extra.update(counts)
                else:
                    failures = []
                    for step in plan.steps:
                        self._check(run["id"], output, deadline, plan.max_output_bytes)
                        result = self._execute_step(run, step, output, workspace, log, deadline)
                        results.append(result)
                        if result["return_code"]:
                            failures.append(result["error"])
                            if not step.continue_on_error:
                                break
                        else:
                            self.repo.emit(run["id"], "milestone", "Completed " + step.label)
                    if plan.tool == "strings" and results:
                        extra["string_count"] = results[0]["stdout_lines"]
                        self.repo.emit(run["id"], "milestone", f"Found {extra['string_count']} strings")
                if failures:
                    status, exit_code, error = "error", 1, "\n".join(failures)[:65536]
                if status == "success":
                    for name in plan.expected_files:
                        if not (output / name).is_file():
                            raise ExecutionFailure("Tool completed without its expected output: " + name)
                    for pattern in plan.expected_globs:
                        if not any(path.is_file() for path in output.rglob(pattern)):
                            raise ExecutionFailure("Tool completed without its expected output: " + pattern)
                if signature(plan.source) != original_input["signature"]:
                    raise ExecutionFailure("Input changed during execution; results are incomplete.")
                if original_input.get("image_paths") and image_sources(plan.source) != original_input["image_paths"]:
                    raise ExecutionFailure("Image segment membership changed during execution.")
                for member in original_input.get("related_files", []):
                    if signature(member["path"]) != member["signature"]:
                        raise ExecutionFailure("Related input changed during execution; results are incomplete: " + member["path"])
                if original_input["kind"] == "directory" and directory_members(plan.source) != original_input["members"]:
                    raise ExecutionFailure("Directory evidence changed during execution; results are incomplete.")
                self._check(run["id"], output, deadline, plan.max_output_bytes)
                if plan.postprocess and (status == "success" or plan.postprocess_on_failure):
                    processed = process_results(plan, output, integrity_check, results)
                    validation_errors = processed.pop("validation_errors", [])
                    extra.update(processed)
                    if validation_errors:
                        status, exit_code = "error", 1
                        error = "\n".join(filter(None, [error, *validation_errors]))[:65536]
                if signature(plan.source) != original_input["signature"]:
                    raise ExecutionFailure("Input changed during result validation; results are incomplete.")
                for member in original_input.get("related_files", []):
                    if signature(member["path"]) != member["signature"]:
                        raise ExecutionFailure("Related input changed during result validation; results are incomplete: " + member["path"])
                if original_input["kind"] == "directory" and directory_members(plan.source) != original_input["members"]:
                    raise ExecutionFailure("Directory evidence changed during result validation; results are incomplete.")
                log.flush()
                os.fsync(log.fileno())
        except ExecutionFailure as exc:
            if getattr(exc, "step_result", None):
                results.append(exc.step_result)
            status, exit_code, error = exc.status, exc.code, str(exc)
        except Exception as exc:
            logger.exception("Run %s failed", run["id"])
            status, exit_code, error = "error", 1, str(exc)
        if self.repo.begin_finalization(run["id"]) and status == "success":
            status, exit_code, error = "cancelled", 130, "Run cancelled; captured results were preserved."
        try:
            if workspace_owned and workspace.exists():
                (workspace / "provenance.json").write_text(json.dumps({"run_id": run["id"], "input": self.repo.input(run["id"]),
                    "plan": run["plan"], "steps": results, "status": status, "error": error, **extra}, indent=2))
                # Include configuration snapshots and provenance as durable results.
                output.mkdir(exist_ok=True)
                metadata = output / "_sifted"
                if metadata.is_symlink() or metadata.resolve() != metadata:
                    raise ExecutionFailure("Tool created a symbolic link in managed metadata; attempt retained.")
                metadata.mkdir(exist_ok=True)
                provenance = workspace / "provenance.json"
                if (metadata / "provenance.json").exists() or (metadata / "provenance.json").is_symlink():
                    raise ExecutionFailure("Tool occupied the managed provenance destination; attempt retained.")
                shutil.copyfile(provenance, metadata / "provenance.json")
                for name in plan.configs:
                    path = workspace_path(workspace, name)
                    if path.is_symlink() or not path.is_file():
                        raise ExecutionFailure("Configuration snapshot disappeared or became a symbolic link.")
                    if path.read_text(encoding="utf-8") != plan.configs[name]:
                        raise ExecutionFailure("Tool changed its configuration snapshot; attempt retained.")
                    destination = metadata / name
                    if destination.resolve() != destination:
                        raise ExecutionFailure("Configuration output path contains a symbolic link.")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, destination)
                files = self._publish(run, workspace, status)
        except Exception as exc:
            logger.exception("Publication failed for %s", run["id"])
            status, exit_code = "error", 1
            error = f"{error or ''}\nUnable to publish output: {exc}. Attempt retained at {workspace}.".strip()
            extra["retained_workspace"] = str(workspace)
        self.repo.finish(run["id"], {"status": status, "exit_code": exit_code, "error": error,
                                    "steps": results, **extra}, files)
        if workspace_owned and workspace.exists() and workspace.resolve() == workspace and not extra.get("retained_workspace"):
            shutil.rmtree(workspace)
        return run["id"]

    def recover(self):
        for run in self.repo.runs():
            if run["status"] != "running":
                continue
            workspace = self.workspace(run)
            active = run.get("process") or {}
            pid = active.get("pid")
            if pid and pid != os.getpid() and active.get("start_time") and process_identity(pid) == active["start_time"]:
                try:
                    if os.getpgid(pid) == pid:
                        os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            # Recover published output after a crash between rename and commit.
            files = []
            try:
                if workspace.exists():
                    if not allowed(workspace, self.settings.output_roots) or workspace.resolve() != workspace:
                        raise ExecutionFailure("Interrupted run's workspace is no longer allowed.")
                    destination = Path(run["output_path"])
                    if not allowed(destination, self.settings.output_roots) or str(destination.resolve()) != run["output_path"]:
                        raise ExecutionFailure("Interrupted run's output destination is no longer allowed.")
                    if (workspace / "output").exists() and (not destination.exists() or (destination.is_dir() and not any(destination.iterdir()))):
                        files = self._publish(run, workspace, "interrupted")
                    elif (workspace / "run.log").exists() and not Path(run["log_path"]).exists():
                        os.replace(workspace / "run.log", run["log_path"])
                destination = Path(run["output_path"])
                if destination.is_dir() and allowed(destination, self.settings.output_roots):
                    for root, dirs, names in os.walk(destination, followlinks=False):
                        dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
                        for name in names:
                            path = Path(root) / name
                            if path.is_symlink() or not path.is_file():
                                continue
                            digest, size = hash_file(path)
                            files.append({"name": path.relative_to(destination).as_posix(), "path": str(path),
                                          "sha256": digest, "size_bytes": size, "complete": False, "run_id": run["id"]})
            except Exception:
                logger.exception("Retained interrupted output at %s", workspace)
            unique = {entry["path"]: entry for entry in files}
            self.repo.finish(run["id"], {"status": "interrupted", "exit_code": 1,
                "error": "Worker was interrupted. Captured output is incomplete; retry creates a new run.",
                "retained_workspace": str(workspace) if workspace.exists() else None}, unique.values())

    def run_forever(self):
        lock_path = self.repo.path.with_suffix(self.repo.path.suffix + ".worker.lock")
        with open(lock_path, "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("Another worker owns this database.") from exc
            heartbeat_stop = threading.Event()

            def heartbeat():
                while not heartbeat_stop.is_set():
                    self.repo.heartbeat(os.getpid())
                    heartbeat_stop.wait(2)

            thread = threading.Thread(target=heartbeat, daemon=True)
            thread.start()
            try:
                self.recover()
                while not self.stop.is_set():
                    if self.run_once() is None:
                        self.stop.wait(0.5)
            finally:
                heartbeat_stop.set()
                thread.join(timeout=5)
                self.repo.clear_heartbeat(os.getpid())


def main():
    from .config import load_config
    from .storage import Repository
    config = load_config()
    worker = Worker(Repository(config["DATABASE_PATH"]), config["SETTINGS"])
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: worker.stop.set())
    worker.run_forever()


if __name__ == "__main__":
    main()
