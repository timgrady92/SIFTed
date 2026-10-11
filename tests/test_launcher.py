"""Exercise the executable entry point and real deployment process lifetimes."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from sifted_core import launcher
from sifted_core.storage import Repository
from sifted_core.worker import process_identity


ROOT = Path(__file__).resolve().parent.parent


def environment(tmp_path):
    return {**os.environ, "SIFTED_PYTHON": sys.executable,
            "SIFTED_DATABASE_PATH": str(tmp_path / "runtime.sqlite3"),
            "SIFTED_BINARIES": json.dumps({"strings": [sys.executable, "-c", "print('launcher_queue_marker')"]}),
            "SIFTED_INPUT_ROOTS": str(tmp_path), "SIFTED_OUTPUT_ROOTS": str(tmp_path)}


@pytest.mark.parametrize("stop_target", ["launcher-term", "launcher-int", "worker", "web"])
def test_executable_supervises_both_services_from_any_directory(tmp_path, stop_target):
    executable = tmp_path / "sifted link with spaces"
    executable.symlink_to(ROOT / "sifted")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = environment(tmp_path)
    # Exercise both the environment default and the explicit CLI override.
    env["SIFTED_PORT"] = str(port) if stop_target == "launcher-term" else "invalid"
    command = [str(executable)]
    if stop_target != "launcher-term":
        command.extend(["--port", str(port)])
    if stop_target == "web":
        command.append("--lan")
    process = subprocess.Popen(command, cwd=tmp_path, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    worker_pid = None
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1) as response:
                    worker = json.load(response)["worker"]
                if worker["status"] == "online":
                    worker_pid = worker["pid"]
                    break
            except (urllib.error.URLError, TimeoutError):
                pass
            time.sleep(0.05)
        assert worker_pid, process.stderr.read() if process.poll() is not None else "Startup timed out"
        address = "00000000" if stop_target == "web" else "0100007F"
        assert f"{address}:{port:04X}" in Path("/proc/net/tcp").read_text()
        children = [int(pid) for pid in Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()]
        web_pid, = [pid for pid in children if pid != worker_pid]
        if stop_target == "launcher-term":
            source = tmp_path / "sample with spaces.txt"
            source.write_text("launcher_queue_marker")
            request = urllib.request.Request(f"http://127.0.0.1:{port}/api/strings/run",
                data=json.dumps({"source_path": str(source), "output_path": str(tmp_path / "results")}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=5) as response:
                run_id = json.load(response)["run_id"]
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/run/{run_id}/status", timeout=1) as response:
                    run = json.load(response)
                if run["status"] not in {"queued", "running"}:
                    break
                time.sleep(0.05)
            assert run["status"] == "success", run
            assert "launcher_queue_marker" in (tmp_path / "results/strings.txt").read_text()
        if stop_target == "web":
            # Abrupt master death must also clean up its forked HTTP children.
            os.kill(web_pid, signal.SIGKILL)
        else:
            os.kill(worker_pid if stop_target == "worker" else process.pid,
                    signal.SIGINT if stop_target == "launcher-int" else signal.SIGTERM)
        code = process.wait(timeout=20)
        assert (code == 0) == stop_target.startswith("launcher")
        assert process_identity(worker_pid) is None
        with socket.socket() as connection:
            assert connection.connect_ex(("127.0.0.1", port)) != 0
        assert Repository(env["SIFTED_DATABASE_PATH"]).worker_status()["status"] == "offline"
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=20)
        process.stderr.close()


@pytest.mark.parametrize("args,port", [(["--port", "0"], "5000"), (["--port", "65536"], "5000"),
                                     (["--port", "abc"], "5000"), ([], "invalid"), (["setup", "extra"], "5000")])
def test_invalid_options_do_not_start_services(tmp_path, args, port):
    env = {**environment(tmp_path), "SIFTED_PORT": port}
    result = subprocess.run([str(ROOT / "sifted"), *args], env=env, cwd=tmp_path,
                            capture_output=True, timeout=5)
    assert result.returncode == 2
    assert not Path(env["SIFTED_DATABASE_PATH"]).exists()


def test_occupied_web_port_stops_worker(tmp_path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        result = subprocess.run([str(ROOT / "sifted"), "--port", str(listener.getsockname()[1])],
                                env=environment(tmp_path), cwd=tmp_path, capture_output=True, timeout=20)
    assert result.returncode == 1
    assert b"web server exited" in result.stderr
    assert Repository(tmp_path / "runtime.sqlite3").worker_status()["status"] == "offline"


def test_help_and_setup_guidance_work_without_installed_dependencies(tmp_path):
    command = [sys.executable, "-S", "-m", "sifted_core.launcher"]
    help_result = subprocess.run([*command, "--help"], cwd=ROOT, env=environment(tmp_path),
                                 capture_output=True, timeout=5)
    assert help_result.returncode == 0
    result = subprocess.run(command, cwd=ROOT, env=environment(tmp_path), capture_output=True, timeout=5)
    assert result.returncode == 1 and b"./sifted setup" in result.stderr
    assert not (tmp_path / "runtime.sqlite3").exists()


def test_spawn_failure_stops_existing_child_and_restores_signals(monkeypatch):
    original_popen = subprocess.Popen
    children = []
    original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def spawn(*args, **kwargs):
        if children:
            raise OSError("Cannot spawn web server")
        child = original_popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        children.append(child)
        return child

    monkeypatch.setattr(launcher.subprocess, "Popen", spawn)
    with pytest.raises(OSError, match="Cannot spawn web server"):
        launcher.run_launcher(5000)
    assert children[0].poll() is not None
    assert all(signal.getsignal(sig) == handler for sig, handler in original_handlers.items())
