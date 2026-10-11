"""Command-line deployment: supervise the HTTP server and durable worker together."""
import argparse
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


BASE_DIR = Path(__file__).resolve().parent.parent


def valid_port(raw):
    try:
        port = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def stop_processes(processes):
    # Signal both services before waiting. A dead Gunicorn master may still
    # have HTTP children, so signal its group even when the master has exited.
    for _, process in processes:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 15
    for _, process in processes:
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
    for _, process in processes:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_launcher(port, lan=False):
    stop = threading.Event()
    previous_signals = {}
    processes = []
    host = "0.0.0.0" if lan else "127.0.0.1"
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_signals[signum] = signal.signal(signum, lambda *_: stop.set())
        commands = [
            ("worker", [sys.executable, "-m", "sifted_core.worker"]),
            ("web server", [sys.executable, "-m", "gunicorn", "--config", "/dev/null",
                            "--bind", f"{host}:{port}", "--workers", "2", "--threads", "8",
                            "--timeout", "0", "--graceful-timeout", "5", "wsgi:app"]),
        ]
        print(f"Starting SIFTed at http://{host}:{port}. Press Ctrl+C to stop.", flush=True)
        if lan:
            print("LAN access is unauthenticated; use a trusted network.", flush=True)
        for name, command in commands:
            if stop.is_set():
                return 0
            processes.append((name, subprocess.Popen(command, cwd=BASE_DIR, start_new_session=True)))
        while not stop.wait(0.2):
            for name, process in processes:
                code = process.poll()
                if code is not None:
                    print(f"SIFTed {name} exited with code {code}; stopping both services.", file=sys.stderr)
                    return 1
        return 0
    finally:
        stop_processes(processes)
        for signum, handler in previous_signals.items():
            signal.signal(signum, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sifted", description="Start the SIFTed web UI and job worker together.",
                                     epilog="First-time installation or dependency update: sifted setup")
    parser.add_argument("--port", type=valid_port, default=os.environ.get("SIFTED_PORT", "5000"),
                        help="HTTP port (default: SIFTED_PORT or 5000)")
    parser.add_argument("--lan", action="store_true",
                        help="Listen on all interfaces; use only on a trusted network (no authentication)")
    args = parser.parse_args(argv)
    missing = [name for name in ("flask", "gunicorn") if importlib.util.find_spec(name) is None]
    if missing:
        parser.exit(1, f"Missing dependencies: {', '.join(missing)}. Run ./sifted setup first.\n")
    try:
        return run_launcher(args.port, args.lan)
    except OSError as exc:
        print(f"Could not start SIFTed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
