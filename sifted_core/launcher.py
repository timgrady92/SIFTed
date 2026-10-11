"""Local launcher: keep web and worker lifetimes together."""
import os
import signal
import subprocess
import sys
import threading

from werkzeug.serving import make_server


def run(app):
    stop = threading.Event()
    previous_signals = {signum: signal.signal(signum, lambda *_: stop.set()) for signum in (signal.SIGINT, signal.SIGTERM)}
    worker = subprocess.Popen([sys.executable, "-m", "sifted_core.worker"], cwd=os.path.dirname(os.path.dirname(__file__)))
    server = None
    try:
        server = make_server("127.0.0.1", int(os.environ.get("SIFTED_PORT", "5000")), app, threaded=True)
        server.timeout = 0.5
        print(f"SIFTed is listening on http://127.0.0.1:{server.server_port}", flush=True)
        while not stop.is_set() and worker.poll() is None:
            server.handle_request()
        if not stop.is_set():
            raise RuntimeError(f"Worker exited with code {worker.returncode}; web server stopped.")
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.server_close()
        if worker.poll() is None:
            worker.terminate()
        try:
            worker.wait(timeout=15)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait()
        for signum, handler in previous_signals.items():
            signal.signal(signum, handler)
