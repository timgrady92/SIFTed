import os
import shlex
import sys
import tempfile
import threading
import unittest

import app as sifted_app


class SiftedAppTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.data_dir = os.path.join(self.temp_dir.name, "data")
        os.makedirs(self.data_dir, exist_ok=True)

        self.image_file = os.path.join(self.temp_dir.name, "image.dd")
        with open(self.image_file, "w", encoding="utf-8") as handle:
            handle.write("test")

        self._orig_paths = {
            "ALLOWED_PATHS": sifted_app.ALLOWED_PATHS,
            "OUTPUT_ROOTS": sifted_app.OUTPUT_ROOTS,
            "INPUT_ROOTS": sifted_app.INPUT_ROOTS,
            "CASES_PATH": sifted_app.CASES_PATH,
            "RUNS_PATH": sifted_app.RUNS_PATH,
        }

        sifted_app.ALLOWED_PATHS = [self.temp_dir.name]
        sifted_app.OUTPUT_ROOTS = [self.temp_dir.name]
        sifted_app.INPUT_ROOTS = [self.temp_dir.name]
        sifted_app.CASES_PATH = os.path.join(self.data_dir, "cases.json")
        sifted_app.RUNS_PATH = os.path.join(self.data_dir, "runs.json")
        sifted_app.app.config["TESTING"] = True

        self.client = sifted_app.app.test_client()

    def tearDown(self):
        for key, value in self._orig_paths.items():
            setattr(sifted_app, key, value)

    def test_filetype_command_preview_recursive(self):
        source_dir = os.path.join(self.temp_dir.name, "evidence")
        os.makedirs(source_dir, exist_ok=True)
        with open(os.path.join(source_dir, "sample.bin"), "w", encoding="utf-8") as handle:
            handle.write("content")
        output_path = os.path.join(self.temp_dir.name, "filetype-output")

        original_runner = sifted_app.start_filetype_run
        sifted_app.start_filetype_run = lambda *args, **kwargs: None
        try:
            response = self.client.post(
                "/api/filetype/run",
                json={
                    "image_path": source_dir,
                    "output_path": output_path,
                    "mode": "mime",
                    "recursive": True,
                },
            )
        finally:
            sifted_app.start_filetype_run = original_runner

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        expected = f"find {shlex.quote(source_dir)} -type f -exec file --mime-type -b {{}} \\;"
        self.assertEqual(data["command"], expected)

    def test_exiftool_rejects_unknown_format(self):
        output_path = os.path.join(self.temp_dir.name, "exif-output")

        original_runner = sifted_app.start_exiftool_run
        sifted_app.start_exiftool_run = lambda *args, **kwargs: None
        try:
            response = self.client.post(
                "/api/exiftool/run",
                json={
                    "image_path": self.image_file,
                    "output_path": output_path,
                    "output_format": "weird",
                },
            )
        finally:
            sifted_app.start_exiftool_run = original_runner

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("-csv", data["command"])
        self.assertIn("metadata.csv", data["command"])

    def test_post_process_failure_sets_exit_code(self):
        run_id = "test-post-process"
        log_path = os.path.join(self.temp_dir.name, "generic.log")
        done = threading.Event()
        captured = {}

        def finalize_stub(run_id_arg, status, exit_code, log_path_arg, extra_updates=None):
            captured["status"] = status
            captured["exit_code"] = exit_code
            done.set()

        original_finalize = sifted_app.finalize_run
        original_mark = sifted_app.mark_run_done
        sifted_app.finalize_run = finalize_stub
        sifted_app.mark_run_done = lambda *_args, **_kwargs: None
        try:
            sifted_app.start_generic_run(
                run_id,
                [sys.executable, "-c", "print('ok')"],
                log_path,
                post_process=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
            )
            completed = done.wait(timeout=5)
            self.assertTrue(completed)
            self.assertEqual(captured.get("status"), "error")
            self.assertEqual(captured.get("exit_code"), 1)
        finally:
            sifted_app.finalize_run = original_finalize
            sifted_app.mark_run_done = original_mark
            sifted_app.RUN_STATE.pop(run_id, None)


if __name__ == "__main__":
    unittest.main()
