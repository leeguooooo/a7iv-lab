"""Compile and execute owned C memory contracts without firmware or devices."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SoundMemoryModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which(os.environ.get("CC", "cc"))
        if cls.compiler is None:
            raise unittest.SkipTest("A C11 host compiler is required")
        cls.temp = tempfile.TemporaryDirectory(prefix="camera-sound-model-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.build = Path(cls.temp.name)

    def run_command(self, args):
        result = subprocess.run(
            list(map(str, args)), capture_output=True, text=True, timeout=60,
            env=dict(os.environ, UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def compile_and_run(self, test, sanitized):
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Wconversion",
                 "-Wsign-conversion", "-Wshadow", "-Wstrict-prototypes", "-pedantic",
                 "-I", ROOT / "native"]
        if sanitized:
            flags += ["-O1", "-g", "-fno-omit-frame-pointer",
                      "-fsanitize=address,undefined"]
        else:
            flags += ["-O2"]
        sources = [ROOT / "native" / name for name in (
            "sound_span.c", "sound_span_model.c", "sound_span_unavailable.c",
            "sound_cp_backing.c")]
        if test == "snapshot":
            sources.append(ROOT / "native/sound_snapshot_model.c")
        sources.append(ROOT / "tools" / f"test_sound_{test}.c")
        binary = self.build / f"{test}-{'sanitized' if sanitized else 'strict'}"
        self.run_command([self.compiler, *flags, *sources, "-o", binary])
        result = json.loads(self.run_command([binary]))
        self.assertTrue(result["passed"])
        return result

    def test_numeric_span(self):
        strict = self.compile_and_run("span", False)
        sanitized = self.compile_and_run("span", True)
        self.assertEqual(strict, sanitized)
        self.assertEqual(strict["success_geometries"], 30)

    def test_copied_snapshot_to_numeric_span(self):
        strict = self.compile_and_run("snapshot", False)
        sanitized = self.compile_and_run("snapshot", True)
        self.assertEqual(strict, sanitized)
        self.assertEqual(strict["success_geometries"], 18)
        self.assertTrue(strict["all_u16_counts_and_states"])

    def test_unavailable_provider_has_no_link_dependencies(self):
        nm = shutil.which("nm")
        if nm is None:
            self.skipTest("nm is required to inspect object dependencies")
        for source in ("sound_span_unavailable.c", "sound_cp_backing.c"):
            with self.subTest(source=source):
                stub = self.build / (source + ".o")
                self.run_command([self.compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                  "-O2", "-c", ROOT / "native" / source, "-o", stub])
                self.assertEqual(self.run_command([nm, "-u", stub]).strip(), "")


if __name__ == "__main__":
    unittest.main()
