import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class NativeCompilation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        source = Path(__file__).resolve().parents[2]
        for relative in ["scripts/compile_to_native.sh",
                         "scripts/check_if_rustup_target_installed.sh",
                         ".github/scripts/compile_all_targets_java.sh"]:
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            revision = os.environ.get("NATIVE_SCRIPT_REF")
            if revision:
                destination.write_bytes(subprocess.check_output(
                    ["git", "show", f"{revision}:{relative}"], cwd=source))
            else:
                shutil.copyfile(source / relative, destination)
            destination.chmod(0o755)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "rustup").write_text(
            "#!/bin/sh\nprintf '%s\\n' x86_64-unknown-linux-gnu x86_64-pc-windows-gnu\n")
        (self.tools / "cargo").write_text('''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
status = int(os.environ.get("FAKE_BUILD_EXIT", "0"))
if status:
    sys.exit(status)
if os.environ.get("FAKE_MISSING_ARTIFACT"):
    sys.exit(0)
target = next((arg.split("=", 1)[1] for arg in args if arg.startswith("--target=")), None)
if target is None:
    target = args[args.index("--target") + 1]
base_target = target.split(".2.", 1)[0]
directory = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / base_target / "release"
if os.environ.get("FAKE_EXPECT_TARGET"):
    assert target == os.environ["FAKE_EXPECT_TARGET"], target
directory.mkdir(parents=True, exist_ok=True)
for name in ["libjava_verkle_cryptography.so", "java_verkle_cryptography.dll"]:
    (directory / name).write_bytes(b"native artifact")
''')
        for p in self.tools.iterdir():
            p.chmod(0o755)
        self.build = self.root / "build outputs"
        self.output = self.root / "packaged outputs"
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.tools) + os.pathsep + self.env["PATH"],
                        CARGO_TARGET_DIR=str(self.build))

    def native(self, **env):
        return subprocess.run(
            ["bash", str(self.repo / "scripts/compile_to_native.sh"),
             "Linux", "x86_64", "java_verkle_cryptography", "dynamic", str(self.output)],
            env={**self.env, **env}, capture_output=True, text=True)

    def test_build_failure_propagates_without_success_message(self):
        result = self.native(FAKE_BUILD_EXIT="42")
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertNotIn("Build completed", result.stdout)
        self.assertFalse(self.output.exists())

    def test_missing_artifact_is_an_error(self):
        result = self.native(FAKE_MISSING_ARTIFACT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Build completed", result.stdout)

    def test_custom_target_directory_is_packaged(self):
        result = self.native()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        library = self.output / "x86_64-unknown-linux-gnu/libjava_verkle_cryptography.so"
        self.assertEqual(library.read_bytes(), b"native artifact")

    def test_explicit_glibc_floor_uses_cargo_artifact_directory(self):
        result = subprocess.run(
            ["bash", str(self.repo / "scripts/compile_to_native.sh"),
             "Linux", "x86_64", "java_verkle_cryptography", "dynamic", str(self.output), "zigbuild"],
            env={**self.env, "GLIBC_VERSION": "2.17", "FAKE_EXPECT_TARGET": "x86_64-unknown-linux-gnu.2.17"},
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.output / "x86_64-unknown-linux-gnu/libjava_verkle_cryptography.so").is_file())

    def test_repository_path_with_spaces(self):
        relocated = self.root / "repository with spaces"
        self.repo.rename(relocated)
        self.repo = relocated
        result = self.native()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.output / "x86_64-unknown-linux-gnu/libjava_verkle_cryptography.so").is_file())

    def test_java_wrapper_propagates_build_failure(self):
        result = subprocess.run(
            ["bash", str(self.repo / ".github/scripts/compile_all_targets_java.sh"),
             "x86_64-unknown-linux-gnu"],
            env={**self.env, "FAKE_BUILD_EXIT": "42"}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)

    def test_windows_wrapper_packages_dll(self):
        result = subprocess.run(
            ["bash", str(self.repo / ".github/scripts/compile_all_targets_java.sh"),
             "x86_64-pc-windows-gnu"], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        library = self.repo / "bindings/java/java_code/src/main/resources/x86_64-pc-windows-gnu/java_verkle_cryptography.dll"
        self.assertEqual(library.read_bytes(), b"native artifact")


if __name__ == "__main__":
    unittest.main()
