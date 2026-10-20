import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "check_python_binding_environment",
    Path(__file__).resolve().parents[1] / "check_python_binding.py",
)
BINDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BINDING)


class PythonBindingEnvironmentTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(directory.name)
        self.output = self.root / "target/python-binding"
        self.stale = self.output / (
            f"python-{sys.version_info.major}.{sys.version_info.minor}"
        )
        self.stale.mkdir(parents=True)
        (self.stale / "incomplete-install").write_text("cached", encoding="utf-8")
        self.environments = []
        self.commands = []
        self.failure = None
        self.stack.enter_context(
            patch.object(
                BINDING,
                "ROOT",
                self.root,
            )
        )
        self.stack.enter_context(patch.object(BINDING.os, "chdir"))
        builder = self.stack.enter_context(patch.object(BINDING.venv, "EnvBuilder"))
        builder.return_value.create.side_effect = self.create_environment
        self.builder = builder
        self.stack.enter_context(
            patch.object(BINDING, "run", side_effect=self.run_command)
        )

    def create_environment(self, environment):
        environment = Path(environment)
        self.environments.append(environment)
        self.assertFalse(environment.is_relative_to(self.output))
        self.assertFalse(environment.exists())
        environment.mkdir(parents=True)
        if self.failure == "venv":
            raise RuntimeError("venv failed")

    def run_command(self, *command):
        self.commands.append(command)
        environment = self.environments[-1]
        self.assertTrue(environment.is_dir())
        python = environment / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        self.assertEqual(command[0], str(python))
        if "maturin" in command:
            wheels = Path(command[command.index("--out") + 1])
            self.assertEqual(wheels.parent, self.output)
            self.assertTrue(wheels.is_dir())
            self.assertEqual(command[command.index("--interpreter") + 1], str(python))
            (wheels / "phantom.whl").write_bytes(b"wheel fixture")
            stage = "build"
        elif "unittest" in command:
            stage = "tests"
        elif "--force-reinstall" in command:
            stage = "wheel-install"
        else:
            stage = "dependencies"
        if stage == self.failure:
            raise subprocess.CalledProcessError(73, command)

    def test_each_run_uses_a_fresh_environment_and_retains_its_wheel(self):
        BINDING.check_development()
        BINDING.check_development()
        self.builder.assert_called_with(with_pip=True)
        self.assertEqual(len(self.environments), 2)
        self.assertNotEqual(*self.environments)
        self.assertTrue(all(not path.parent.exists() for path in self.environments))
        self.assertEqual(len(list(self.output.glob("wheels-*/*.whl"))), 2)
        self.assertEqual(
            (self.stale / "incomplete-install").read_text(encoding="utf-8"), "cached"
        )
        self.assertEqual(len(self.commands), 8)
        for offset in (0, 4):
            self.assertEqual(self.commands[offset][1:4], ("-m", "pip", "install"))
            self.assertIn("maturin==1.15.0", self.commands[offset])
            self.assertIn("--locked", self.commands[offset + 1])
            self.assertIn("--no-deps", self.commands[offset + 2])
            self.assertEqual(
                self.commands[offset + 3][1:],
                ("-m", "unittest", "discover", "-s", "bindings/python/tests", "-v"),
            )

    def test_failures_propagate_and_remove_only_the_temporary_environment(self):
        stages = ("venv", "dependencies", "build", "wheel-install", "tests")
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage):
                self.failure = stage
                self.commands.clear()
                expected = (
                    RuntimeError if stage == "venv" else subprocess.CalledProcessError
                )
                with self.assertRaises(expected) as caught:
                    BINDING.check_development()
                if stage != "venv":
                    self.assertEqual(caught.exception.returncode, 73)
                self.assertFalse(self.environments[-1].parent.exists())
                self.assertTrue((self.stale / "incomplete-install").exists())
                self.assertEqual(len(self.commands), index)

    def test_a_first_run_creates_the_wheel_output_directory(self):
        fresh = self.root / "fresh"
        self.output = fresh / "target/python-binding"
        with patch.object(BINDING, "ROOT", fresh):
            BINDING.check_development()
        self.assertEqual(len(list(self.output.glob("wheels-*/*.whl"))), 1)
        self.assertFalse(self.environments[-1].parent.exists())


if __name__ == "__main__":
    unittest.main()
