import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts.capture.android_device import ANDROID_BROWSERS, AndroidLaunch
from scripts.capture.browser_launch import BrowserLaunchFailures
from scripts.capture.tests.test_android_device_lifecycle import (
    CONFIGURATION,
    REMOVE_FILE,
    URL,
    ObservedSession,
    OfflineDevice,
    failure_from,
)


class ConfigurationDevice(OfflineDevice):
    def __init__(self) -> None:
        super().__init__()
        self.post_push_failure: BaseException | None = None
        self.configuration_failures: list[BaseException] = []
        self.published_before_failure: dict[str, bytes] | None = None

    def run(self, *arguments: str, check: bool = True) -> str:
        result = super().run(*arguments, check=check)
        if arguments[0] == "push" and self.post_push_failure is not None:
            original = self.post_push_failure
            self.post_push_failure = None
            self.published_before_failure = dict(self.files)
            self.raised.append(original)
            self.configuration_failures.append(original)
            raise original
        return result


class ConfigurationBackupFailures(Exception):
    def __init__(self, failures: tuple[BaseException, ...]) -> None:
        self.failures = failures
        super().__init__("configuration control backup failed")


class ConfigurationResources:
    def __init__(self) -> None:
        self.device = ConfigurationDevice()
        self.materials: list[tempfile.TemporaryDirectory] = []
        self.prepared: list[tuple[Path, bytes]] = []
        self.cleaned_before_fault: list[tuple[Path, bool]] = []
        self.actual_init = tempfile.TemporaryDirectory.__init__
        self.actual_cleanup = tempfile.TemporaryDirectory.cleanup
        self.actual_write = Path.write_bytes
        self.preparation_failure: BaseException | None = None
        self.cleanup_failure: BaseException | None = None
        self.backup_started = False

    @contextmanager
    def observe(self):
        def initialize(material, *arguments, **options):
            self.actual_init(material, *arguments, **options)
            self.materials.append(material)

        def write(local: Path, payload: bytes) -> int:
            result = self.actual_write(local, payload)
            if self.materials and local.parent == Path(self.materials[-1].name):
                self.prepared.append((local, local.read_bytes()))
                if self.preparation_failure is not None:
                    original = self.preparation_failure
                    self.preparation_failure = None
                    self.device.configuration_failures.append(original)
                    raise original
            return result

        def cleanup(material) -> None:
            self.actual_cleanup(material)
            if self.cleanup_failure is not None:
                original = self.cleanup_failure
                self.cleanup_failure = None
                directory = Path(material.name)
                self.cleaned_before_fault.append((directory, not directory.exists()))
                self.device.configuration_failures.append(original)
                raise original

        with ExitStack() as observations:
            observations.enter_context(
                patch.object(tempfile.TemporaryDirectory, "__init__", new=initialize)
            )
            observations.enter_context(patch.object(Path, "write_bytes", new=write))
            observations.enter_context(
                patch.object(tempfile.TemporaryDirectory, "cleanup", new=cleanup)
            )
            yield

    def backup(self) -> None:
        self.backup_started = True
        failures = []
        for material in self.materials:
            try:
                self.actual_cleanup(material)
            except BaseException as failure:
                failures.append(failure)

        try:
            self.device.backup()
        except BaseException as failure:
            failures.append(failure)

        if failures:
            raise ConfigurationBackupFailures(tuple(failures))


class AndroidConfigurationLifecycleTests(unittest.TestCase):
    def resources(self) -> ConfigurationResources:
        resources = ConfigurationResources()
        self.addCleanup(resources.backup)
        return resources

    def session(self, resources: ConfigurationResources) -> ObservedSession:
        launch = AndroidLaunch(
            ANDROID_BROWSERS["chrome-android"],
            URL,
            ("--disable-fre",),
            entry="intent",
            settle=0,
            typing_attempts=1,
        )
        return ObservedSession(resources.device, launch)

    def assert_local_material_removed(self, resources: ConfigurationResources) -> None:
        self.assertFalse(resources.backup_started)
        self.assertFalse(resources.device.backup_started)
        self.assertEqual(len(resources.materials), 1)
        self.assertEqual(len(resources.prepared), 1)
        local, payload = resources.prepared[0]
        self.assertEqual(payload, b"_ --disable-fre\n")
        self.assertEqual(local.parent, Path(resources.materials[0].name))
        self.assertFalse(local.exists())
        self.assertFalse(local.parent.exists())

    def test_local_preparation_failure_preserves_existing_remote_configuration(
        self,
    ) -> None:
        resources = self.resources()
        device = resources.device
        existing = b"retained configuration before this capture\n"
        device.files[CONFIGURATION] = existing
        original = OSError("controlled post-write preparation failure")
        resources.preparation_failure = original
        session = self.session(resources)

        with resources.observe():
            failure = failure_from(session.__enter__)

        self.assert_local_material_removed(resources)
        self.assertIs(session.original_entry_failure, original)
        self.assertIs(failure, original)
        self.assertEqual(len(device.configuration_failures), 1)
        self.assertIs(device.configuration_failures[0], original)
        self.assertEqual(device.pushes, [])
        self.assertEqual(device.files, {CONFIGURATION: existing})
        self.assertNotIn(REMOVE_FILE, device.commands)

    def test_published_configuration_is_removed_after_local_cleanup_failure(
        self,
    ) -> None:
        resources = self.resources()
        device = resources.device
        original = OSError("controlled post-cleanup failure")
        resources.cleanup_failure = original
        session = self.session(resources)

        with resources.observe():
            failure = failure_from(session.__enter__)

        self.assert_local_material_removed(resources)
        self.assertEqual(
            resources.cleaned_before_fault, [(Path(resources.materials[0].name), True)]
        )
        self.assertEqual(len(device.pushes), 1)
        local, remote, payload = device.pushes[0]
        self.assertEqual(local, resources.prepared[0][0])
        self.assertEqual((remote, payload), (CONFIGURATION, b"_ --disable-fre\n"))
        self.assertEqual(len(device.configuration_failures), 1)
        self.assertIs(device.configuration_failures[0], original)
        self.assertIs(session.original_entry_failure, original)
        self.assertIs(failure, original)
        self.assertNotIn(CONFIGURATION, device.files)
        self.assertIn(REMOVE_FILE, device.commands)

    def test_push_primary_and_local_cleanup_failure_keep_original_objects(
        self,
    ) -> None:
        resources = self.resources()
        device = resources.device
        primary = OSError("controlled post-publication push failure")
        secondary = OSError("controlled post-cleanup failure")
        previous = RuntimeError("pre-existing push cause")
        primary.__cause__ = previous
        device.post_push_failure = primary
        resources.cleanup_failure = secondary
        session = self.session(resources)

        with resources.observe():
            failure = failure_from(session.__enter__)

        self.assert_local_material_removed(resources)
        self.assertEqual(
            resources.cleaned_before_fault, [(Path(resources.materials[0].name), True)]
        )
        self.assertEqual(
            device.published_before_failure, {CONFIGURATION: b"_ --disable-fre\n"}
        )
        self.assertEqual(len(device.pushes), 1)
        self.assertEqual(len(device.raised), 1)
        self.assertIs(device.raised[0], primary)
        self.assertEqual(len(device.configuration_failures), 2)
        self.assertIs(device.configuration_failures[0], primary)
        self.assertIs(device.configuration_failures[1], secondary)
        self.assertIs(primary.__cause__, previous)
        self.assertIs(getattr(failure, "primary", None), primary)
        self.assertIsInstance(failure, BrowserLaunchFailures)
        self.assertEqual(len(failure.cleanup), 1)
        self.assertIs(failure.cleanup[0], secondary)
        self.assertIs(failure.previous_cause, previous)
        self.assertNotIn(CONFIGURATION, device.files)
        self.assertIn(REMOVE_FILE, device.commands)
