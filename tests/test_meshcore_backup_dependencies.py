"""Dependency diagnostics/repair tests: no USB access or package installation."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "meshcore_backup.py"
SPEC = importlib.util.spec_from_file_location("meshcore_backup_dependencies", MODULE_PATH)
backup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = backup
SPEC.loader.exec_module(backup)


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.versions = {name: pin for name, _, _, pin in backup.DEPENDENCIES}
        self.version_mock = mock.patch.object(backup, "_package_version", side_effect=self.versions.get)
        self.api_mock = mock.patch.object(backup, "_check_dependency_api")
        self.version_mock.start()
        self.check_api = self.api_mock.start()
        self.probe_mock = mock.patch.object(backup, "_probe_dependency_report", side_effect=backup.dependency_report)
        self.probe_mock.start()
        self.addCleanup(self.version_mock.stop)
        self.addCleanup(self.api_mock.stop)
        self.addCleanup(self.probe_mock.stop)

    def test_four_component_version_and_cli_report(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(backup.subprocess, "run") as run:
            self.assertEqual(backup.main(["dependencies", "--install"]), 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["ok"])
        self.assertEqual(report["executable"], sys.executable)
        self.assertEqual(report["packages"][0]["installed"], "2.3.9.1")
        self.assertEqual(report["packages"][0]["supported"], ">=2.3.9,<3.0.0")
        self.assertEqual(self.check_api.call_count, 3)
        run.assert_not_called()

    def test_missing_old_future_and_prerelease_versions(self):
        for version in (None, "2.3.8.9", "3.0.0", "2.3.9rc1", "2.3.9.dev1", "invalid"):
            with self.subTest(version=version):
                self.versions["meshcore"] = version
                report = backup.dependency_report()
                self.assertFalse(report["ok"])
                item = report["packages"][0]
                self.assertFalse(item["version_ok"])
                self.assertIn(version or "not installed", item["error"])
                self.assertIn(">=2.3.9,<3.0.0", item["error"])

    def test_stable_versions_within_range_are_reused(self):
        for version in ("2.3.9", "2.3.9.1", "2.4", "2.3.9.post1", "2.3.9+local"):
            with self.subTest(version=version):
                self.versions["meshcore"] = version
                self.assertTrue(backup.dependency_report()["ok"])

    def test_text_reports_all_installed_supported_and_repair_versions(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(backup.main(["dependencies", "--text"]), 0)
        for name, version in self.versions.items():
            self.assertIn(f"{name}: installed {version}; supported >=", output.getvalue())
            self.assertIn(f"repair {version} -- API OK", output.getvalue())

    def test_check_only_does_not_install(self):
        self.versions["meshcore-cli"] = None
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(backup.subprocess, "run") as run:
            self.assertEqual(backup.main(["dependencies"]), 10)
        run.assert_not_called()

    def test_missing_or_incompatible_repairs_exact_set_then_fresh_probe(self):
        for version in (None, "1.0", "3.0.0"):
            with self.subTest(version=version):
                self.versions["meshcore"] = version
                results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0)]
                with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(
                    backup.subprocess, "run", side_effect=results
                ) as run:
                    self.assertEqual(backup.ensure_dependencies(install=True, text=True), 0)
                self.assertEqual(run.call_count, 2)
                pip_command = run.call_args_list[0].args[0]
                self.assertEqual(pip_command[:4], [sys.executable, "-m", "pip", "install"])
                self.assertEqual(pip_command[-3:], [
                    "meshcore==2.3.9.1", "meshcore-cli==1.6.3", "PyNaCl==1.6.2"
                ])
                self.assertNotIn("--force-reinstall", pip_command)
                self.assertEqual(run.call_args_list[1].args[0], [
                    sys.executable, str(MODULE_PATH), "dependencies", "--text"
                ])

    def test_broken_api_forces_reinstall_not_false_version_error(self):
        self.check_api.side_effect = backup.BackupError(backup.ExitCode.DEPENDENCY, "API missing (ImportError)")
        with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(
            backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
        ) as run:
            self.assertEqual(backup.ensure_dependencies(install=True), 0)
        self.assertIn("--force-reinstall", run.call_args_list[0].args[0])

    def test_pip_failure_is_visible_and_stops_repair(self):
        self.versions["meshcore"] = None
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()), mock.patch.object(
            backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)
        ) as run:
            self.assertEqual(backup.ensure_dependencies(install=True), 10)
        self.assertEqual(run.call_count, 1)
        report = json.loads(output.getvalue())
        self.assertIn("pip exit 7", report["error"])
        self.assertEqual(report["packages"][1]["installed"], "1.6.3")

    def test_repaired_but_still_invalid_stops_without_repair_loop(self):
        self.versions["meshcore"] = None
        with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(backup.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 10)
        ]) as run:
            self.assertEqual(backup.ensure_dependencies(install=True), 10)
        self.assertEqual(run.call_count, 2)
        self.assertNotIn("--install", run.call_args_list[1].args[0])


class ApiInspectionTests(unittest.TestCase):
    def test_repair_probe_imports_apis_only_in_a_separate_process(self):
        expected = {"ok": False, "exit_code": 10, "packages": [{"name": "meshcore", "installed": None}]}
        with mock.patch.object(backup, "dependency_report") as local_report, mock.patch.object(
            backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 10, json.dumps(expected))
        ) as run:
            self.assertEqual(backup._probe_dependency_report(), expected)
        local_report.assert_not_called()
        self.assertEqual(run.call_args.args[0], [sys.executable, str(MODULE_PATH), "dependencies"])
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_probe_failure_cannot_be_treated_as_a_version_mismatch(self):
        with mock.patch.object(backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "")), self.assertRaises(
            backup.BackupError
        ) as caught:
            backup._probe_dependency_report()
        self.assertIn("could not produce a version/API report", caught.exception.reason)

    def test_api_inspection_never_calls_transport_or_key_functions(self):
        module = mock.Mock()
        with mock.patch.object(backup.importlib, "import_module", return_value=module):
            for name in backup.DEPENDENCY_APIS:
                backup._check_dependency_api(name)
        self.assertEqual(module.mock_calls, [])

    def test_import_failure_does_not_leak_configuration_or_claim_version_mismatch(self):
        def broken_import(_):
            print("SECRET import log")
            print("SECRET error log", file=sys.stderr)
            raise ImportError("SECRET configuration value")

        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), mock.patch.object(
            backup.importlib, "import_module", side_effect=broken_import
        ), self.assertRaises(backup.BackupError) as caught:
            backup._check_dependency_api("meshcore")
        self.assertIn("MeshCore.create_serial unavailable (ImportError)", caught.exception.reason)
        self.assertNotIn("SECRET", caught.exception.reason + output.getvalue() + errors.getvalue())

    def test_missing_callable_is_api_failure(self):
        with mock.patch.object(backup.importlib, "import_module", return_value=object()), self.assertRaises(
            backup.BackupError
        ) as caught:
            backup._check_dependency_api("meshcore-cli")
        self.assertIn("setup_repeater_serial unavailable (AttributeError)", caught.exception.reason)


if __name__ == "__main__":
    unittest.main()
