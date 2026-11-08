"""Exercise the actual pinned bootstrap embedded in both single-file flashers."""
import contextlib
import hashlib
import io
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SHELL = (ROOT / 'mcfirmware.sh').read_text()
WINDOWS = (ROOT / 'firmware.cmd').read_text()
BOOTSTRAP = SHELL.split("<<'PY_STATION_RECOVERY'\n", 1)[1].split('PY_STATION_RECOVERY\n', 1)[0]


class Menus(unittest.TestCase):
    def test_platforms_use_identical_verified_bootstrap(self):
        windows = WINDOWS.split('function Invoke-StationRecovery {', 1)[1]
        windows = windows.split("$bootstrap = @'\n", 1)[1].split("'@\n", 1)[0]
        self.assertEqual(BOOTSTRAP, windows)
        self.assertRegex(BOOTSTRAP, r'SHA256 = "[0-9a-f]{64}"')
        compile(BOOTSTRAP, '<bootstrap>', 'exec')

    def test_recovery_branches_before_normal_probes_and_tool_setup(self):
        self.assertLess(SHELL.index('\nstation_recovery_early_menu "$@"'), SHELL.index('\ninitialize_privilege_mode\n'))
        self.assertLess(WINDOWS.index('\n$operation = Prompt-Menu'), WINDOWS.index('\ncheck_requirements\n'))
        branch = WINDOWS.split('if ($operation.Index -eq 2) {', 1)[1].split('\n}', 1)[0]
        self.assertIn('exit $recoveryStatus', branch)

    def run_bootstrap(self, data, digest, result=0):
        program = re.sub(r'SHA256 = "[0-9a-f]{64}"', 'SHA256 = "' + digest + '"', BOOTSTRAP)
        seen = []
        def backend(command):
            path = Path(command[1])
            self.assertEqual(path.read_bytes(), b'# fixture, never executed\n')
            self.assertEqual(command[2:], ['--guided'])
            seen.append(path)
            return result
        with patch('urllib.request.urlopen', return_value=io.BytesIO(data)), \
                patch('subprocess.call', side_effect=backend) as called, \
                patch.object(sys, 'argv', ['launcher', '--guided']), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                exec(compile(program, '<actual embedded bootstrap>', 'exec'), {})
        for path in seen:
            self.assertFalse(path.exists(), 'Temporary scripts/firmware must be cleaned up')
        return stopped.exception.code, called.call_count

    def archive(self, name='Station-Recovery/tools/station_recovery.py'):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as bundle:
            bundle.writestr(name, b'# fixture, never executed\n')
        return buffer.getvalue()

    def test_failure_status_reaches_parent_and_temp_is_removed(self):
        data = self.archive()
        for status in (0, 1, 2, 7):
            self.assertEqual(self.run_bootstrap(data, hashlib.sha256(data).hexdigest(), status), (status, 1))

    def test_checksum_failure_cannot_execute_recovery(self):
        self.assertEqual(self.run_bootstrap(self.archive(), '0' * 64), (1, 0))

    def test_bad_paths_cannot_execute_recovery(self):
        # On Windows zipfile normalizes backslashes to forward slashes when
        # constructing a ZipInfo; retain the traversal after normalization.
        for name in ('../escape.py', '/escape.py', '..\\escape.py'):
            data = self.archive(name)
            self.assertEqual(self.run_bootstrap(data, hashlib.sha256(data).hexdigest()), (1, 0))


if __name__ == '__main__':
    unittest.main()
