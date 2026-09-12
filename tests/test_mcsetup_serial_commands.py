#!/usr/bin/env python3
"""Exercise mcsetup's real shell functions against a simulated serial radio."""

import os
from pathlib import Path
import pty
import re
import select
import shlex
import shutil
import subprocess
import tempfile
import termios
import threading
import time
import tty
import unittest


SCRIPT = (Path(__file__).resolve().parents[1] / "mcsetup.sh").read_text()
FUNCTION_NAMES = (
    "serial_cmd", "serial_cmd_echo", "serial_cmd_multiline_200ms", "serial_setting_cmd",
    "run_raw_command", "open_picocom_console", "read_usb_logging_setting",
    "setup_has_separate_logging_tty", "prime_serial_baud", "offer_disable_usb_logging",
    "read_hex_key_setting", "trim", "set_empty_settings",
    "edit_repeater_settings_menu", "clean_node_info_field",
    "normalize_firmware_version", "query_companion_device_info",
    "query_companion_full_version", "refresh_detected_node_info",
)
FUNCTIONS = "\n".join(
    match.group(0)
    for name in FUNCTION_NAMES
    if (match := re.search(r"^" + name + r"\(\) \{\n.*?^\}", SCRIPT, re.M | re.S))
)


class Radio:
    def __init__(self, replies=None, delay=0, logs=False, required_baud=None):
        self.master, self.slave = pty.openpty()
        tty.setraw(self.slave)
        self.port = os.ttyname(self.slave)
        self.replies = replies or {}
        self.delay = delay
        self.logs = logs
        self.required_baud = required_baud
        self.commands = []
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.worker.join(timeout=2)
        os.close(self.master)
        os.close(self.slave)

    def serve(self):
        command = bytearray()
        pending = []
        next_log = time.monotonic()
        while not self.stop.is_set():
            readable, _, _ = select.select([self.master], [], [], 0.01)
            if readable:
                for value in os.read(self.master, 4096):
                    if value == 13:
                        line = bytes(command)
                        command.clear()
                        self.commands.append(line)
                        if self.required_baud is not None and termios.tcgetattr(self.slave)[4] != self.required_baud:
                            continue
                        # Firmware echoes the input, then prefixes its reply.
                        os.write(self.master, line + b"\r\n")
                        reply = self.replies.get(line, b"Unknown command")
                        if reply is not None:
                            pending.append((time.monotonic() + self.delay, reply))
                    elif value != 10:
                        command.append(value)
            now = time.monotonic()
            for deadline, reply in pending[:]:
                if deadline <= now:
                    os.write(self.master, b"  -> " + reply + b"\r\n")
                    pending.remove((deadline, reply))
            if self.logs and now >= next_log:
                os.write(self.master, b"INFO: Dispatcher::recv payload_len=16 RSSI=-80\r\n")
                next_log = now + 0.03


class CompanionRadio(Radio):
    def serve(self):
        buffer = bytearray()
        while not self.stop.is_set():
            readable, _, _ = select.select([self.master], [], [], 0.01)
            if not readable:
                continue
            buffer.extend(os.read(self.master, 4096))
            while buffer:
                # Companion's idle state ignores bytes other than '<'.
                if buffer[0] != 60:
                    del buffer[0]
                    continue
                if len(buffer) < 3:
                    break
                end = 3 + int.from_bytes(buffer[1:3], "little")
                if len(buffer) < end:
                    break
                command = bytes(buffer[3:end])
                del buffer[:end]
                self.commands.append(command)
                if command == b"\x16\x0e":
                    reply = bytearray(80)
                    reply[:2] = b"\x0d\x0e"
                    reply[20:60] = b"Heltec V4.3 OLED".ljust(40, b"\0")
                    reply[60:80] = b"v1.17.1.6-halo-keym".ljust(20, b"\0")
                elif command == b"Bversion":
                    reply = b"\x1dCompanion v1.17.1.6-halo-keymind-cascade-dev-14796e65 (protocol 14)"
                else:
                    reply = b"\x01"
                os.write(self.master, b">" + len(reply).to_bytes(2, "little") + reply)


@unittest.skipUnless(shutil.which("socat") and shutil.which("perl"), "needs socat and perl")
class SerialCommandsTest(unittest.TestCase):
    def run_shell(self, radio, body, menu_input="", options=""):
        # Extract functions instead of sourcing the install/system setup code.
        harness = "set -euo pipefail\n" + FUNCTIONS + "\n" + r"""
ensure_serial_access() { :; }
ensure_command() { command -v "$1" >/dev/null; }
print_detected_node_summary() { :; }
DEVICE_NAME=$1
BAUD=115200
SERIAL_BAUD_CACHE=57600
DEFAULT_BAUDS=(57600 115200 38400)
SERIAL_IDLE_TIMEOUT=0.1
SERIAL_TOTAL_TIMEOUT=0.35s
SERIAL_RETRY_DELAY=0
MCSETUP_INFO_IDLE_TIMEOUT=0.1
MCSETUP_INFO_TOTAL_TIMEOUT=0.35s
""" + options + "\n" + body
        result = subprocess.run(
            ["bash", "-c", harness, "mcsetup-test", radio.port],
            input=menu_input, text=True, capture_output=True, timeout=12,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_raw_menu_sends_even_when_clock_was_unreadable(self):
        with Radio({b"get tx": b"15"}) as radio:
            output = self.run_shell(
                radio, "set_empty_settings; device_epoch=; edit_repeater_settings_menu",
                "0\nget tx\nq\n",
            )
            self.assertEqual(radio.commands, [b"get tx"])
            self.assertIn("\n15\n", output)
            self.assertNotIn("printf '%b'", output)

    def test_picocom_menu_uses_detected_baud_and_explains_exit(self):
        with Radio() as radio:
            output = self.run_shell(
                radio,
                """
ensure_command() { printf 'ENSURE_COMMAND:%s\\n' "$1"; }
picocom() { printf 'PICOCOM_ARGS:'; printf ' <%s>' "$@"; printf '\\n'; }
set_empty_settings
device_epoch=
SERIAL_BAUD_CACHE=57600
edit_repeater_settings_menu
""",
                "p\nq\n",
            )
            self.assertIn("P) Picocom serial console (exit: Ctrl-A, then Ctrl-X)", output)
            self.assertIn("To exit: press Ctrl-A, release it, then press Ctrl-X.", output)
            self.assertIn("Ctrl-C is sent to the radio and does not exit picocom.", output)
            self.assertIn("ENSURE_COMMAND:picocom", output)
            self.assertIn(f"PICOCOM_ARGS: <--baud> <57600> <--flow> <n> <--noreset> <{radio.port}>", output)
            self.assertLess(output.index("ENSURE_COMMAND:picocom"), output.index("PICOCOM_ARGS:"))
            self.assertIn("Returned to setup.", output)

    def test_enabled_usb_logging_can_be_disabled_with_one_rebooting_write(self):
        replies = {
            b"get usb.logging": b"on",
            b"board": b"Station G2",
            b"set usb.logging off reboot": None,
        }
        with Radio(replies) as radio:
            output = self.run_shell(
                radio,
                "status=0; offer_disable_usb_logging || status=$?; echo STATUS:$status",
                "y\n",
            )
            self.assertEqual(radio.commands, [
                b"get usb.logging", b"set usb.logging off reboot",
            ])
            self.assertIn("USB logging is enabled", output)
            self.assertIn("Sending: set usb.logging off reboot", output)
            self.assertIn("STATUS:2", output)

    def test_disabled_usb_logging_needs_no_prompt_or_write(self):
        with Radio({b"get usb.logging": b"off"}, required_baud=termios.B57600) as radio:
            output = self.run_shell(
                radio,
                "status=0; offer_disable_usb_logging || status=$?; "
                "echo STATUS:$status BAUD:$SERIAL_BAUD_CACHE PROFILE:$SERIAL_SETTINGS_PROFILE",
                options='SERIAL_BAUD_CACHE=""',
            )
            self.assertEqual(radio.commands, [b"get usb.logging", b"get usb.logging"])
            self.assertNotIn("Turn off USB logging", output)
            self.assertIn("STATUS:0 BAUD:57600 PROFILE:fast", output)

    def test_separate_logging_tty_enables_fast_reads_without_disable_prompt(self):
        with Radio({b"get usb.logging": b"on"}) as radio:
            output = self.run_shell(
                radio,
                "setup_has_separate_logging_tty() { return 0; }; "
                "offer_disable_usb_logging; echo PROFILE:$SERIAL_SETTINGS_PROFILE",
            )
            self.assertEqual(radio.commands, [b"get usb.logging"])
            self.assertIn("USB logging has a separate tty", output)
            self.assertNotIn("Turn off USB logging", output)
            self.assertIn("PROFILE:fast", output)

    def test_interface_02_sibling_is_detected_as_separate_logging_tty(self):
        with tempfile.TemporaryDirectory() as directory, Radio() as radio:
            by_id = Path(directory)
            primary = by_id / "usb-RAK4631_TEST-if00"
            logging = by_id / "usb-RAK4631_TEST-if02"
            primary.touch()
            logging.touch()
            output = self.run_shell(
                radio,
                "setup_has_separate_logging_tty && echo SEPARATE",
                options=(
                    f"MCSETUP_SERIAL_BY_ID_DIR={shlex.quote(directory)}; "
                    f"SETUP_USB_SELECTED_LINK={shlex.quote(str(primary))}"
                ),
            )
            self.assertEqual(output.strip(), "SEPARATE")

    def test_settings_profiles_use_only_the_verified_baud(self):
        with Radio() as radio:
            output = self.run_shell(
                radio,
                """
serial_cmd() {
    printf 'PROFILE:%s RETRIES:%s FIRST:%s IDLE:%s TOTAL:%s\\n' \
        "$SERIAL_SETTINGS_PROFILE" "$SERIAL_RETRIES" \
        "$SERIAL_FIRST_CANDIDATE_ONLY" "$SERIAL_IDLE_TIMEOUT" "$SERIAL_TOTAL_TIMEOUT"
}
SERIAL_SETTINGS_PROFILE=fast
serial_setting_cmd 'get dutycycle'
SERIAL_SETTINGS_PROFILE=known-noisy
serial_setting_cmd 'get dutycycle'
""",
            )
            self.assertIn("PROFILE:fast RETRIES:1 FIRST:1 IDLE:0.2 TOTAL:0.5s", output)
            self.assertIn("PROFILE:known-noisy RETRIES:1 FIRST:1 IDLE:0.35 TOTAL:2s", output)

    def test_quiet_setting_read_finishes_on_short_idle_timeout(self):
        with Radio({b"get dutycycle": b"100"}) as radio:
            start = time.monotonic()
            output = self.run_shell(
                radio,
                "SERIAL_SETTINGS_PROFILE=fast; "
                "SERIAL_RESPONSE_REGEX='^[0-9]+$' serial_setting_cmd 'get dutycycle'",
            )
            self.assertLess(time.monotonic() - start, 1.0)
            self.assertEqual(radio.commands, [b"get dutycycle"])
            self.assertEqual(output.strip(), "100")

    def test_noisy_setting_read_is_capped_without_baud_retries(self):
        with Radio({b"get dutycycle": b"100"}, logs=True) as radio:
            start = time.monotonic()
            output = self.run_shell(
                radio,
                "SERIAL_SETTINGS_PROFILE=known-noisy; "
                "SERIAL_RESPONSE_REGEX='^[0-9]+$' serial_setting_cmd 'get dutycycle'",
            )
            self.assertLess(time.monotonic() - start, 3.0)
            self.assertEqual(radio.commands, [b"get dutycycle"])
            self.assertEqual(output.strip(), "100")

    def test_command_can_be_entered_at_choice(self):
        command = b"tempradio 910.1,500,7,5,180"
        with Radio({command: b"OK - temp params for 180 mins"}) as radio:
            output = self.run_shell(
                radio, "set_empty_settings; device_epoch=; edit_repeater_settings_menu",
                command.decode() + "\nq\n",
            )
            self.assertEqual(radio.commands, [command])
            self.assertIn("OK - temp params for 180 mins", output)

    def test_delayed_reply_is_not_cut_off_by_stdin_eof(self):
        command = b"tempradio 910.1,500,7,5,180"
        with Radio({command: b"OK - temp params for 180 mins"}, delay=0.65) as radio:
            output = self.run_shell(
                radio, "run_raw_command " + shlex.quote(command.decode()),
                options="SERIAL_IDLE_TIMEOUT=1.1; SERIAL_TOTAL_TIMEOUT=1.8s",
            )
            self.assertIn("OK - temp params for 180 mins", output)
            self.assertEqual(radio.commands, [command])

    def test_continuous_logs_do_not_discard_multiline_reply_at_timeout(self):
        reply = b"1: 910.100,500,7,5,2000000000,2000010800\r\n2: scheduled"
        with Radio({b"get tempradioat": reply}, logs=True) as radio:
            start = time.monotonic()
            output = self.run_shell(radio, "run_raw_command 'get tempradioat'")
            self.assertGreaterEqual(time.monotonic() - start, 0.3)
            self.assertIn(reply.decode().replace("\r", ""), output)
            self.assertNotIn("Dispatcher", output)
            self.assertEqual(radio.commands, [b"get tempradioat"])

    def test_firmware_errors_are_visible(self):
        for reply in (b"ERR: queue full", b"Error, invalid params", b"(ERR: clock cannot go backwards)"):
            with self.subTest(reply=reply), Radio({b"set tempradioat bad": reply}) as radio:
                output = self.run_shell(radio, "run_raw_command 'set tempradioat bad'")
                self.assertIn(reply.decode(), output)
                self.assertEqual(radio.commands, [b"set tempradioat bad"])

    def test_no_reply_does_not_repeat_a_command_at_other_bauds(self):
        command = b"set tempradioat 910.1,500,7,5,2000000000,2000010800"
        with Radio({command: None}, logs=True) as radio:
            output = self.run_shell(radio, "run_raw_command " + shlex.quote(command.decode()))
            self.assertEqual(radio.commands, [command])
            self.assertIn("No reply", output)

    def test_command_backslashes_are_sent_literally(self):
        command = br"set name O'Brien\rget tx"
        with Radio({command: b"OK"}) as radio:
            output = self.run_shell(radio, "run_raw_command " + shlex.quote(command.decode()))
            self.assertEqual(radio.commands, [command])
            self.assertIn("\nOK\n", output)

    def test_baud_discovery_uses_reads_before_sending_one_write(self):
        command = b"tempradio 910.1,500,7,5,180"
        replies = {b"board": b"RAK 4631", command: b"OK - temp params for 180 mins"}
        with Radio(replies, required_baud=termios.B57600) as radio:
            output = self.run_shell(
                radio, "run_raw_command " + shlex.quote(command.decode()),
                options='SERIAL_BAUD_CACHE=""',
            )
            self.assertEqual(radio.commands, [b"board", b"board", command])
            self.assertIn("OK - temp params for 180 mins", output)

    def test_missing_port_reports_transport_failure_without_exiting_menu(self):
        with Radio() as radio:
            output = self.run_shell(
                radio, "DEVICE_NAME=/dev/mcsetup-test-missing; run_raw_command 'get tx'; echo still-running",
            )
            self.assertEqual(radio.commands, [])
            self.assertIn("Serial command failed", output)
            self.assertIn("still-running", output)

    def test_binary_probe_does_not_corrupt_following_board_command(self):
        with Radio({b"board": b"Heltec V4", b"ver": b"v1.16.01-halo-keymind-dev-ebd7da79"}) as radio:
            output = self.run_shell(radio, "refresh_detected_node_info; printf '%s\\n' \"$DETECTED_NODE_BOARD\" \"$DETECTED_NODE_VERSION\"")
            self.assertEqual(output.splitlines(), ["Heltec V4", "v1.16.01-halo-keymind-dev-ebd7da79"])
            self.assertIn(b"board", radio.commands)

    def test_companion_identity_still_uses_valid_binary_frames(self):
        with CompanionRadio() as radio:
            output = self.run_shell(radio, "refresh_detected_node_info; printf '%s\\n' \"$DETECTED_NODE_BOARD\" \"$DETECTED_NODE_VERSION\"")
            self.assertEqual(output.splitlines(), [
                "Heltec V4.3 OLED", "v1.17.1.6-halo-keymind-cascade-dev-14796e65",
            ])
            self.assertEqual(radio.commands, [b"\x16\x0e", b"Bversion"])

    def test_key_extraction_still_handles_debug_on_the_same_line(self):
        key = b"ABCDEF0123456789" * 4
        with Radio({b"get public.key": key + b" INFO: Dispatcher::recv"}) as radio:
            output = self.run_shell(radio, "read_hex_key_setting public.key 64")
            self.assertEqual(output.strip(), key.decode())


if __name__ == "__main__":
    unittest.main()
