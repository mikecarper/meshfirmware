import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import meshcore_restore as restore


def event(kind, payload):
    return SimpleNamespace(type=SimpleNamespace(value=kind), payload=payload)


class Commands:
    def __init__(self, *, key="new", model="OtherBoard", channels=2, contacts=10):
        self.key = key
        self.model = model
        self.channels = channels
        self.contacts = contacts
        self.writes = 0

    async def send_appstart(self):
        return event("self_info", {"public_key": self.key, "adv_type": 1})

    async def send_device_query(self):
        return event("device_info", {"model": self.model, "ver": "test",
                                     "max_channels": self.channels, "max_contacts": self.contacts})

    async def import_private_key(self, key):
        self.writes += 1
        return event("command_ok", {})


def archive():
    return {
        "source": {"node": {"public_key": "old", "role": "companion"}},
        "sections": {
            "device_info": {"data": {"model": "OriginalBoard"}},
            "channels": {"data": [
                {"channel_idx": 0, "channel_name": "used"},
                {"channel_idx": 1, "channel_name": "used"},
                {"channel_idx": 2, "channel_name": ""},
            ]},
            "contacts": {"data": {"one": {}}},
            "identity_private_key": {"data": {"private_key": "00" * 64}},
        },
    }


class RestoreSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_different_model_needs_new_hardware_choice(self):
        commands = Commands()
        client = SimpleNamespace(commands=commands)
        with self.assertRaisesRegex(restore.RestoreError, "model differs"):
            await restore.inspect(client, archive())
        result = await restore.inspect(client, archive(), new_hardware=True)
        self.assertEqual(result["channel_capacity"], 2)

    async def test_populated_channel_must_fit_new_target(self):
        data = archive()
        data["sections"]["channels"]["data"][2]["channel_name"] = "required"
        client = SimpleNamespace(commands=Commands())
        with self.assertRaisesRegex(restore.RestoreError, "too few channel slots"):
            await restore.inspect(client, data, new_hardware=True)

    async def test_identity_replacement_requires_explicit_choice(self):
        commands = Commands()
        client = SimpleNamespace(commands=commands)
        with self.assertRaisesRegex(restore.RestoreError, "explicit identity replacement"):
            await restore.apply(client, archive(), new_hardware=True)
        self.assertEqual(commands.writes, 0)

    async def test_different_serial_requires_new_hardware_choice(self):
        args = SimpleNamespace(command="probe", input="unused", target_serial="NEW",
                               new_hardware=False, confirmed=False, replace_identity=False)
        with mock.patch.object(restore, "load_backup", return_value=(archive(), {"sha256": "x"}, "OLD")):
            with mock.patch.object(restore, "matching_port") as port:
                with self.assertRaisesRegex(restore.RestoreError, "requires --new-hardware"):
                    await restore.run(args)
                port.assert_not_called()

    def test_bluetooth_default_is_metadata_not_literal_name(self):
        name, mode = restore.bluetooth_name_status("> MeshCore-example (default from node name)")
        self.assertEqual(name, "MeshCore-example")
        self.assertEqual(mode, "default from node name")
        self.assertEqual(restore.bluetooth_name_status("> Custom (custom)"), ("Custom", "custom"))
        with self.assertRaises(restore.RestoreError):
            restore.bluetooth_name_status("> malformed")
        self.assertEqual(
            restore.archived_bluetooth_name({"data": {"name": "MeshCore-new", "default": True}}),
            ("MeshCore-new", "default from node name"),
        )

    def test_archived_usb_logging_state(self):
        data = archive()
        data["sections"]["usb_logging"] = {
            "state": "complete", "data": {"text": "usb.logging off; port: primary USB serial port"}
        }
        self.assertEqual(restore.archived_usb_logging(data), "off")

    def test_radio_cad_status_parses_auto_and_explicit_timings(self):
        self.assertEqual(
            restore.radio_cad_status("radio.cad on, scan=auto(100) ms, retry=auto ms, max=auto ms"),
            ("on", "auto", "auto", "auto"),
        )
        self.assertEqual(
            restore.radio_cad_status("radio.cad off, scan=20 ms, retry=5 ms, max=80 ms"),
            ("off", "20", "5", "80"),
        )

    def test_terminal_mode_switch_disables_logging_before_binary(self):
        serial_port = mock.MagicMock()
        serial_port.__enter__.return_value = serial_port
        replies = ["terminal", "usb.logging on; port: primary", "OK - USB logging off (saved)", "OK - Binary mode"]
        with mock.patch("serial.Serial", return_value=serial_port):
            with mock.patch.object(restore, "terminal_command", side_effect=replies) as command:
                with mock.patch.object(restore.time, "sleep"):
                    self.assertEqual(restore.switch_terminal_to_binary("COM7"), "on")
        self.assertEqual([call.args[1] for call in command.call_args_list], [
            "+++MESHCORE-TERM-START", "get usb.logging", "set usb.logging off", "+++MESHCORE-TERM-STOP"
        ])

    async def test_bluetooth_resync_cycles_only_when_enabled(self):
        class BluetoothCommands:
            def __init__(self, enabled):
                self.enabled = enabled
                self.calls = []

            async def run_cli_command(self, command):
                self.calls.append(command)
                if command == "get bluetooth":
                    return event("cli_reply", {"text": f"bluetooth {'on' if self.enabled else 'off'}"})
                self.enabled = command.endswith("on")
                return event("cli_reply", {"text": f"OK - Bluetooth {'on' if self.enabled else 'off'} (this boot)"})

        enabled = BluetoothCommands(True)
        await restore.resync_bluetooth(enabled)
        self.assertEqual(enabled.calls, ["get bluetooth", "set bluetooth off", "set bluetooth on", "get bluetooth"])
        disabled = BluetoothCommands(False)
        await restore.resync_bluetooth(disabled)
        self.assertEqual(disabled.calls, ["get bluetooth"])


if __name__ == "__main__":
    unittest.main()
