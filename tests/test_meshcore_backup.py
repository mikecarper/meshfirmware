import asyncio
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "meshcore_backup.py"
SPEC = importlib.util.spec_from_file_location("meshcore_backup", MODULE_PATH)
backup = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = backup
SPEC.loader.exec_module(backup)


PUBLIC_KEY = "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
SECOND_PUBLIC_KEY = "22" * 32
PRIVATE_KEY = (
    "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60"
    "c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471"
)


class FakeEvent:
    def __init__(self, kind, payload=None):
        self.type = kind
        self.payload = {} if payload is None else payload


class FakeReader:
    def __init__(self, contact_nb):
        self.contact_nb = contact_nb


class FakeCommands:
    def __init__(
        self,
        *,
        private_kind="private_key",
        contact_count=2,
        second_public_key=PUBLIC_KEY,
        adv_type=1,
        optional_error=None,
        private_key=PRIVATE_KEY,
        channel_secret_length=16,
    ):
        self.private_kind = private_kind
        self.second_public_key = second_public_key
        self.adv_type = adv_type
        self.optional_error = optional_error
        self.private_key = private_key
        self.channel_secret_length = channel_secret_length
        self.appstart_calls = 0
        self.contacts = {
            "aa" * 32: {
                "public_key": "aa" * 32,
                "type": 1,
                "flags": 1,
                "out_path_len": 0,
                "out_path_hash_mode": 0,
                "out_path": "",
                "adv_name": "alpha",
                "last_advert": 1,
                "adv_lat": 1.0,
                "adv_lon": 2.0,
                "lastmod": 1,
            },
            "bb" * 32: {
                "public_key": "bb" * 32,
                "type": 2,
                "flags": 2,
                "out_path_len": 2,
                "out_path_hash_mode": 0,
                "out_path": "0102",
                "adv_name": "beta",
                "last_advert": 2,
                "adv_lat": -1.0,
                "adv_lon": -2.0,
                "lastmod": 2,
            },
        }
        self.contact_count = contact_count

    async def send_appstart(self):
        self.appstart_calls += 1
        public_key = PUBLIC_KEY if self.appstart_calls == 1 else self.second_public_key
        return FakeEvent(
            "self_info",
            {
                "public_key": public_key,
                "adv_type": self.adv_type,
                "name": "unit-test-node",
                "tx_power": 20,
                "max_tx_power": 22,
                "adv_lat": 1.25,
                "adv_lon": -2.5,
                "radio_freq": 910.525,
                "radio_bw": 62.5,
                "radio_sf": 7,
                "radio_cr": 5,
                "manual_add_contacts": True,
                "telemetry_mode_base": 1,
                "telemetry_mode_loc": 1,
                "telemetry_mode_env": 1,
                "adv_loc_policy": 0,
                "multi_acks": 1,
            },
        )

    async def send_device_query(self):
        return FakeEvent(
            "device_info",
            {
                "fw ver": 10,
                "max_contacts": 100,
                "max_channels": 2,
                "ble_pin": 123456,
                "fw_build": "test-build",
                "model": "test-board",
                "ver": "1.2.3",
                "repeat": False,
                "path_hash_mode": 0,
            },
        )

    async def export_private_key(self):
        if self.private_kind == "private_key":
            return FakeEvent("private_key", {"private_key": bytes.fromhex(self.private_key)})
        return FakeEvent(self.private_kind, {})

    async def get_contacts(self):
        return FakeEvent("contacts", self.contacts)

    async def get_channel(self, index):
        secret = bytes([index + 1]) * self.channel_secret_length
        return FakeEvent(
            "channel_info",
            {
                "channel_idx": index,
                "channel_name": "#public" if index == 0 else "private",
                "channel_secret": secret,
                "channel_hash": __import__("hashlib").sha256(secret).hexdigest()[:2],
            },
        )

    async def get_bat(self):
        return FakeEvent("battery_info", {"level": 4050, "used_kb": 12, "total_kb": 256})

    async def get_autoadd_config(self):
        return FakeEvent("autoadd_config", {"config": 1, "max_hops": 3})

    async def get_default_flood_scope(self):
        return FakeEvent("default_flood_scope", {})

    async def get_tuning(self):
        if self.optional_error == "tuning":
            return FakeEvent("command_error", {"reason": "timeout"})
        return FakeEvent("tuning_params", {"rx_delay": 10, "airtime_factor": 2})

    async def get_custom_vars(self):
        return FakeEvent("custom_vars", {"owner": "test"})

    async def run_cli_command(self, command):
        return FakeEvent("cli_reply", {"text": f"> value-for-{command}"})


class FakeClient:
    def __init__(self, **kwargs):
        self.commands = FakeCommands(**kwargs)
        self._reader = FakeReader(self.commands.contact_count)
        self.disconnected = False

    async def disconnect(self):
        self.disconnected = True


class FakeSerial:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeTextCli:
    def __init__(self, *, connect=True):
        self.connect = connect
        self.serial = FakeSerial()
        self.commands = []

    async def setup_repeater_serial(self, port, baud):
        return self.serial if self.connect else None

    async def process_repeater_line(self, serial_port, command, echo=False):
        self.commands.append(command)
        if command == "get public.key":
            print(f"  -> > {PUBLIC_KEY}")
        elif command == "get prv.key":
            print(f"  -> > {PRIVATE_KEY}")
        elif command == "get role":
            print("  -> > repeater")
        elif command == "get acl":
            print("  -> 001122:3")
        elif command == "region":
            print("  -> US,902.0,928.0")
        else:
            print(f"  -> > value-for-{command.replace(' ', '-')}")
        return True


def run(coro):
    return asyncio.run(coro)


class MeshCoreBackupTests(unittest.TestCase):
    def make_request(self, directory, **changes):
        values = {
            "port": "COM_TEST",
            "output_dir": Path(directory),
            "usb_serial": "SERIAL-123",
            "usb_location": "1-2.3",
            "usb_parent": "USB\\VID_239A&PID_8029\\SERIAL-123",
            "usb_interface": "00",
            "device_hint": "test-board",
        }
        values.update(changes)
        return backup.BackupRequest(**values)

    def connector(self, client):
        async def connect(_request):
            return client

        return connect

    def assert_recomputed_archive_invalid(self, archive):
        archive["integrity"]["sha256"] = backup._archive_digest(archive)
        with self.assertRaises(backup.BackupError) as raised:
            backup.validate_archive_data(archive)
        self.assertEqual(raised.exception.code, backup.ExitCode.ARCHIVE_INVALID)

    def test_complete_companion_backup_is_atomic_and_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(client),
                )
            )

            self.assertEqual(outcome.exit_code, backup.ExitCode.PARTIAL)
            self.assertFalse(outcome.safe_for_wipe)
            self.assertTrue(client.disconnected)
            self.assertTrue(outcome.path.is_file())
            self.assertFalse(list(Path(directory).glob("*.partial")))

            verified = backup.verify_archive_file(
                outcome.path,
                expected_public_key=PUBLIC_KEY,
            )
            self.assertFalse(verified["safe_for_wipe"])
            self.assertEqual(verified["sha256"], outcome.sha256)
            with self.assertRaises(backup.BackupError):
                backup.verify_archive_file(outcome.path, require_safe_for_wipe=True)

            archive = json.loads(outcome.path.read_text(encoding="utf-8"))
            self.assertEqual(archive["schema"], backup.SCHEMA)
            self.assertEqual(
                archive["payload"]["sections"]["contacts"]["counts"],
                {"declared": 2, "received": 2},
            )
            self.assertEqual(
                archive["payload"]["sections"]["channels"]["counts"],
                {"declared": 2, "received": 2},
            )
            self.assertFalse(archive["payload"]["restore_plan"]["executor_implemented"])
            self.assertIn("messages", archive["payload"]["excluded"])
            self.assertEqual(
                archive["payload"]["completeness"]["status"],
                "api-snapshot-complete",
            )

            summary = json.dumps(outcome.public_summary())
            self.assertTrue(outcome.public_summary()["ok"])
            self.assertNotIn(PRIVATE_KEY, summary)
            self.assertNotIn(PUBLIC_KEY, summary)
            self.assertEqual(outcome.public_summary()["path"], str(outcome.path))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(outcome.path.stat().st_mode) & 0o077, 0)

    def test_disabled_private_key_saves_partial_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(FakeClient(private_kind="disabled")),
                )
            )
            self.assertEqual(outcome.exit_code, backup.ExitCode.PARTIAL)
            self.assertFalse(outcome.safe_for_wipe)
            verified = backup.verify_archive_file(outcome.path)
            self.assertFalse(verified["safe_for_wipe"])
            with self.assertRaises(backup.BackupError) as raised:
                backup.verify_archive_file(outcome.path, require_safe_for_wipe=True)
            self.assertEqual(raised.exception.code, backup.ExitCode.ARCHIVE_INVALID)

    def test_contact_stream_count_mismatch_is_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(FakeClient(contact_count=3)),
                )
            )
            self.assertEqual(outcome.exit_code, backup.ExitCode.PARTIAL)
            archive = json.loads(outcome.path.read_text(encoding="utf-8"))
            contacts = archive["payload"]["sections"]["contacts"]
            self.assertEqual(contacts["state"], "error")
            self.assertEqual(contacts["counts"], {"declared": 3, "received": 2})

    def test_persistent_setting_timeout_is_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(FakeClient(optional_error="tuning")),
                )
            )
            self.assertEqual(outcome.exit_code, backup.ExitCode.PARTIAL)
            archive = json.loads(outcome.path.read_text(encoding="utf-8"))
            self.assertIn("tuning", archive["payload"]["completeness"]["missing_required"])

    def test_public_key_change_is_hard_gate_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(backup.BackupError) as raised:
                run(
                    backup.create_backup(
                        self.make_request(directory),
                        companion_connector=self.connector(
                            FakeClient(second_public_key=SECOND_PUBLIC_KEY)
                        ),
                    )
                )
            self.assertEqual(raised.exception.code, backup.ExitCode.NODE_IDENTITY)
            self.assertFalse(list(Path(directory).glob("*.json")))

    def test_expected_public_key_mismatch_is_hard_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(backup.BackupError) as raised:
                run(
                    backup.create_backup(
                        self.make_request(directory, expected_public_key=SECOND_PUBLIC_KEY),
                        companion_connector=self.connector(FakeClient()),
                    )
                )
            self.assertEqual(raised.exception.code, backup.ExitCode.NODE_IDENTITY)

    def test_interface_02_is_rejected_before_connector(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []

            async def connector(_request):
                calls.append(True)
                return FakeClient()

            with self.assertRaises(backup.BackupError) as raised:
                run(
                    backup.create_backup(
                        self.make_request(directory, usb_interface="MI_02"),
                        companion_connector=connector,
                    )
                )
            self.assertEqual(raised.exception.code, backup.ExitCode.USB_IDENTITY)
            self.assertFalse(calls)

    def test_by_id_parent_interface_02_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.make_request(
                directory,
                usb_interface=None,
                usb_parent="by-id:usb-Adafruit_MeshCore-if02-port0",
            )
            with self.assertRaises(backup.BackupError) as raised:
                run(
                    backup.create_backup(
                        request, companion_connector=self.connector(FakeClient())
                    )
                )
            self.assertEqual(raised.exception.code, backup.ExitCode.USB_IDENTITY)

    def test_requires_stable_physical_usb_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            request = self.make_request(
                directory, usb_serial=None, usb_location=None, usb_parent=None
            )
            with self.assertRaises(backup.BackupError) as raised:
                run(
                    backup.create_backup(
                        request, companion_connector=self.connector(FakeClient())
                    )
                )
            self.assertEqual(raised.exception.code, backup.ExitCode.USB_IDENTITY)

    def test_rejects_blank_and_parent_only_logging_usb_identity(self):
        cases = {
            "blank": {
                "usb_serial": "   ",
                "usb_location": "\t",
                "usb_parent": "\r\n",
                "usb_interface": None,
            },
            "parent-mi02": {
                "usb_serial": None,
                "usb_location": None,
                "usb_parent": "USB\\VID_239A&PID_8029&MI_02\\SERIAL-123",
                "usb_interface": None,
            },
        }
        for label, changes in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                calls = []

                async def connector(_request):
                    calls.append(True)
                    return FakeClient()

                with self.assertRaises(backup.BackupError) as raised:
                    run(
                        backup.create_backup(
                            self.make_request(directory, **changes),
                            companion_connector=connector,
                        )
                    )
                self.assertEqual(raised.exception.code, backup.ExitCode.USB_IDENTITY)
                self.assertFalse(calls)

    def test_target_role_hint_falls_back_and_records_current_role(self):
        with tempfile.TemporaryDirectory() as directory:
            text_cli = FakeTextCli(connect=False)
            outcome = run(
                backup.create_backup(
                    self.make_request(directory, role_hint="repeater"),
                    companion_connector=self.connector(FakeClient(adv_type=1)),
                    text_cli_module=text_cli,
                )
            )
            self.assertEqual(outcome.role, "companion")
            self.assertEqual(outcome.exit_code, backup.ExitCode.PARTIAL)

    def test_mismatched_private_key_is_never_wipe_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(
                        FakeClient(private_key="33" * 64)
                    ),
                )
            )
            archive = json.loads(outcome.path.read_text(encoding="utf-8"))
            self.assertEqual(
                archive["payload"]["sections"]["identity_private_key"]["state"],
                "error",
            )
            self.assertFalse(outcome.safe_for_wipe)

    def test_malformed_contact_and_channel_are_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            contact_client = FakeClient()
            contact_client.commands.contacts["aa" * 32]["out_path_len"] = 3
            contact_outcome = run(
                backup.create_backup(
                    self.make_request(
                        directory,
                        output=Path(directory) / "malformed-contact.json",
                    ),
                    companion_connector=self.connector(contact_client),
                )
            )
            contact_archive = json.loads(
                contact_outcome.path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                contact_archive["payload"]["sections"]["contacts"]["state"],
                "error",
            )

            channel_outcome = run(
                backup.create_backup(
                    self.make_request(
                        directory,
                        output=Path(directory) / "malformed-channel.json",
                    ),
                    companion_connector=self.connector(
                        FakeClient(channel_secret_length=15)
                    ),
                )
            )
            channel_archive = json.loads(
                channel_outcome.path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                channel_archive["payload"]["sections"]["channels"]["state"],
                "error",
            )

    def test_common_cli_uses_existing_helper_and_is_conservatively_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            text_cli = FakeTextCli()

            async def no_companion(_request):
                raise backup.BackupError(backup.ExitCode.UNSUPPORTED, "not binary")

            outcome = run(
                backup.create_backup(
                    self.make_request(directory, role_hint="auto"),
                    companion_connector=no_companion,
                    text_cli_module=text_cli,
                )
            )
            self.assertEqual(outcome.role, "repeater")
            self.assertEqual(outcome.exit_code, backup.ExitCode.PARTIAL)
            self.assertIn("get prv.key", text_cli.commands)
            self.assertIn("region", text_cli.commands)
            self.assertTrue(text_cli.serial.closed)
            archive = json.loads(outcome.path.read_text(encoding="utf-8"))
            self.assertEqual(
                archive["payload"]["source"]["capture_api"],
                "meshcore-cli-common-cli",
            )

    def test_tamper_detection_and_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixed.json"
            request = self.make_request(directory, output=path)
            run(
                backup.create_backup(
                    request, companion_connector=self.connector(FakeClient())
                )
            )
            with self.assertRaises(backup.BackupError) as overwrite:
                run(
                    backup.create_backup(
                        request, companion_connector=self.connector(FakeClient())
                    )
                )
            self.assertEqual(overwrite.exception.code, backup.ExitCode.ARCHIVE_WRITE)

            archive = json.loads(path.read_text(encoding="utf-8"))
            archive["payload"]["source"]["node"]["role"] = "tampered"
            path.write_text(json.dumps(archive), encoding="utf-8")
            with self.assertRaises(backup.BackupError) as tampered:
                backup.verify_archive_file(path)
            self.assertEqual(tampered.exception.code, backup.ExitCode.ARCHIVE_INVALID)

    def test_atomic_publish_does_not_overwrite_a_racing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            outcome = run(
                backup.create_backup(
                    self.make_request(directory, output=source),
                    companion_connector=self.connector(FakeClient()),
                )
            )
            archive = json.loads(outcome.path.read_text(encoding="utf-8"))
            target = Path(directory) / "raced.json"
            real_link = os.link

            def create_destination_then_link(temporary, destination):
                Path(destination).write_text("racing writer", encoding="utf-8")
                return real_link(temporary, destination)

            with mock.patch.object(
                backup.os, "link", side_effect=create_destination_then_link
            ):
                with self.assertRaises(backup.BackupError) as raised:
                    backup.atomic_write_archive(target, archive)
            self.assertEqual(raised.exception.code, backup.ExitCode.ARCHIVE_WRITE)
            self.assertEqual(target.read_text(encoding="utf-8"), "racing writer")
            self.assertFalse(list(Path(directory).glob("*.partial")))

    def test_v1_validation_requires_core_identity_and_consistent_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(FakeClient()),
                )
            )
            original = json.loads(outcome.path.read_text(encoding="utf-8"))

            empty = backup.make_archive(
                {
                    "source": {},
                    "sections": {},
                    "excluded": {},
                    "completeness": {
                        "status": "partial",
                        "safe_for_wipe": False,
                        "safe_for_restore": False,
                        "missing_required": [],
                        "optional_errors": [],
                        "reasons": [],
                    },
                    "restore_plan": {},
                }
            )
            self.assert_recomputed_archive_invalid(empty)

            archive = json.loads(json.dumps(original))
            archive["payload"]["source"].pop("node")
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            archive["payload"]["sections"].pop("contacts")
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            archive["payload"]["sections"]["contacts"].pop("required")
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            identity = archive["payload"]["source"]["physical_usb_identity"]
            identity.update(
                {
                    "serial": None,
                    "location": None,
                    "parent": "USB\\VID_239A&PID_8029&MI_02\\SERIAL-123",
                    "interface": None,
                }
            )
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            archive["payload"]["sections"]["self_info"]["data"][
                "public_key"
            ] = SECOND_PUBLIC_KEY
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            archive["payload"]["sections"]["identity_stability"]["data"][
                "stable"
            ] = False
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            archive["payload"]["sections"]["contacts"]["counts"]["received"] += 1
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            archive["payload"]["sections"]["channels"]["counts"]["declared"] += 1
            self.assert_recomputed_archive_invalid(archive)

            archive = json.loads(json.dumps(original))
            archive["payload"]["completeness"].pop("status")
            self.assert_recomputed_archive_invalid(archive)

    def test_v1_archive_cannot_claim_wipe_safe_even_with_recomputed_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(FakeClient()),
                )
            )
            archive = json.loads(outcome.path.read_text(encoding="utf-8"))
            archive["payload"]["completeness"]["safe_for_wipe"] = True
            archive["integrity"]["sha256"] = backup._archive_digest(archive)
            with self.assertRaises(backup.BackupError) as raised:
                backup.validate_archive_data(archive, require_safe_for_wipe=True)
            self.assertEqual(raised.exception.code, backup.ExitCode.ARCHIVE_INVALID)

    def test_verify_summary_never_contains_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = run(
                backup.create_backup(
                    self.make_request(directory),
                    companion_connector=self.connector(FakeClient()),
                )
            )
            summary = backup.verify_archive_file(outcome.path)
            encoded = json.dumps(summary)
            self.assertNotIn(PRIVATE_KEY, encoded)
            self.assertNotIn(PUBLIC_KEY, encoded)
            self.assertEqual(summary["path"], str(outcome.path))


if __name__ == "__main__":
    unittest.main()
