"""Restore the writable parts of a verified MeshCore companion USB backup.

This is a logical configuration restore, not a firmware or unread-message restore.
No secret values are written to stdout or logs.
"""

import argparse
import asyncio
import hmac
import json
import re
import sys
import time
from pathlib import Path

from meshcore_backup import validate_archive_data


class RestoreError(Exception):
    pass


def load_backup(path):
    with path.open("r", encoding="utf-8") as stream:
        archive = json.load(stream)
    verified = validate_archive_data(archive)
    payload = archive["payload"]
    if payload["source"]["node"]["role"] != "companion":
        raise RestoreError("Only companion backups can be restored")
    sections = payload["sections"]
    required = ("self_info", "identity_private_key", "device_info", "channels", "contacts")
    if any(sections[name]["state"] != "complete" for name in required):
        raise RestoreError("Backup lacks a complete identity, channels, or contacts section")
    serial = payload["source"]["physical_usb_identity"].get("serial")
    if not serial:
        raise RestoreError("Backup has no USB serial for physical-device matching")
    return payload, verified, serial


def matching_port(serial):
    from serial.tools import list_ports

    ports = [p.device for p in list_ports.comports() if p.serial_number and
             hmac.compare_digest(p.serial_number.lower(), serial.lower())]
    if len(ports) != 1:
        raise RestoreError(f"Expected one connected USB device with backup serial; found {len(ports)}")
    return ports[0]


def list_usb_ports():
    from serial.tools import list_ports

    for port in list_ports.comports():
        if port.serial_number:
            print(f"{port.device}: USB serial {port.serial_number}; {port.description}")


def terminal_command(serial_port, command, seconds=1.5):
    serial_port.reset_input_buffer()
    serial_port.write((command + "\n").encode("ascii"))
    deadline = time.monotonic() + seconds
    received = bytearray()
    while time.monotonic() < deadline:
        received.extend(serial_port.read(512))
    return received.decode("utf-8", "replace")


def usb_logging_state(reply):
    match = re.search(r"\busb\.logging\s+(on|off)\b", reply, re.IGNORECASE)
    return match.group(1).lower() if match else None


def switch_terminal_to_binary(port):
    """Use the Full Companion terminal handoff; never print console contents."""
    import serial

    with serial.Serial(port, 115200, timeout=0.15, write_timeout=1) as connection:
        connection.rts = False
        connection.dtr = True
        time.sleep(0.2)
        terminal_command(connection, "+++MESHCORE-TERM-START", seconds=0.5)
        original = usb_logging_state(terminal_command(connection, "get usb.logging"))
        if original is None:
            raise RestoreError("USB terminal did not report its logging state")
        if original == "on":
            response = terminal_command(connection, "set usb.logging off")
            if "OK - USB logging off (saved)" not in response or "reboot required" in response:
                terminal_command(connection, "set usb.logging on")
                raise RestoreError("USB logging could not be disabled without a reboot")
        response = terminal_command(connection, "+++MESHCORE-TERM-STOP")
        if "OK - Binary mode" not in response:
            if original == "on":
                terminal_command(connection, "set usb.logging on")
            raise RestoreError("USB terminal did not enter Binary Companion mode")
    return original


def restore_terminal_state(port, logging_state):
    """Return the device to the original text terminal and logging state."""
    import serial

    with serial.Serial(port, 115200, timeout=0.15, write_timeout=1) as connection:
        connection.rts = False
        connection.dtr = True
        time.sleep(0.2)
        terminal_command(connection, "+++MESHCORE-TERM-START", seconds=0.6)
        current = usb_logging_state(terminal_command(connection, "get usb.logging"))
        if current is None:
            raise RestoreError("Could not read USB logging after returning to terminal mode")
        if current != logging_state:
            response = terminal_command(connection, f"set usb.logging {logging_state}")
            if f"OK - USB logging {logging_state} (saved)" not in response:
                raise RestoreError("Could not restore the prior USB logging setting")


def archived_usb_logging(backup):
    section = backup["sections"].get("usb_logging", {})
    if section.get("state") != "complete":
        return None
    data = section.get("data", {})
    return usb_logging_state(data.get("text", "")) if isinstance(data, dict) else None


def bluetooth_name_status(reply):
    match = re.fullmatch(r">\s*(.*?)\s+\((default from node name|custom)\)\s*", reply, re.IGNORECASE)
    if not match:
        raise RestoreError("Bluetooth name status has an unrecognized format")
    return match.group(1), match.group(2).lower()


def archived_bluetooth_name(section):
    data = section["data"]
    if "name" in data and "default" in data:
        return data["name"], "default from node name" if data["default"] else "custom"
    return bluetooth_name_status(data["text"])


def radio_cad_status(reply):
    match = re.search(
        r"\bradio\.cad\s+(on|off),\s*scan=(auto|\d+)(?:\(\d+\))?\s+ms,\s*"
        r"retry=(auto|\d+)\s+ms,\s*max=(auto|\d+)\s+ms",
        reply,
        re.IGNORECASE,
    )
    if not match:
        raise RestoreError("Radio CAD status has an unrecognized format")
    return tuple(value.lower() for value in match.groups())


def check_event(event, kind, label):
    if event is None or getattr(event.type, "value", None) != kind:
        raise RestoreError(f"{label}: device did not confirm the operation")
    return event.payload


async def connect(port):
    from meshcore import MeshCore

    client = await MeshCore.create_serial(port=port, baudrate=115200,
                                          default_timeout=8, only_error=True)
    if client is None:
        raise RestoreError("USB device is not answering as a MeshCore serial companion; settings restore cannot run in DFU or another role")
    return client


async def inspect(client, backup, *, new_hardware=False):
    info = check_event(await client.commands.send_appstart(), "self_info", "Companion probe")
    device = check_event(await client.commands.send_device_query(), "device_info", "Device probe")
    if info.get("adv_type") != 1:
        raise RestoreError("Connected device is not a companion")
    source = backup["sections"]["device_info"]["data"]
    capacity = device.get("max_channels", 0)
    channels = backup["sections"]["channels"]["data"]
    if capacity < len(channels) and any(row["channel_name"] for row in channels[capacity:]):
        raise RestoreError("Target has too few channel slots for populated backup channels")
    if device.get("max_contacts", 0) < len(backup["sections"]["contacts"]["data"]):
        raise RestoreError("Target has fewer contact slots than the backup")
    if source.get("model") != device.get("model") and not new_hardware:
        raise RestoreError("Target MeshCore model differs; use the explicit new-hardware path")
    key = info.get("public_key", "")
    expected = backup["source"]["node"]["public_key"]
    return {"same_key": isinstance(key, str) and hmac.compare_digest(key.lower(), expected.lower()),
            "key_prefix": key[:12], "model": device.get("model"), "version": device.get("ver"),
            "channel_capacity": capacity}


async def write(commands, method, label, *args):
    result = await getattr(commands, method)(*args)
    check_event(result, "command_ok", label)


async def resync_bluetooth(commands):
    reply = check_event(await commands.run_cli_command("get bluetooth"), "cli_reply", "Bluetooth status")
    state = re.search(r"\bbluetooth\s+(on|off)\b", reply.get("text", ""), re.IGNORECASE)
    if not state:
        raise RestoreError("Bluetooth status could not be read")
    if state.group(1).lower() == "off":
        print("Bluetooth was already off; left unchanged")
        return
    try:
        reply = check_event(await commands.run_cli_command("set bluetooth off"), "cli_reply", "Bluetooth off")
        if "OK - Bluetooth off" not in reply.get("text", ""):
            raise RestoreError("Bluetooth did not confirm off")
    finally:
        # Bluetooth control is for this boot only. Do not leave a previously
        # enabled phone connection disabled if the first operation fails.
        reply = check_event(await commands.run_cli_command("set bluetooth on"), "cli_reply", "Bluetooth on")
        if "OK - Bluetooth on" not in reply.get("text", ""):
            raise RestoreError("Bluetooth could not be re-enabled")
    reply = check_event(await commands.run_cli_command("get bluetooth"), "cli_reply", "Bluetooth verification")
    if not re.search(r"\bbluetooth\s+on\b", reply.get("text", ""), re.IGNORECASE):
        raise RestoreError("Bluetooth did not verify as on")
    print("Bluetooth cycled on this boot; reconnect the phone app to sync restored settings")


async def ensure_usb_logging_off(commands):
    reply = check_event(await commands.run_cli_command("get usb.logging"), "cli_reply", "USB logging status")
    state = usb_logging_state(reply.get("text", ""))
    if state is None:
        raise RestoreError("USB logging status could not be read")
    if state == "on":
        reply = check_event(await commands.run_cli_command("set usb.logging off"), "cli_reply", "USB logging off")
        if "OK - USB logging off (saved)" not in reply.get("text", ""):
            raise RestoreError("USB logging could not be set to the backup's off state")
        reply = check_event(await commands.run_cli_command("get usb.logging"), "cli_reply", "USB logging verification")
        if usb_logging_state(reply.get("text", "")) != "off":
            raise RestoreError("USB logging did not verify as off")


async def apply(client, backup, *, replace_identity=False, new_hardware=False):
    sections = backup["sections"]
    status = await inspect(client, backup, new_hardware=new_hardware)
    expected = backup["source"]["node"]["public_key"]
    commands = client.commands
    if not status["same_key"]:
        if not replace_identity:
            raise RestoreError("Target public key differs; rerun with explicit identity replacement")
        key = bytes.fromhex(sections["identity_private_key"]["data"]["private_key"])
        await write(commands, "import_private_key", "Identity", key)
        current = check_event(await commands.send_appstart(), "self_info", "Identity verification")
        if not hmac.compare_digest(str(current.get("public_key", "")).lower(), expected.lower()):
            raise RestoreError("Imported identity did not verify; stopped before restoring settings")
        print("Identity restored and verified")
    else:
        print("Identity already matches backup")

    channels = sections["channels"]["data"][:status["channel_capacity"]]
    for row in channels:
        idx = row["channel_idx"]
        current = check_event(await commands.get_channel(idx), "channel_info", f"Channel {idx} read")
        secret = current.get("channel_secret")
        secret_hex = secret.hex() if isinstance(secret, bytes) else secret
        if current.get("channel_name") == row["channel_name"] and secret_hex == row["channel_secret"]:
            continue
        await write(commands, "set_channel", f"Channel {idx}", idx, row["channel_name"], bytes.fromhex(row["channel_secret"]))
        saved = check_event(await commands.get_channel(idx), "channel_info", f"Channel {idx} verification")
        secret = saved.get("channel_secret")
        secret_hex = secret.hex() if isinstance(secret, bytes) else secret
        if saved.get("channel_name") != row["channel_name"] or secret_hex != row["channel_secret"]:
            raise RestoreError(f"Channel {idx} failed verification")
    print(f"Channels verified: {len(channels)}")

    desired_contacts = sections["contacts"]["data"]
    existing = check_event(await commands.get_contacts(), "contacts", "Contact inventory")
    if not isinstance(existing, dict):
        raise RestoreError("Target contacts could not be read")
    changed = 0
    for key, row in desired_contacts.items():
        live = existing.get(key)
        fields = ("public_key", "type", "flags", "out_path_len", "out_path_hash_mode",
                  "out_path", "adv_name", "last_advert", "adv_lat", "adv_lon")
        if live and all(live.get(field) == row.get(field) for field in fields):
            continue
        await write(commands, "add_contact" if live is None else "update_contact", "Contact", dict(row))
        changed += 1
        if changed % 20 == 0:
            print(f"Contacts written: {changed}")
    refreshed = check_event(await commands.get_contacts(), "contacts", "Contact verification")
    missing = [key for key in desired_contacts if key not in refreshed]
    if missing:
        raise RestoreError(f"Contact verification failed for {len(missing)} records")
    stable_fields = ("public_key", "type", "flags", "out_path_len", "out_path_hash_mode",
                     "out_path", "adv_name", "adv_lat", "adv_lon")
    differing = sum(any(refreshed[key].get(field) != row.get(field) for field in stable_fields)
                    for key, row in desired_contacts.items())
    if differing:
        raise RestoreError(f"Contact verification found {differing} differing records")
    print(f"Contacts present: {len(desired_contacts)}; written: {changed}")

    saved = sections["self_info"]["data"]
    live = check_event(await commands.send_appstart(), "self_info", "Settings read")
    if live.get("name") != saved["name"]:
        await write(commands, "set_name", "Name", saved["name"])
    if (live.get("adv_lat"), live.get("adv_lon")) != (saved["adv_lat"], saved["adv_lon"]):
        await write(commands, "set_coords", "Coordinates", saved["adv_lat"], saved["adv_lon"])
    if live.get("tx_power") != saved["tx_power"]:
        await write(commands, "set_tx_power", "TX power", saved["tx_power"])
    radio_fields = ("radio_freq", "radio_bw", "radio_sf", "radio_cr")
    if any(live.get(field) != saved[field] for field in radio_fields):
        await write(commands, "set_radio", "Radio", *(saved[field] for field in radio_fields))
    other_fields = ("manual_add_contacts", "telemetry_mode_base", "telemetry_mode_loc",
                    "telemetry_mode_env", "adv_loc_policy", "multi_acks")
    if any(live.get(field) != saved[field] for field in other_fields):
        await write(commands, "set_other_params_from_infos", "Other settings", saved)
    after = check_event(await commands.send_appstart(), "self_info", "Settings verification")
    for field in ("name", "tx_power", *radio_fields, *other_fields):
        if after.get(field) != saved[field]:
            raise RestoreError(f"Setting failed verification: {field}")
    for field in ("adv_lat", "adv_lon"):
        if abs(after.get(field, 9999) - saved[field]) > 0.000002:
            raise RestoreError(f"Setting failed verification: {field}")
    print("Companion settings verified")

    pin = sections["device_info"]["data"].get("ble_pin")
    if isinstance(pin, int):
        device = check_event(await commands.send_device_query(), "device_info", "Device settings read")
        if device.get("ble_pin") != pin:
            await write(commands, "set_devicepin", "BLE PIN", pin)
            device = check_event(await commands.send_device_query(), "device_info", "BLE PIN verification")
            if device.get("ble_pin") != pin:
                raise RestoreError("BLE PIN failed verification")
        print("BLE PIN verified")

    if sections["autoadd"]["state"] == "complete":
        value = sections["autoadd"]["data"]["config"]
        current = check_event(await commands.get_autoadd_config(), "autoadd_config", "Auto-add verification")
        if current.get("config") != value:
            await write(commands, "set_autoadd_config", "Auto-add", value)
            current = check_event(await commands.get_autoadd_config(), "autoadd_config", "Auto-add verification")
            if current.get("config") != value:
                raise RestoreError("Auto-add failed verification")
    if sections["tuning"]["state"] == "complete":
        value = sections["tuning"]["data"]
        current = check_event(await commands.get_tuning(), "tuning_params", "Tuning verification")
        if any(current.get(k) != value[k] for k in ("rx_delay", "airtime_factor")):
            await write(commands, "set_tuning", "Tuning", value["rx_delay"], value["airtime_factor"])
            current = check_event(await commands.get_tuning(), "tuning_params", "Tuning verification")
            if any(current.get(k) != value[k] for k in ("rx_delay", "airtime_factor")):
                raise RestoreError("Tuning failed verification")
    if sections["custom_vars"]["state"] == "complete":
        current = check_event(await commands.get_custom_vars(), "custom_vars", "Custom-variable read")
        for key, value in sections["custom_vars"]["data"].items():
            if current.get(key) != value:
                await write(commands, "set_custom_var", "Custom variable", key, value)
        current = check_event(await commands.get_custom_vars(), "custom_vars", "Custom-variable verification")
        if any(current.get(k) != v for k, v in sections["custom_vars"]["data"].items()):
            raise RestoreError("Custom variables failed verification")
    if sections["default_flood_scope"]["state"] == "complete":
        scope = sections["default_flood_scope"]["data"]
        name = scope.get("scope_name", "")
        current = check_event(await commands.get_default_flood_scope(), "default_flood_scope", "Flood-scope read")
        if current != scope:
            await write(commands, "set_default_flood_scope", "Default flood scope", name)
            current = check_event(await commands.get_default_flood_scope(), "default_flood_scope", "Flood-scope verification")
        if name:
            if current.get("scope_name") != name or current.get("scope_key") != scope.get("scope_key"):
                raise RestoreError("Default flood scope failed verification")
        elif current.get("scope_name", "") or current.get("scope_key", "0" * 32) != "0" * 32:
            raise RestoreError("Default flood scope failed verification")
    if sections.get("bluetooth_name", {}).get("state") == "complete":
        saved_name, saved_mode = archived_bluetooth_name(sections["bluetooth_name"])
        reply = check_event(await commands.run_cli_command("get bluetooth.name"), "cli_reply", "Bluetooth name read")
        current_name, current_mode = bluetooth_name_status(reply.get("text", ""))
        if saved_mode != current_mode or (saved_mode == "custom" and saved_name != current_name):
            value = "default" if saved_mode == "default from node name" else saved_name
            reply = check_event(await commands.run_cli_command(f"set bluetooth.name {value}"), "cli_reply", "Bluetooth name restore")
            if "OK - Bluetooth name" not in reply.get("text", ""):
                raise RestoreError("Bluetooth name was not accepted")
            reply = check_event(await commands.run_cli_command("get bluetooth.name"), "cli_reply", "Bluetooth name verification")
            verified_name, verified_mode = bluetooth_name_status(reply.get("text", ""))
            if verified_mode != saved_mode or (saved_mode == "custom" and verified_name != saved_name):
                raise RestoreError("Bluetooth name did not verify")
            print("Bluetooth name setting restored; reboot may be needed for advertising-name change")
    if sections.get("radio_cad", {}).get("state") == "complete":
        desired = radio_cad_status(sections["radio_cad"]["data"]["text"])
        reply = check_event(await commands.run_cli_command("get radio.cad"), "cli_reply", "Radio CAD read")
        current = radio_cad_status(reply.get("text", ""))
        if current[1:] != desired[1:]:
            reply = check_event(
                await commands.run_cli_command("set radio.cad timings " + " ".join(desired[1:])),
                "cli_reply", "Radio CAD timings",
            )
            if "error" in reply.get("text", "").lower():
                raise RestoreError("Radio CAD timings were rejected")
        if current[0] != desired[0]:
            reply = check_event(await commands.run_cli_command(f"set radio.cad {desired[0]}"), "cli_reply", "Radio CAD mode")
            if "error" in reply.get("text", "").lower():
                raise RestoreError("Radio CAD mode was rejected")
        if current != desired:
            reply = check_event(await commands.run_cli_command("get radio.cad"), "cli_reply", "Radio CAD verification")
            if radio_cad_status(reply.get("text", "")) != desired:
                raise RestoreError("Radio CAD did not verify")
    print("Structured role settings verified")
    print("Note: firmware, unread messages, and other optional CLI-only settings are not in this restore scope")


async def run(args):
    if args.command == "ports":
        list_usb_ports()
        return 0
    path = Path(args.input).expanduser().resolve()
    backup, verified, serial = load_backup(path)
    selected_serial = args.target_serial or serial
    if selected_serial.lower() != serial.lower() and not args.new_hardware:
        raise RestoreError("A different USB serial requires --new-hardware")
    port = matching_port(selected_serial)
    print(f"Verified archive SHA-256: {verified['sha256']}")
    print(f"Matched USB serial {selected_serial} on {port}")
    original_logging = None
    switched_from_terminal = False
    try:
        client = await connect(port)
    except RestoreError:
        if not args.allow_mode_switch:
            raise RestoreError("No binary companion reply. If this is a Full Companion terminal, rerun with --allow-mode-switch to change USB logging temporarily")
        original_logging = switch_terminal_to_binary(port)
        switched_from_terminal = True
        print(f"Entered Binary Companion mode; prior USB logging was {original_logging}")
        try:
            client = await connect(port)
        except Exception:
            restore_terminal_state(port, original_logging)
            raise
    completed = False
    try:
        status = await inspect(client, backup, new_hardware=args.new_hardware)
        print(f"MeshCore companion: {status['model']}, firmware {status['version']}, key {status['key_prefix']}...")
        print(f"Backup key {backup['source']['node']['public_key'][:12]}..., contacts {len(backup['sections']['contacts']['data'])}, channels {len(backup['sections']['channels']['data'])}")
        if args.command == "probe":
            print("Identity matches" if status["same_key"] else "Identity differs; restoring would replace it")
            return 0
        if args.command == "resync":
            if not args.confirmed:
                raise RestoreError("Bluetooth resync requires an explicit confirmation")
            if not status["same_key"]:
                raise RestoreError("Bluetooth resync target identity does not match the backup")
            await resync_bluetooth(client.commands)
            completed = True
            return 0
        if not args.confirmed:
            raise RestoreError("Restore requires an explicit confirmation")
        if not status["same_key"] and not args.replace_identity:
            raise RestoreError("Identity differs; explicit --replace-identity is required")
        if matching_port(selected_serial) != port:
            raise RestoreError("USB device changed ports before restore")
        await apply(client, backup, replace_identity=args.replace_identity, new_hardware=args.new_hardware)
        if archived_usb_logging(backup) == "off":
            await ensure_usb_logging_off(client.commands)
        completed = True
        return 0
    finally:
        await client.disconnect()
        if args.command == "probe" and switched_from_terminal:
            restore_terminal_state(port, original_logging)
        elif args.command in ("restore", "resync"):
            if completed:
                desired = archived_usb_logging(backup)
                if desired == "on":
                    restore_terminal_state(port, "on")
                    print("USB logging restored to the backup's on setting")
                elif desired == "off":
                    print("USB logging remains off, matching the backup")
            elif switched_from_terminal:
                restore_terminal_state(port, original_logging)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ports", "probe", "restore", "resync"))
    parser.add_argument("--input")
    parser.add_argument("--target-serial")
    parser.add_argument("--new-hardware", action="store_true")
    parser.add_argument("--allow-mode-switch", action="store_true")
    parser.add_argument("--confirmed", action="store_true")
    parser.add_argument("--replace-identity", action="store_true")
    args = parser.parse_args(argv)
    if args.command != "ports" and not args.input:
        parser.error("--input is required for probe, restore, or resync")
    try:
        return asyncio.run(run(args))
    except Exception as exc:
        # Avoid accidentally exposing key material or channel secrets in exceptions.
        if isinstance(exc, RestoreError):
            print(f"Restore stopped: {exc}", file=sys.stderr)
        else:
            print(f"Restore stopped: {type(exc).__name__}; no secret details displayed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
