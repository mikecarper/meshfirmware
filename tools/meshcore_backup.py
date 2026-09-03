#!/usr/bin/env python3
"""Non-interactive MeshCore USB backup and archive verification helper.

The shell and PowerShell frontends own all user prompts.  This helper never
erases, flashes, resets, or restores a radio.  It intentionally does not read
the message queue because ``get_msg`` consumes unread messages.

Exit codes are part of the frontend contract:

    0   complete backup, or valid archive
    2   invalid command-line arguments
    10  required Python/runtime dependency unavailable
    20  stable physical USB identity was not supplied
    21  MeshCore public-key identity mismatch
    30  role or transport unsupported/unavailable
    31  backup saved, but incomplete or unsafe for an unattended wipe
    32  archive could not be written or re-read atomically
    40  archive schema, content, or digest invalid

Restore-related codes 41-43 and ESP raw-image code 50 are reserved so that a
future restore/esptool extension can add behavior without renumbering callers.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as _datetime
import hashlib
import hmac
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Awaitable, Callable, Mapping, Optional


SCHEMA = "org.meshfirmware.meshcore-backup/v1"
ARCHIVE_KIND = "meshcore-logical-usb"
TOOL_VERSION = "0.2.0"
MIN_MESHCORE_VERSION = (2, 3, 9)
MIN_MESHCORE_CLI_VERSION = (1, 6, 3)
MIN_PYNACL_VERSION = (1, 5, 0)
MAX_MESHCORE_VERSION = (3, 0, 0)
MAX_MESHCORE_CLI_VERSION = (2, 0, 0)
MAX_PYNACL_VERSION = (2, 0, 0)
ROLE_CHOICES = ("auto", "companion", "repeater", "room-server", "sensor", "kiss")
SECTION_STATES = {"complete", "unsupported", "disabled", "error", "not_applicable"}
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HEX_32_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
HEX_64_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{128}(?![0-9a-f])")
COMPANION_CLI_QUERIES = (
    ("storage_layout", "get storage.layout", None),
    ("radio_cad", "get radio.cad", "set radio.cad"),
    ("radio_rxgain", "get radio.rxgain", "set radio.rxgain"),
    ("radio_fem_rxgain", "get radio.fem.rxgain", "set radio.fem.rxgain"),
    ("radio_fem_txgain", "get radio.fem.txgain", "set radio.fem.txgain"),
    ("bluetooth_name", "get bluetooth.name", "set bluetooth.name"),
    ("display_rotation", "get display.rotation", "set display.rotation"),
    ("power_saving", "get powersaving", "powersaving on/off"),
    ("usb_logging", "get usb.logging", "set usb.logging"),
    ("radio_rxps", "get radio.rxps.config", "set radio.rxps"),
)


class ExitCode(IntEnum):
    OK = 0
    USAGE = 2
    DEPENDENCY = 10
    USB_IDENTITY = 20
    NODE_IDENTITY = 21
    UNSUPPORTED = 30
    PARTIAL = 31
    ARCHIVE_WRITE = 32
    ARCHIVE_INVALID = 40
    RESTORE_IDENTITY = 41
    RESTORE_WRITE = 42
    RESTORE_VERIFY = 43
    ESPTOOL_BACKUP = 50


class BackupError(RuntimeError):
    """Expected failure carrying a stable process exit code."""

    def __init__(self, code: ExitCode, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class BackupRequest:
    port: str
    output_dir: Path
    output: Optional[Path] = None
    baud: int = 115200
    timeout: float = 8.0
    role_hint: str = "auto"
    usb_serial: Optional[str] = None
    usb_location: Optional[str] = None
    usb_parent: Optional[str] = None
    usb_interface: Optional[str] = None
    device_hint: Optional[str] = None
    expected_public_key: Optional[str] = None

    def physical_identity(self) -> dict[str, Any]:
        return {
            "serial": self.usb_serial,
            "location": self.usb_location,
            "parent": self.usb_parent,
            "interface": self.usb_interface,
            "device_hint": self.device_hint,
            "attestation": "caller-provided",
        }


@dataclass(frozen=True)
class BackupOutcome:
    path: Path
    sha256: str
    completeness: str
    safe_for_wipe: bool
    role: str
    public_key: Optional[str]
    reasons: tuple[str, ...] = ()

    @property
    def exit_code(self) -> ExitCode:
        return ExitCode.OK if self.safe_for_wipe else ExitCode.PARTIAL

    def public_summary(self) -> dict[str, Any]:
        # Deliberately omit node keys, contacts, channels, credentials, and CLI
        # replies.  The key prefix is enough to correlate a backup interactively.
        return {
            "ok": True,
            "exit_code": int(self.exit_code),
            "archive": str(self.path),
            "path": str(self.path),
            "sha256": self.sha256,
            "completeness": self.completeness,
            "safe_for_wipe": self.safe_for_wipe,
            "role": self.role,
            "node_key_prefix": self.public_key[:12] if self.public_key else None,
            "reasons": list(self.reasons),
        }


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat(timespec="seconds")


def _package_version(name: str) -> Optional[str]:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _require_package_version(
    name: str,
    minimum: tuple[int, ...],
    maximum_exclusive: Optional[tuple[int, ...]] = None,
) -> None:
    installed = _package_version(name)
    if installed is None:
        raise BackupError(ExitCode.DEPENDENCY, f"{name} is not installed")
    numeric = tuple(int(part) for part in re.findall(r"\d+", installed)[: len(minimum)])
    numeric += (0,) * (len(minimum) - len(numeric))
    if numeric < minimum:
        floor = ".".join(str(part) for part in minimum)
        raise BackupError(ExitCode.DEPENDENCY, f"{name}>={floor} is required")
    if maximum_exclusive is not None and numeric >= maximum_exclusive:
        floor = ".".join(str(part) for part in minimum)
        ceiling = ".".join(str(part) for part in maximum_exclusive)
        raise BackupError(
            ExitCode.DEPENDENCY, f"{name}>={floor},<{ceiling} is required"
        )


def _require_python_version() -> None:
    if sys.version_info < (3, 10):
        raise BackupError(ExitCode.DEPENDENCY, "Python 3.10 or newer is required")


def _json_safe(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (_datetime.datetime, _datetime.date)):
        return value.isoformat()
    if hasattr(value, "value") and isinstance(value.value, (str, int, float, bool)):
        return value.value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _archive_digest(archive: Mapping[str, Any]) -> str:
    covered = dict(archive)
    covered.pop("integrity", None)
    return hashlib.sha256(_canonical_bytes(covered)).hexdigest()


def _normalise_hex(value: Any, byte_length: int, label: str) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        text = bytes(value).hex()
    else:
        text = str(value or "").strip().lower()
        if text.startswith("0x"):
            text = text[2:]
    if len(text) != byte_length * 2 or not re.fullmatch(r"[0-9a-f]+", text):
        raise ValueError(f"{label} must be exactly {byte_length} bytes of hexadecimal")
    return text


def _derive_meshcore_public_key(private_key: str) -> str:
    """Derive MeshCore's Ed25519 public key from its 64-byte expanded key."""

    _require_package_version("PyNaCl", MIN_PYNACL_VERSION, MAX_PYNACL_VERSION)
    try:
        from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
    except (ImportError, ModuleNotFoundError) as exc:
        raise BackupError(
            ExitCode.DEPENDENCY, "PyNaCl is required to validate MeshCore identities"
        ) from exc
    try:
        private_bytes = bytes.fromhex(private_key)
        return crypto_scalarmult_ed25519_base_noclamp(private_bytes[:32]).hex()
    except (TypeError, ValueError, RuntimeError) as exc:
        raise ValueError("private key is not a valid MeshCore Ed25519 key") from exc


def _validate_contact_records(value: Any) -> Optional[str]:
    if not isinstance(value, (Mapping, list)):
        return "contacts response was not a collection"
    rows = list(value.values()) if isinstance(value, Mapping) else list(value)
    mapping_keys = list(value.keys()) if isinstance(value, Mapping) else []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            return f"contact {index} was not an object"
        try:
            public_key = _normalise_hex(row.get("public_key"), 32, "contact public key")
        except ValueError:
            return f"contact {index} has an invalid public key"
        if mapping_keys and str(mapping_keys[index]).lower() != public_key:
            return f"contact {index} map key does not match its public key"
        for field in ("type", "flags", "out_path_len", "out_path_hash_mode", "last_advert", "lastmod"):
            if not isinstance(row.get(field), int):
                return f"contact {index} has an invalid {field}"
        if not 0 <= row["type"] <= 255 or not 0 <= row["flags"] <= 255:
            return f"contact {index} has an out-of-range type or flags value"
        path_len = row["out_path_len"]
        path_mode = row["out_path_hash_mode"]
        path = row.get("out_path")
        if not isinstance(path, str) or not re.fullmatch(r"[0-9a-fA-F]*", path):
            return f"contact {index} has an invalid path encoding"
        if path_len == -1:
            if path_mode != -1 or path:
                return f"contact {index} has inconsistent flood-path metadata"
        elif not (0 <= path_len <= 63 and 0 <= path_mode <= 3):
            return f"contact {index} has out-of-range path metadata"
        elif len(path) != path_len * (path_mode + 1) * 2:
            return f"contact {index} path length does not match its metadata"
        if not isinstance(row.get("adv_name"), str):
            return f"contact {index} has an invalid advertised name"
        if row["last_advert"] < 0 or row["lastmod"] < 0:
            return f"contact {index} has a negative timestamp"
        lat, lon = row.get("adv_lat"), row.get("adv_lon")
        if not isinstance(lat, (int, float)) or not -90 <= lat <= 90:
            return f"contact {index} has an invalid latitude"
        if not isinstance(lon, (int, float)) or not -180 <= lon <= 180:
            return f"contact {index} has an invalid longitude"
    return None


def _validate_channel_record(value: Any, expected_index: int) -> Optional[str]:
    if not isinstance(value, Mapping) or value.get("channel_idx") != expected_index:
        return "channel index mismatch"
    name = value.get("channel_name")
    if not isinstance(name, str) or len(name.encode("utf-8")) > 32:
        return "channel name is invalid"
    secret_value = value.get("channel_secret")
    try:
        secret = (
            bytes(secret_value)
            if isinstance(secret_value, (bytes, bytearray, memoryview))
            else bytes.fromhex(_normalise_hex(secret_value, 16, "channel secret"))
        )
    except (TypeError, ValueError):
        return "channel secret is not exactly 16 bytes"
    if len(secret) != 16:
        return "channel secret is not exactly 16 bytes"
    channel_hash = value.get("channel_hash")
    expected_hash = hashlib.sha256(secret).hexdigest()[:2]
    if channel_hash is not None and (
        not isinstance(channel_hash, str)
        or not hmac.compare_digest(channel_hash.lower(), expected_hash)
    ):
        return "channel hash does not match its secret"
    return None


def _validate_self_info(value: Any) -> Optional[str]:
    if not isinstance(value, Mapping):
        return "SELF_INFO payload was not an object"
    required = (
        "adv_type",
        "tx_power",
        "max_tx_power",
        "public_key",
        "adv_lat",
        "adv_lon",
        "multi_acks",
        "adv_loc_policy",
        "telemetry_mode_env",
        "telemetry_mode_loc",
        "telemetry_mode_base",
        "manual_add_contacts",
        "radio_freq",
        "radio_bw",
        "radio_sf",
        "radio_cr",
        "name",
    )
    missing = [field for field in required if field not in value]
    if missing:
        return f"SELF_INFO is missing fields: {', '.join(missing)}"
    try:
        _normalise_hex(value.get("public_key"), 32, "public key")
    except ValueError:
        return "SELF_INFO public key is invalid"
    if value["adv_type"] != 1:
        return "binary companion reported an unexpected advertisement role"
    for field in ("tx_power", "max_tx_power"):
        if not isinstance(value[field], int) or not 0 <= value[field] <= 255:
            return f"SELF_INFO {field} is invalid"
    if not isinstance(value["adv_lat"], (int, float)) or not -90 <= value["adv_lat"] <= 90:
        return "SELF_INFO latitude is invalid"
    if not isinstance(value["adv_lon"], (int, float)) or not -180 <= value["adv_lon"] <= 180:
        return "SELF_INFO longitude is invalid"
    for field in ("multi_acks", "adv_loc_policy", "telemetry_mode_env", "telemetry_mode_loc", "telemetry_mode_base"):
        if not isinstance(value[field], int) or not 0 <= value[field] <= 3:
            return f"SELF_INFO {field} is invalid"
    if not isinstance(value["manual_add_contacts"], bool):
        return "SELF_INFO manual_add_contacts is invalid"
    if not isinstance(value["radio_freq"], (int, float)) or not 100 <= value["radio_freq"] <= 3000:
        return "SELF_INFO radio frequency is invalid"
    if not isinstance(value["radio_bw"], (int, float)) or not 1 <= value["radio_bw"] <= 1000:
        return "SELF_INFO radio bandwidth is invalid"
    if not isinstance(value["radio_sf"], int) or not 5 <= value["radio_sf"] <= 12:
        return "SELF_INFO spreading factor is invalid"
    if not isinstance(value["radio_cr"], int) or not 5 <= value["radio_cr"] <= 8:
        return "SELF_INFO coding rate is invalid"
    name = value["name"]
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 32:
        return "SELF_INFO node name is invalid"
    return None


def _validate_device_info(value: Any) -> Optional[str]:
    if not isinstance(value, Mapping):
        return "DEVICE_INFO payload was not an object"
    required = ("fw ver", "max_contacts", "max_channels", "ble_pin", "fw_build", "model", "ver")
    missing = [field for field in required if field not in value]
    if missing:
        return f"DEVICE_INFO is missing fields: {', '.join(missing)}"
    protocol_version = value["fw ver"]
    if not isinstance(protocol_version, int) or protocol_version < 3:
        return "DEVICE_INFO protocol version is invalid or too old"
    if not isinstance(value["max_contacts"], int) or not 0 <= value["max_contacts"] <= 510:
        return "DEVICE_INFO max_contacts is invalid"
    if not isinstance(value["max_channels"], int) or not 0 <= value["max_channels"] <= 255:
        return "DEVICE_INFO max_channels is invalid"
    ble_pin = value["ble_pin"]
    if not isinstance(ble_pin, int) or not (ble_pin == 0 or 100000 <= ble_pin <= 999999):
        return "DEVICE_INFO BLE PIN is invalid"
    for field in ("fw_build", "model", "ver"):
        if not isinstance(value[field], str) or not value[field]:
            return f"DEVICE_INFO {field} is invalid"
    if protocol_version >= 9 and not isinstance(value.get("repeat"), bool):
        return "DEVICE_INFO repeat setting is missing or invalid"
    if protocol_version >= 10 and (
        not isinstance(value.get("path_hash_mode"), int)
        or not 0 <= value["path_hash_mode"] <= 3
    ):
        return "DEVICE_INFO path_hash_mode is missing or invalid"
    return None


def _safe_reason(value: Any) -> str:
    if isinstance(value, Mapping):
        value = value.get("reason", value.get("error", "command failed"))
    text = str(value or "command failed").replace("\r", " ").replace("\n", " ")
    return text[:240]


def _event_kind(event: Any) -> str:
    kind = getattr(event, "type", None)
    kind = getattr(kind, "value", kind)
    return str(kind or "").lower()


def _event_payload(event: Any) -> Any:
    return getattr(event, "payload", None)


def _event_attributes(event: Any) -> Any:
    return getattr(event, "attributes", None)


def _is_unsupported_event(event: Any) -> bool:
    if _event_kind(event) == "disabled":
        return False
    reason = _safe_reason(_event_payload(event)).lower()
    return "unsupported" in reason or "err_code_unsupported_cmd" in reason


def _section(
    state: str,
    *,
    required: bool,
    data: Any = None,
    reason: Optional[str] = None,
    restore_method: Optional[str] = None,
) -> dict[str, Any]:
    if state not in SECTION_STATES:
        raise ValueError(f"invalid section state: {state}")
    result: dict[str, Any] = {"state": state, "required": required}
    if data is not None:
        result["data"] = _json_safe(data)
    if reason:
        result["reason"] = reason
    if restore_method:
        result["restore_method"] = restore_method
    return result


def _event_section(
    event: Any,
    expected_kind: str,
    *,
    required: bool,
    restore_method: Optional[str] = None,
) -> dict[str, Any]:
    kind = _event_kind(event)
    if kind == expected_kind:
        result = _section(
            "complete",
            required=required,
            data=_event_payload(event),
            restore_method=restore_method,
        )
        attributes = _event_attributes(event)
        if isinstance(attributes, Mapping) and attributes:
            result["attributes"] = _json_safe(attributes)
        return result
    if kind == "disabled":
        return _section(
            "disabled",
            required=required,
            reason="firmware disabled this export",
            restore_method=restore_method,
        )
    if _is_unsupported_event(event):
        return _section(
            "unsupported",
            required=required,
            reason="firmware does not support this query",
            restore_method=restore_method,
        )
    return _section(
        "error",
        required=required,
        reason=_safe_reason(_event_payload(event) or f"unexpected response: {kind}"),
        restore_method=restore_method,
    )


async def _query_section(
    method: Callable[..., Awaitable[Any]],
    expected_kind: str,
    *,
    required: bool,
    restore_method: Optional[str] = None,
    args: tuple[Any, ...] = (),
) -> dict[str, Any]:
    try:
        event = await method(*args)
    except Exception as exc:  # a failed read must create a partial archive
        return _section(
            "error",
            required=required,
            reason=f"query failed: {type(exc).__name__}",
            restore_method=restore_method,
        )
    return _event_section(
        event, expected_kind, required=required, restore_method=restore_method
    )


def _public_key_from_self_info(section: Mapping[str, Any]) -> Optional[str]:
    if section.get("state") != "complete":
        return None
    data = section.get("data")
    if not isinstance(data, Mapping):
        return None
    try:
        return _normalise_hex(data.get("public_key"), 32, "public key")
    except ValueError:
        return None


def _role_from_adv_type(value: Any) -> str:
    # MeshCore advertisement type values are stable across the companion API.
    return {
        1: "companion",
        2: "repeater",
        3: "room-server",
        4: "sensor",
    }.get(value, "unknown")


async def collect_companion(client: Any, request: BackupRequest) -> dict[str, Any]:
    """Collect a structured snapshot through meshcore's high-level API."""

    commands = client.commands
    sections: dict[str, dict[str, Any]] = {}

    sections["self_info"] = await _query_section(
        commands.send_appstart,
        "self_info",
        required=True,
        restore_method="set_name/set_coords/set_tx_power/set_radio/set_other_params_from_infos",
    )
    public_key = _public_key_from_self_info(sections["self_info"])
    if not public_key:
        sections["self_info"] = _section(
            "error", required=True, reason="SELF_INFO did not contain a valid public key"
        )
    elif sections["self_info"].get("state") == "complete":
        validation_error = _validate_self_info(sections["self_info"].get("data"))
        if validation_error:
            sections["self_info"]["state"] = "error"
            sections["self_info"]["reason"] = validation_error

    if request.expected_public_key:
        expected = _normalise_hex(request.expected_public_key, 32, "expected public key")
        if not public_key or public_key != expected:
            raise BackupError(ExitCode.NODE_IDENTITY, "node public key did not match expectation")

    sections["device_info"] = await _query_section(
        commands.send_device_query, "device_info", required=True
    )
    device_data = sections["device_info"].get("data", {})
    if sections["device_info"].get("state") == "complete":
        validation_error = _validate_device_info(device_data)
        if validation_error:
            sections["device_info"]["state"] = "error"
            sections["device_info"]["reason"] = validation_error
    max_channels = device_data.get("max_channels") if isinstance(device_data, Mapping) else None

    private_section = await _query_section(
        commands.export_private_key,
        "private_key",
        required=True,
        restore_method="import_private_key",
    )
    if private_section.get("state") == "complete":
        private_data = private_section.get("data")
        try:
            if not isinstance(private_data, Mapping):
                raise ValueError("missing private-key response object")
            private_key = _normalise_hex(
                private_data.get("private_key"), 64, "private key"
            )
            private_section["data"] = {"private_key": private_key}
            derived_public_key = _derive_meshcore_public_key(private_key)
            if not public_key or not hmac.compare_digest(derived_public_key, public_key):
                private_section["state"] = "error"
                private_section["reason"] = (
                    "private key does not derive the public identity reported by SELF_INFO"
                )
        except ValueError as exc:
            private_section = _section("error", required=True, reason=str(exc))
    sections["identity_private_key"] = private_section

    contacts_section = await _query_section(
        commands.get_contacts,
        "contacts",
        required=True,
        restore_method="add_contact/update_contact",
    )
    if contacts_section.get("state") == "complete":
        contacts = contacts_section.get("data")
        validation_error = _validate_contact_records(contacts)
        if validation_error:
            contacts_section = _section(
                "error", required=True, data=contacts, reason=validation_error
            )
        else:
            received = len(contacts)
            declared = getattr(getattr(client, "_reader", None), "contact_nb", received)
            contacts_section["counts"] = {"declared": declared, "received": received}
            if not isinstance(declared, int) or declared != received:
                contacts_section["state"] = "error"
                contacts_section["reason"] = "contact stream count did not match terminator"
    sections["contacts"] = contacts_section

    if not isinstance(max_channels, int) or max_channels < 0 or max_channels > 255:
        sections["channels"] = _section(
            "error",
            required=True,
            reason="device did not report a valid max_channels value",
            restore_method="set_channel",
        )
    else:
        channel_rows: list[Any] = []
        channel_errors: list[dict[str, Any]] = []
        for index in range(max_channels):
            one = await _query_section(
                commands.get_channel,
                "channel_info",
                required=True,
                args=(index,),
                restore_method="set_channel",
            )
            if one.get("state") != "complete":
                channel_errors.append({"index": index, "state": one["state"], "reason": one.get("reason")})
                continue
            row = one.get("data")
            validation_error = _validate_channel_record(row, index)
            if validation_error:
                channel_errors.append(
                    {"index": index, "state": "error", "reason": validation_error}
                )
                continue
            channel_rows.append(row)
        sections["channels"] = _section(
            "complete" if not channel_errors and len(channel_rows) == max_channels else "error",
            required=True,
            data=channel_rows,
            reason="one or more channel records were not captured" if channel_errors else None,
            restore_method="set_channel",
        )
        sections["channels"]["counts"] = {
            "declared": max_channels,
            "received": len(channel_rows),
        }
        if channel_errors:
            sections["channels"]["errors"] = channel_errors

    api_queries = (
        ("battery_and_storage", "get_bat", "battery_info", None, False),
        ("autoadd", "get_autoadd_config", "autoadd_config", "set_autoadd_config", True),
        ("default_flood_scope", "get_default_flood_scope", "default_flood_scope", "set_default_flood_scope", True),
        ("tuning", "get_tuning", "tuning_params", "set_tuning", True),
        ("custom_vars", "get_custom_vars", "custom_vars", "set_custom_var", True),
    )
    for section_name, method_name, expected_kind, restore_method, required in api_queries:
        method = getattr(commands, method_name, None)
        if method is None:
            sections[section_name] = _section(
                "unsupported",
                required=required,
                reason=f"installed meshcore API lacks {method_name}",
                restore_method=restore_method,
            )
        else:
            sections[section_name] = await _query_section(
                method,
                expected_kind,
                required=required,
                restore_method=restore_method,
            )

    # Reuse the official framed CLI command API for persistent settings that
    # do not yet have dedicated structured getters. An unsupported command is
    # still returned as CLI_REPLY, so classify its text rather than treating
    # every reply as a successful capture.
    run_cli = getattr(commands, "run_cli_command", None)
    if run_cli is None:
        for section_name, command, restore_method in COMPANION_CLI_QUERIES:
            sections[section_name] = _section(
                "unsupported",
                required=False,
                reason="installed meshcore API lacks run_cli_command",
                restore_method=restore_method,
            )
    else:
        for section_name, command, restore_method in COMPANION_CLI_QUERIES:
            cli_section = await _query_section(
                run_cli,
                "cli_reply",
                required=False,
                args=(command,),
                restore_method=restore_method,
            )
            if cli_section.get("state") == "complete":
                cli_data = cli_section.get("data")
                text = cli_data.get("text") if isinstance(cli_data, Mapping) else None
                if not isinstance(text, str):
                    cli_section["state"] = "error"
                    cli_section["reason"] = "CLI reply did not contain text"
                else:
                    lower = text.strip().lower()
                    if "unknown command" in lower or "unsupported" in lower:
                        cli_section["state"] = "unsupported"
                        cli_section["reason"] = "firmware does not expose this setting"
                    elif lower.startswith("error") or lower.startswith("-> error"):
                        cli_section["state"] = "error"
                        cli_section["reason"] = "firmware reported an error for this setting"
            cli_section["command"] = command
            sections[section_name] = cli_section
        sections["storage_layout"]["diagnostic_scope"] = (
            "layout_only; this is not a filesystem consistency check"
        )

    storage_suspect = False
    battery_data = sections["battery_and_storage"].get("data", {})
    if isinstance(battery_data, Mapping):
        used_kb, total_kb = battery_data.get("used_kb"), battery_data.get("total_kb")
        if isinstance(used_kb, int) and isinstance(total_kb, int):
            storage_suspect = total_kb < 0 or used_kb < 0 or used_kb > total_kb
    if storage_suspect:
        sections["battery_and_storage"]["state"] = "error"
        sections["battery_and_storage"]["reason"] = "storage counters are internally inconsistent"

    final_identity = await _query_section(
        commands.send_appstart, "self_info", required=True
    )
    final_public_key = _public_key_from_self_info(final_identity)
    sections["identity_stability"] = _section(
        "complete" if public_key and final_public_key == public_key else "error",
        required=True,
        data={"stable": bool(public_key and final_public_key == public_key)},
        reason=(
            None
            if public_key and final_public_key == public_key
            else "public key changed or disappeared during backup"
        ),
    )
    if public_key and final_public_key and final_public_key != public_key:
        raise BackupError(ExitCode.NODE_IDENTITY, "node public key changed during backup")

    adv_type = None
    self_data = sections["self_info"].get("data")
    if isinstance(self_data, Mapping):
        adv_type = self_data.get("adv_type")
    detected_role = _role_from_adv_type(adv_type)
    return _build_payload(request, detected_role, public_key, sections, capture="companion-api")


TEXT_SETTINGS = (
    "get name",
    "get radio",
    "get lat",
    "get lon",
    "get tx",
    "get repeat",
    "get rxdelay",
    "get txdelay",
    "get af",
    "get multi.acks",
    "get advert.interval",
    "get flood.advert.interval",
    "get flood.max",
    "get flood.max.advert",
    "get flood.max.unscoped",
    "get flood.channel.data",
    "get allow.read.only",
    "get telemetry.access",
    "get system.watchdog",
    "get storage.layout",
)


async def _meshcore_cli_query(cli_module: Any, serial_port: Any, command: str) -> tuple[bool, str]:
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        ok = await cli_module.process_repeater_line(serial_port, command, echo=False)
    text = ANSI_RE.sub("", captured.getvalue()).replace("\r", "")
    lines = [line.rstrip() for line in text.splitlines() if line.strip() and line.strip() != command]
    return bool(ok), "\n".join(lines)


async def collect_text_cli(request: BackupRequest, cli_module: Any = None) -> dict[str, Any]:
    """Conservative backup for CommonCLI roles using meshcore-cli's helper.

    CommonCLI has no atomic bulk-export verb.  We preserve identity, settings,
    ACL, and region replies, but keep ``safe_for_wipe`` false because a changing
    firmware command surface cannot be proven complete from these text reads.
    """

    if cli_module is None:
        _require_package_version(
            "meshcore-cli", MIN_MESHCORE_CLI_VERSION, MAX_MESHCORE_CLI_VERSION
        )
        _require_package_version("PyNaCl", MIN_PYNACL_VERSION, MAX_PYNACL_VERSION)
        try:
            from meshcore_cli import meshcore_cli as cli_module  # type: ignore[no-redef]
        except (ImportError, ModuleNotFoundError) as exc:
            raise BackupError(ExitCode.DEPENDENCY, "meshcore-cli is not installed") from exc

    serial_port = await cli_module.setup_repeater_serial(request.port, request.baud)
    if serial_port is None:
        raise BackupError(ExitCode.UNSUPPORTED, "CommonCLI serial connection failed")
    try:
        replies: dict[str, dict[str, Any]] = {}
        for command in ("ver", "get role", "get public.key", "get prv.key", *TEXT_SETTINGS, "get acl", "region"):
            ok, text = await _meshcore_cli_query(cli_module, serial_port, command)
            replies[command] = {"ok": ok, "text": text}
        _, final_public_text = await _meshcore_cli_query(cli_module, serial_port, "get public.key")
    finally:
        with contextlib.suppress(Exception):
            serial_port.close()

    public_match = HEX_32_RE.search(replies["get public.key"]["text"])
    final_match = HEX_32_RE.search(final_public_text)
    public_key = public_match.group(0).lower() if public_match else None
    if not public_key:
        # A binary companion (and KISS firmware) can accept an opened serial
        # port yet never answer CommonCLI text.  Treat that as adapter failure
        # so create_backup() can try the companion API instead of mislabelling
        # the current node from a target-firmware hint.
        raise BackupError(ExitCode.UNSUPPORTED, "device did not answer as CommonCLI")
    if request.expected_public_key:
        expected = _normalise_hex(request.expected_public_key, 32, "expected public key")
        if public_key != expected:
            raise BackupError(ExitCode.NODE_IDENTITY, "node public key did not match expectation")
    if public_key and (not final_match or final_match.group(0).lower() != public_key):
        raise BackupError(ExitCode.NODE_IDENTITY, "node public key changed during backup")

    private_match = HEX_64_RE.search(replies["get prv.key"]["text"])
    private_key = private_match.group(0).lower() if private_match else None
    private_key_error = None
    if private_key:
        try:
            if not hmac.compare_digest(
                _derive_meshcore_public_key(private_key), public_key
            ):
                private_key_error = (
                    "private key does not derive the public identity reported by CommonCLI"
                )
        except ValueError as exc:
            private_key_error = str(exc)
    role_text = replies["get role"]["text"].lower()
    detected_role = "common-cli"
    for candidate in ("repeater", "room-server", "sensor"):
        if candidate.replace("-", " ") in role_text or candidate in role_text:
            detected_role = candidate
            break

    # Remove identity secrets from the generic command map; they live only in
    # their typed section below.
    public_reply = replies.pop("get public.key")
    replies.pop("get prv.key")
    settings = {key: value for key, value in replies.items() if key in TEXT_SETTINGS or key in ("ver", "get role")}
    sections = {
        "identity_public_key": _section(
            "complete" if public_key else "error",
            required=True,
            data={"public_key": public_key} if public_key else None,
            reason=None if public_key else "get public.key did not return a 32-byte key",
        ),
        "identity_private_key": _section(
            "complete" if private_key and not private_key_error else "error",
            required=True,
            data={"private_key": private_key} if private_key else None,
            reason=(
                private_key_error
                if private_key_error
                else None if private_key else "get prv.key did not return a 64-byte key"
            ),
            restore_method="set prv.key",
        ),
        "identity_stability": _section(
            "complete" if public_key and final_match and final_match.group(0).lower() == public_key else "error",
            required=True,
            data={"stable": bool(public_key and final_match and final_match.group(0).lower() == public_key)},
        ),
        "settings": _section("complete", required=True, data=settings),
        "acl": _section(
            "complete" if replies["get acl"]["ok"] else "error",
            required=detected_role in ("repeater", "room-server", "common-cli"),
            data={"raw": replies["get acl"]["text"]},
            restore_method="setperm",
        ),
        "regions": _section(
            "complete" if replies["region"]["ok"] else "error",
            required=detected_role in ("repeater", "room-server", "common-cli"),
            data={"raw": replies["region"]["text"]},
            restore_method="region load/region save",
        ),
        "contacts": _section("not_applicable", required=False, reason="not exposed by this role"),
        "channels": _section("not_applicable", required=False, reason="not exposed by this role"),
    }
    payload = _build_payload(request, detected_role, public_key, sections, capture="meshcore-cli-common-cli")
    payload["completeness"]["status"] = "partial"
    payload["completeness"]["safe_for_wipe"] = False
    payload["completeness"]["safe_for_restore"] = False
    payload["completeness"]["reasons"].append(
        "CommonCLI has no versioned bulk export, so unenumerated role-specific settings may be absent"
    )
    payload["source"]["public_key_query_ok"] = public_reply["ok"]
    return payload


def _build_payload(
    request: BackupRequest,
    detected_role: str,
    public_key: Optional[str],
    sections: dict[str, dict[str, Any]],
    *,
    capture: str,
) -> dict[str, Any]:
    missing_required = sorted(
        name
        for name, section in sections.items()
        if section.get("required") and section.get("state") != "complete"
    )
    optional_errors = sorted(
        name
        for name, section in sections.items()
        if not section.get("required") and section.get("state") == "error"
    )
    reasons = [f"required section incomplete: {name}" for name in missing_required]
    reasons.extend(f"optional query failed: {name}" for name in optional_errors)
    snapshot_complete = not missing_required and not optional_errors and bool(public_key)
    if not public_key and "identity public key unavailable" not in reasons:
        reasons.append("identity public key unavailable")
        snapshot_complete = False

    # This is a verified logical snapshot, not a raw filesystem image. The
    # current public API cannot non-destructively export unread messages or all
    # board-specific persisted preferences, and this tool intentionally has no
    # restore executor. Never let a successful API snapshot silently authorize
    # a destructive wipe.
    reasons.extend(
        (
            "unread messages are not exported because the available API consumes them",
            "the current MeshCore API does not expose every persisted role-specific setting",
            "automatic restore is not implemented",
        )
    )

    captured = [name for name, section in sections.items() if section.get("state") == "complete"]
    unavailable = [
        {"section": name, "state": section.get("state"), "reason": section.get("reason")}
        for name, section in sections.items()
        if section.get("state") != "complete"
    ]
    return {
        "source": {
            "transport": "usb-serial",
            "port_at_capture": request.port,
            "physical_usb_identity": request.physical_identity(),
            "node": {
                "public_key": public_key,
                "role": detected_role,
                "device_hint": request.device_hint,
            },
            "capture_api": capture,
        },
        "sections": sections,
        "excluded": {
            "messages": "excluded because reading the queue consumes unread messages",
            "logs": "runtime logs are not configuration and may contain unrelated data",
            "unexposed_preferences": (
                "the current USB API has no versioned export for every board-specific preference"
            ),
        },
        "completeness": {
            "status": "api-snapshot-complete" if snapshot_complete else "partial",
            "safe_for_wipe": False,
            "safe_for_restore": False,
            "missing_required": missing_required,
            "optional_errors": optional_errors,
            "reasons": reasons,
        },
        "restore_plan": {
            "executor_implemented": False,
            "requires_separate_explicit_confirmation": True,
            "requires_target_public_key_or_blank_identity_gate": True,
            "strategy": "role-aware MeshCore APIs and CommonCLI inverse operations",
            "ordered_sections": captured,
            "unavailable_sections": unavailable,
            "post_restore_verification": [
                "re-query public key and role",
                "re-query each restored section",
                "compare canonical nonvolatile values",
            ],
        },
    }


async def _default_companion_connector(request: BackupRequest) -> Any:
    _require_package_version(
        "meshcore", MIN_MESHCORE_VERSION, MAX_MESHCORE_VERSION
    )
    _require_package_version("PyNaCl", MIN_PYNACL_VERSION, MAX_PYNACL_VERSION)
    try:
        from meshcore import MeshCore
    except (ImportError, ModuleNotFoundError) as exc:
        raise BackupError(ExitCode.DEPENDENCY, "meshcore Python package is not installed") from exc
    try:
        client = await MeshCore.create_serial(
            port=request.port,
            baudrate=request.baud,
            default_timeout=request.timeout,
            only_error=True,
        )
    except Exception as exc:
        raise BackupError(
            ExitCode.UNSUPPORTED, f"MeshCore companion connection failed: {type(exc).__name__}"
        ) from exc
    if client is None:
        raise BackupError(ExitCode.UNSUPPORTED, "device did not answer as a companion")
    return client


def _has_stable_usb_identity(
    serial: Optional[str], location: Optional[str], parent: Optional[str]
) -> bool:
    return any(str(value or "").strip() for value in (serial, location, parent))


def _is_logging_usb_interface(interface: Optional[str], parent: Optional[str]) -> bool:
    interface_token = re.sub(r"[^a-z0-9]", "", str(interface or "").lower())
    if interface_token in {"2", "02", "if2", "if02", "mi2", "mi02"}:
        return True
    return bool(
        re.search(
            r"(?:^|[^a-z0-9])(?:if|mi)[_-]?0*2(?:$|[^a-z0-9])",
            str(parent or "").lower(),
        )
    )


def _validate_request(request: BackupRequest) -> None:
    if request.role_hint not in ROLE_CHOICES:
        raise BackupError(ExitCode.USAGE, "invalid role hint")
    if not request.port.strip():
        raise BackupError(ExitCode.USAGE, "serial port is required")
    if request.baud <= 0 or request.timeout <= 0:
        raise BackupError(ExitCode.USAGE, "baud and timeout must be positive")
    if not _has_stable_usb_identity(
        request.usb_serial, request.usb_location, request.usb_parent
    ):
        raise BackupError(
            ExitCode.USB_IDENTITY,
            "usb serial, location, or parent identity is required before reading secrets",
        )
    if _is_logging_usb_interface(request.usb_interface, request.usb_parent):
        raise BackupError(
            ExitCode.USB_IDENTITY,
            "refusing dual-USB logging interface 02; select the primary command interface",
        )
    if request.expected_public_key:
        try:
            _normalise_hex(request.expected_public_key, 32, "expected public key")
        except ValueError as exc:
            raise BackupError(ExitCode.USAGE, str(exc)) from exc


def _default_output_dir() -> Path:
    return Path.home() / ".meshfirmware" / "backups"


def _safe_filename_part(value: Optional[str], fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", value or "").strip(".-")
    return (text[:48] or fallback).lower()


def _choose_output_path(request: BackupRequest, payload: Mapping[str, Any]) -> Path:
    if request.output is not None:
        return request.output.expanduser().resolve()
    node = payload.get("source", {}).get("node", {})
    pubkey = node.get("public_key") if isinstance(node, Mapping) else None
    label = _safe_filename_part(request.device_hint, str(pubkey or "unknown")[:12])
    stamp = _datetime.datetime.now(_datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return (request.output_dir.expanduser() / f"meshcore-{stamp}-{label}.json").resolve()


def make_archive(payload: Mapping[str, Any]) -> dict[str, Any]:
    archive: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": ARCHIVE_KIND,
        "created_utc": _utc_now(),
        "tool": {
            "name": "meshcore_backup.py",
            "version": TOOL_VERSION,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "meshcore": _package_version("meshcore"),
            "meshcore_cli": _package_version("meshcore-cli"),
        },
        "payload": _json_safe(payload),
    }
    archive["integrity"] = {
        "algorithm": "sha256",
        "scope": "canonical-json-document-without-integrity",
        "sha256": _archive_digest(archive),
    }
    return archive


def validate_archive_data(
    archive: Any,
    *,
    require_safe_for_wipe: bool = False,
    expected_public_key: Optional[str] = None,
) -> dict[str, Any]:
    if not isinstance(archive, Mapping):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive root must be a JSON object")
    if archive.get("schema") != SCHEMA or archive.get("kind") != ARCHIVE_KIND:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive schema or kind is unsupported")
    integrity = archive.get("integrity")
    if (
        not isinstance(integrity, Mapping)
        or integrity.get("algorithm") != "sha256"
        or integrity.get("scope") != "canonical-json-document-without-integrity"
    ):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive integrity metadata is missing")
    expected_digest = integrity.get("sha256")
    actual_digest = _archive_digest(archive)
    if (
        not isinstance(expected_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
        or not hmac.compare_digest(expected_digest, actual_digest)
    ):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive digest mismatch")

    payload = archive.get("payload")
    if not isinstance(payload, Mapping):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive payload is missing")
    sections = payload.get("sections")
    completeness = payload.get("completeness")
    source = payload.get("source")
    restore_plan = payload.get("restore_plan")
    excluded = payload.get("excluded")
    if (
        not isinstance(sections, Mapping)
        or not isinstance(completeness, Mapping)
        or not isinstance(source, Mapping)
        or not isinstance(restore_plan, Mapping)
        or not isinstance(excluded, Mapping)
    ):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive payload structure is invalid")
    for name, section in sections.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(section, Mapping)
            or section.get("state") not in SECTION_STATES
            or type(section.get("required")) is not bool
        ):
            raise BackupError(ExitCode.ARCHIVE_INVALID, f"section metadata is invalid: {name}")

    capture_api = source.get("capture_api")
    role = None
    companion_required = {
        "self_info": True,
        "device_info": True,
        "identity_private_key": True,
        "contacts": True,
        "channels": True,
        "battery_and_storage": False,
        "autoadd": True,
        "default_flood_scope": True,
        "tuning": True,
        "custom_vars": True,
        "identity_stability": True,
        **{name: False for name, _, _ in COMPANION_CLI_QUERIES},
    }
    common_required = {
        "identity_public_key": True,
        "identity_private_key": True,
        "identity_stability": True,
        "settings": True,
        "contacts": False,
        "channels": False,
    }
    required_sections = (
        companion_required if capture_api == "companion-api" else common_required
    )
    if capture_api not in {"companion-api", "meshcore-cli-common-cli"}:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive capture API is invalid")
    missing_core = sorted(set(required_sections) - set(sections))
    if missing_core:
        raise BackupError(
            ExitCode.ARCHIVE_INVALID,
            f"archive is missing core sections: {', '.join(missing_core)}",
        )

    if source.get("transport") != "usb-serial" or not isinstance(
        source.get("port_at_capture"), str
    ) or not source["port_at_capture"].strip():
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive USB transport is invalid")
    physical_identity = source.get("physical_usb_identity")
    if not isinstance(physical_identity, Mapping):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive USB identity is missing")
    for field in ("serial", "location", "parent", "interface", "device_hint"):
        value = physical_identity.get(field)
        if value is not None and not isinstance(value, str):
            raise BackupError(ExitCode.ARCHIVE_INVALID, "archive USB identity is invalid")
    if not _has_stable_usb_identity(
        physical_identity.get("serial"),
        physical_identity.get("location"),
        physical_identity.get("parent"),
    ):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive USB identity is missing")
    if _is_logging_usb_interface(
        physical_identity.get("interface"), physical_identity.get("parent")
    ):
        raise BackupError(
            ExitCode.ARCHIVE_INVALID,
            "archive was captured through logging-only USB interface 02",
        )
    if physical_identity.get("attestation") != "caller-provided":
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive USB identity attestation is invalid")

    node = source.get("node")
    if not isinstance(node, Mapping):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive node identity is missing")
    try:
        public_key = _normalise_hex(
            node.get("public_key"), 32, "archive public key"
        )
    except ValueError as exc:
        raise BackupError(ExitCode.ARCHIVE_INVALID, str(exc)) from exc
    role = node.get("role")
    valid_roles = {
        "companion",
        "repeater",
        "room-server",
        "sensor",
        "kiss",
        "common-cli",
        "unknown",
    }
    if not isinstance(role, str) or role not in valid_roles:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive node role is invalid")
    if capture_api == "companion-api" and role != "companion":
        raise BackupError(ExitCode.ARCHIVE_INVALID, "companion archive role is inconsistent")
    if capture_api == "meshcore-cli-common-cli" and role not in {
        "repeater",
        "room-server",
        "sensor",
        "common-cli",
    }:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "CommonCLI archive role is inconsistent")

    if capture_api == "meshcore-cli-common-cli":
        common_required.update(
            {
                "acl": role in {"repeater", "room-server", "common-cli"},
                "regions": role in {"repeater", "room-server", "common-cli"},
            }
        )
        missing_common = sorted(set(common_required) - set(sections))
        if missing_common:
            raise BackupError(
                ExitCode.ARCHIVE_INVALID,
                f"archive is missing core sections: {', '.join(missing_common)}",
            )
        required_sections = common_required
    for name, expected_required in required_sections.items():
        if sections[name].get("required") is not expected_required:
            raise BackupError(
                ExitCode.ARCHIVE_INVALID,
                f"core section has an invalid required flag: {name}",
            )

    self_section = sections.get("self_info")
    if isinstance(self_section, Mapping):
        self_data = self_section.get("data")
        if not isinstance(self_data, Mapping):
            raise BackupError(ExitCode.ARCHIVE_INVALID, "SELF_INFO data is missing")
        try:
            self_public_key = _normalise_hex(
                self_data.get("public_key"), 32, "SELF_INFO public key"
            )
        except ValueError as exc:
            raise BackupError(ExitCode.ARCHIVE_INVALID, str(exc)) from exc
        if not hmac.compare_digest(self_public_key, public_key):
            raise BackupError(
                ExitCode.ARCHIVE_INVALID,
                "SELF_INFO public key does not match the archive node identity",
            )
        if self_section.get("state") == "complete":
            self_error = _validate_self_info(self_data)
            if self_error:
                raise BackupError(ExitCode.ARCHIVE_INVALID, self_error)

    public_section = sections.get("identity_public_key")
    if isinstance(public_section, Mapping):
        public_data = public_section.get("data")
        if public_section.get("state") != "complete" or not isinstance(
            public_data, Mapping
        ):
            raise BackupError(ExitCode.ARCHIVE_INVALID, "public-key section is incomplete")
        try:
            section_public_key = _normalise_hex(
                public_data.get("public_key"), 32, "identity public key"
            )
        except ValueError as exc:
            raise BackupError(ExitCode.ARCHIVE_INVALID, str(exc)) from exc
        if not hmac.compare_digest(section_public_key, public_key):
            raise BackupError(
                ExitCode.ARCHIVE_INVALID,
                "public-key section does not match the archive node identity",
            )

    stability_section = sections["identity_stability"]
    stability_data = stability_section.get("data")
    if (
        stability_section.get("state") != "complete"
        or not isinstance(stability_data, Mapping)
        or stability_data.get("stable") is not True
    ):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive node identity was not stable")

    device_section = sections.get("device_info")
    if isinstance(device_section, Mapping) and device_section.get("state") == "complete":
        device_error = _validate_device_info(device_section.get("data"))
        if device_error:
            raise BackupError(ExitCode.ARCHIVE_INVALID, device_error)

    def string_list(field: str) -> list[str]:
        value = completeness.get(field)
        if (
            not isinstance(value, list)
            or any(not isinstance(item, str) or not item for item in value)
            or len(set(value)) != len(value)
        ):
            raise BackupError(
                ExitCode.ARCHIVE_INVALID,
                f"archive completeness {field} is invalid",
            )
        return value

    recalculated_missing = sorted(
        name
        for name, section in sections.items()
        if section.get("required") and section.get("state") != "complete"
    )
    missing_required = string_list("missing_required")
    if sorted(missing_required) != recalculated_missing:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "completeness metadata is inconsistent")
    recalculated_optional_errors = sorted(
        name
        for name, section in sections.items()
        if not section.get("required") and section.get("state") == "error"
    )
    optional_errors = string_list("optional_errors")
    if sorted(optional_errors) != recalculated_optional_errors:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "optional-error metadata is inconsistent")
    reasons = string_list("reasons")
    expected_reasons = {
        *(f"required section incomplete: {name}" for name in recalculated_missing),
        *(f"optional query failed: {name}" for name in recalculated_optional_errors),
    }
    if not expected_reasons.issubset(reasons):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "completeness reasons are inconsistent")
    status = completeness.get("status")
    if status not in {"api-snapshot-complete", "partial"}:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive completeness status is invalid")
    expected_status = (
        "api-snapshot-complete"
        if capture_api == "companion-api"
        and not recalculated_missing
        and not recalculated_optional_errors
        else "partial"
    )
    if status != expected_status:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive completeness status is inconsistent")
    if completeness.get("safe_for_wipe") is not False or completeness.get(
        "safe_for_restore"
    ) is not False:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive safety metadata is invalid")
    if (
        restore_plan.get("executor_implemented") is not False
        or restore_plan.get("requires_separate_explicit_confirmation") is not True
        or restore_plan.get("requires_target_public_key_or_blank_identity_gate") is not True
    ):
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive restore plan is invalid")

    if expected_public_key:
        try:
            expected_key = _normalise_hex(expected_public_key, 32, "expected public key")
        except ValueError as exc:
            raise BackupError(ExitCode.USAGE, str(exc)) from exc
        if public_key != expected_key:
            raise BackupError(ExitCode.NODE_IDENTITY, "archive public key did not match expectation")

    private_section = sections.get("identity_private_key")
    if isinstance(private_section, Mapping) and private_section.get("state") == "complete":
        private_data = private_section.get("data")
        try:
            if not isinstance(private_data, Mapping):
                raise ValueError("complete private-key section has no data")
            private_key = _normalise_hex(
                private_data.get("private_key"), 64, "archive private key"
            )
            if not public_key or not hmac.compare_digest(
                _derive_meshcore_public_key(private_key), public_key
            ):
                raise ValueError("archive private key does not match its public identity")
        except ValueError as exc:
            raise BackupError(ExitCode.ARCHIVE_INVALID, str(exc)) from exc

    contacts_section = sections.get("contacts")
    if isinstance(contacts_section, Mapping) and contacts_section.get("state") == "complete":
        contact_error = _validate_contact_records(contacts_section.get("data"))
        if contact_error:
            raise BackupError(ExitCode.ARCHIVE_INVALID, contact_error)

    channels_section = sections.get("channels")
    if isinstance(channels_section, Mapping) and channels_section.get("state") == "complete":
        channels = channels_section.get("data")
        if not isinstance(channels, list):
            raise BackupError(ExitCode.ARCHIVE_INVALID, "archive channels are not a list")
        for index, channel in enumerate(channels):
            channel_error = _validate_channel_record(channel, index)
            if channel_error:
                raise BackupError(
                    ExitCode.ARCHIVE_INVALID,
                    f"archive channel {index} is invalid: {channel_error}",
                )

    for section_name in ("contacts", "channels"):
        section = sections[section_name]
        counts = section.get("counts")
        if section.get("state") == "complete" and not isinstance(counts, Mapping):
            raise BackupError(
                ExitCode.ARCHIVE_INVALID,
                f"complete {section_name} section has no counts",
            )
        if counts is None:
            continue
        if not isinstance(counts, Mapping):
            raise BackupError(ExitCode.ARCHIVE_INVALID, f"{section_name} counts are invalid")
        declared = counts.get("declared")
        received = counts.get("received")
        data = section.get("data")
        if (
            type(declared) is not int
            or type(received) is not int
            or declared < 0
            or received < 0
            or not isinstance(data, (Mapping, list))
            or received != len(data)
            or (section.get("state") == "complete" and declared != received)
        ):
            raise BackupError(ExitCode.ARCHIVE_INVALID, f"{section_name} counts are inconsistent")
        if (
            section_name == "channels"
            and isinstance(device_section, Mapping)
            and device_section.get("state") == "complete"
            and isinstance(device_section.get("data"), Mapping)
            and declared != device_section["data"].get("max_channels")
        ):
            raise BackupError(ExitCode.ARCHIVE_INVALID, "channel count does not match DEVICE_INFO")

    safe = False
    if require_safe_for_wipe:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "archive is valid but not safe for wipe")
    return {
        "sha256": actual_digest,
        "completeness": status,
        "safe_for_wipe": safe,
        "role": role,
        "public_key": public_key,
    }


def atomic_write_archive(path: Path, archive: Mapping[str, Any]) -> str:
    path = path.expanduser().resolve()
    if path.exists():
        raise BackupError(ExitCode.ARCHIVE_WRITE, "refusing to overwrite an existing backup")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BackupError(ExitCode.ARCHIVE_WRITE, "could not create backup directory") from exc

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = None
            json.dump(archive, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        with contextlib.suppress(OSError):
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        with temporary.open("r", encoding="utf-8") as handle:
            reread = json.load(handle)
        validate_archive_data(reread)
        # Publish by adding a second name for the completed inode. Unlike
        # os.replace(), this is atomic and fails if another process creates the
        # requested destination after our initial existence check.
        os.link(temporary, path)
        return _archive_digest(reread)
    except FileExistsError as exc:
        raise BackupError(
            ExitCode.ARCHIVE_WRITE, "refusing to overwrite an existing backup"
        ) from exc
    except BackupError:
        raise
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise BackupError(ExitCode.ARCHIVE_WRITE, "atomic backup write or verification failed") from exc
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()


async def create_backup(
    request: BackupRequest,
    *,
    companion_connector: Optional[Callable[[BackupRequest], Awaitable[Any]]] = None,
    text_cli_module: Any = None,
) -> BackupOutcome:
    _validate_request(request)
    connector = companion_connector or _default_companion_connector

    async def try_companion() -> dict[str, Any]:
        client = await connector(request)
        try:
            return await collect_companion(client, request)
        finally:
            with contextlib.suppress(Exception):
                await client.disconnect()

    async def try_text() -> dict[str, Any]:
        return await collect_text_cli(request, text_cli_module)

    # role_hint may describe the firmware about to be installed, not what is
    # currently attached.  It therefore changes probe order only; the current
    # node's responses determine the role recorded in the archive.
    probes = (
        (try_text, try_companion)
        if request.role_hint in ("repeater", "room-server", "sensor")
        else (try_companion, try_text)
    )
    first_error: Optional[BackupError] = None
    for probe in probes:
        try:
            payload = await probe()
            break
        except BackupError as exc:
            # Identity failures are hard gates, never a reason to probe the
            # same port through another protocol.
            if exc.code in (ExitCode.NODE_IDENTITY, ExitCode.USB_IDENTITY):
                raise
            if first_error is None:
                first_error = exc
    else:
        raise first_error or BackupError(ExitCode.UNSUPPORTED, "no supported MeshCore USB API responded")

    archive = make_archive(payload)
    path = _choose_output_path(request, payload)
    digest = atomic_write_archive(path, archive)
    completeness = payload["completeness"]
    node = payload["source"]["node"]
    return BackupOutcome(
        path=path,
        sha256=digest,
        completeness=completeness["status"],
        safe_for_wipe=bool(completeness["safe_for_wipe"]),
        role=node["role"],
        public_key=node.get("public_key"),
        reasons=tuple(str(reason) for reason in completeness.get("reasons", ())),
    )


def verify_archive_file(
    path: Path,
    *,
    require_safe_for_wipe: bool = False,
    expected_public_key: Optional[str] = None,
) -> dict[str, Any]:
    try:
        with path.expanduser().open("r", encoding="utf-8") as handle:
            archive = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError(ExitCode.ARCHIVE_INVALID, "backup file is unreadable or invalid JSON") from exc
    result = validate_archive_data(
        archive,
        require_safe_for_wipe=require_safe_for_wipe,
        expected_public_key=expected_public_key,
    )
    return {
        "ok": True,
        "exit_code": int(ExitCode.OK),
        "archive": str(path.expanduser().resolve()),
        "path": str(path.expanduser().resolve()),
        "sha256": result["sha256"],
        "completeness": result["completeness"],
        "safe_for_wipe": result["safe_for_wipe"],
        "role": result["role"],
        "node_key_prefix": result["public_key"][:12] if result["public_key"] else None,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup = subparsers.add_parser("backup", help="create a logical USB backup")
    backup.add_argument("--port", required=True)
    destination = backup.add_mutually_exclusive_group()
    destination.add_argument("--output", type=Path)
    destination.add_argument("--output-dir", type=Path, default=_default_output_dir())
    backup.add_argument("--baud", type=int, default=115200)
    backup.add_argument("--timeout", type=float, default=8.0)
    backup.add_argument("--role-hint", choices=ROLE_CHOICES, default="auto")
    backup.add_argument("--usb-serial")
    backup.add_argument("--usb-location")
    backup.add_argument("--usb-parent")
    backup.add_argument("--usb-interface")
    backup.add_argument("--device-hint")
    backup.add_argument("--expected-public-key")

    verify = subparsers.add_parser("verify", help="validate a backup without revealing secrets")
    verify.add_argument("--input", required=True, type=Path)
    verify.add_argument("--require-safe-for-wipe", action="store_true")
    verify.add_argument("--expected-public-key")

    subparsers.add_parser("version", help="print the helper/frontend contract version")
    return parser


def _error_summary(error: BackupError) -> dict[str, Any]:
    return {
        "ok": False,
        "exit_code": int(error.code),
        "error": error.reason,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _require_python_version()
        if args.command == "backup":
            output_dir = args.output_dir or _default_output_dir()
            request = BackupRequest(
                port=args.port,
                output_dir=output_dir,
                output=args.output,
                baud=args.baud,
                timeout=args.timeout,
                role_hint=args.role_hint,
                usb_serial=args.usb_serial,
                usb_location=args.usb_location,
                usb_parent=args.usb_parent,
                usb_interface=args.usb_interface,
                device_hint=args.device_hint,
                expected_public_key=args.expected_public_key,
            )
            outcome = asyncio.run(create_backup(request))
            print(json.dumps(outcome.public_summary(), sort_keys=True), flush=True)
            return int(outcome.exit_code)
        if args.command == "version":
            print(
                json.dumps(
                    {"ok": True, "schema": SCHEMA, "tool_version": TOOL_VERSION},
                    sort_keys=True,
                ),
                flush=True,
            )
            return int(ExitCode.OK)
        summary = verify_archive_file(
            args.input,
            require_safe_for_wipe=args.require_safe_for_wipe,
            expected_public_key=args.expected_public_key,
        )
        print(json.dumps(summary, sort_keys=True), flush=True)
        return int(ExitCode.OK)
    except BackupError as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True), flush=True)
        return int(exc.code)
    except KeyboardInterrupt:
        error = BackupError(ExitCode.UNSUPPORTED, "operation interrupted")
        print(json.dumps(_error_summary(error), sort_keys=True), flush=True)
        return int(error.code)


if __name__ == "__main__":
    raise SystemExit(main())
