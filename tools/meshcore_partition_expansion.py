#!/usr/bin/env python3
"""Plan and verify a release-pinned MeshCore ESP32 partition bridge.

This helper never opens a serial port or writes device flash. Its JSON output
contains public metadata only. The caller owns physical-device identity,
backups, bridge execution, uninterrupted-power guidance and ROM re-entry.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
import zlib


class ExpansionError(Exception):
    """A fail-closed plan/verification result safe to show to the user."""


REPOSITORY = "mikecarper/MeshCore"
PUBLISHED_USB_SET_URL = "https://github.com/mikecarper/MeshCore/releases/download/utility-usb-partition-v1-3d3d5827/meshcore-usb-partition-bridges.zip"
PUBLISHED_USB_SET_SHA256 = "187cac4f3f716d5df50e123a03ba51da637356874a434a72a60d9eb99d988ed8"
FORMAT = "meshcore-usb-partition-expansion-v2"
USB_BRIDGE_MARKER = b"MeshCore USB partition migration bridge v1"
USB_NVS_GUARD_MARKER = b"MeshCore USB NVS no-autoerase guard v1"
USB_PROFILES = {(0, 4 << 20), (0, 8 << 20), (5, 4 << 20),
                (9, 4 << 20), (9, 8 << 20), (9, 16 << 20)}
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
TABLE_SIZE = 0x1000
NVS_OFFSET, NVS_SIZE = 0x9000, 0x5000
OTA_OFFSET, OTA_SIZE = 0xE000, 0x2000
CHIP_NAMES = {0: "ESP32", 2: "ESP32-S2", 5: "ESP32-C3", 9: "ESP32-S3",
              12: "ESP32-C2", 13: "ESP32-C6", 16: "ESP32-H2", 18: "ESP32-P4",
              20: "ESP32-C61", 23: "ESP32-C5", 25: "ESP32-H21",
              28: "ESP32-H4", 31: "ESP32-E22", 32: "ESP32-S31"}
TARGET_LAYOUTS = {
    4 << 20: (0x1F0000, 0x200000, 0x3F0000, 0x10000),
    8 << 20: (0x330000, 0x340000, 0x670000, 0x180000),
    16 << 20: (0x640000, 0x650000, 0xC90000, 0x360000),
}

# Reviewed artifact keys from MeshCore's package_esp32_partition_migration.py.
# Exact target identity, not a board-name/flash-capacity guess, selects a ZIP.
# Canonical infrastructure targets only: single-slot Full Companions and C6
# boards do not have a reviewed preservation bridge in this release recipe.
CATALOG: dict[int, tuple[str, str]] = {}


def _catalog(board: str, target: str) -> None:
    target_id = int.from_bytes(hashlib.sha256(target.encode("ascii")).digest()[:4], "little")
    if target_id in CATALOG:
        raise RuntimeError("duplicate reviewed migration target")
    CATALOG[target_id] = (board, target)


for _board, _target in (
    ("heltec-v4", "heltec_v4_repeater"),
    ("xiao-s3-wio", "Xiao_S3_WIO_repeater"),
    ("station-g2-repeater", "Station_G2_repeater"),
    ("station-g2-room-server", "Station_G2_room_server"),
    ("t3s3-sx1262-repeater", "LilyGo_T3S3_sx1262_repeater"),
    ("t3s3-sx1262-room-server", "LilyGo_T3S3_sx1262_room_server"),
    ("t3s3-sx1276-repeater", "LilyGo_T3S3_sx1276_repeater"),
    ("t3s3-sx1276-room-server", "LilyGo_T3S3_sx1276_room_server"),
    ("thinknode-m2-repeater", "ThinkNode_M2_Repeater"),
    ("thinknode-m2-room-server", "ThinkNode_M2_room_server"),
    ("heltec-v4-expansionkit-repeater", "heltec_v4_expansionkit_repeater"),
    ("heltec-v4-room-server", "heltec_v4_room_server"),
    ("heltec-v4-sensor", "heltec_v4_sensor"),
    ("xiao-s3-wio-room-server", "Xiao_S3_WIO_room_server"),
    ("xiao-s3-wio-sensor", "Xiao_S3_WIO_sensor"),
    ("nibble-zero-repeater", "nibble_zero_connect_repeater_"),
    ("nibble-zero-room-server", "nibble_zero_connect_room_server_"),
    ("nibble-screen-repeater", "nibble_screen_connect_repeater_"),
    ("nibble-screen-room-server", "nibble_screen_connect_room_server_"),
    ("ebyte-eora-s3-repeater", "Ebyte_EoRa-S3_Repeater"),
    ("ebyte-eora-s3-room-server", "Ebyte_EoRa-S3_room_server"),
    ("thinknode-m5-repeater", "ThinkNode_M5_Repeater"),
    ("thinknode-m5-room-server", "ThinkNode_M5_room_server"),
    ("thinknode-m7-repeater", "ThinkNode_M7_repeater"),
    ("thinknode-m7-room-server", "ThinkNode_M7_room_server"),
    ("thinknode-m9-repeater", "ThinkNode_M9_repeater_"),
    ("thinknode-m9-room-server", "ThinkNode_M9_room_server_"),
    ("heltec-t190-repeater", "Heltec_T190_repeater_"),
    ("heltec-t190-room-server", "Heltec_T190_room_server_"),
    ("heltec-rc32-no-display-repeater", "heltec_rc32_without_display_repeater"),
    ("heltec-rc32-no-display-room-server", "heltec_rc32_without_display_room_server"),
    ("heltec-rc32-no-display-sensor", "heltec_rc32_without_display_sensor"),
    ("lilygo-tdeck-repeater", "LilyGo_TDeck_repeater"),
    ("lilygo-teth-elite-sx1262-repeater", "LilyGo_TETH_Elite_sx1262_repeater"),
    ("lilygo-teth-elite-sx1262-room-server", "LilyGo_TETH_Elite_sx1262_room_server"),
    ("t-beam-s3-supreme-sx1262-repeater", "T_Beam_S3_Supreme_SX1262_repeater"),
    ("t-beam-s3-supreme-sx1262-room-server", "T_Beam_S3_Supreme_SX1262_room_server"),
    ("station-g3-esp32-repeater", "Station_G3_ESP32_repeater"),
    ("station-g3-esp32-room-server", "Station_G3_ESP32_room_server"),
    ("station-g3-esp32-logging-repeater", "Station_G3_ESP32_logging_repeater"),
    ("station-g2-logging-repeater", "Station_G2_logging_repeater"),
    ("heltec-ct62-repeater", "Heltec_ct62_repeater"),
    ("heltec-ct62-sensor", "Heltec_ct62_sensor"),
    ("tenstar-c3-sx1262-repeater", "Tenstar_C3_sx1262_repeater"),
    ("tenstar-c3-sx1268-repeater", "Tenstar_C3_sx1268_repeater"),
    ("generic-e22-sx1262-repeater", "Generic_E22_sx1262_repeater"),
    ("generic-e22-sx1268-repeater", "Generic_E22_sx1268_repeater"),
):
    _catalog(_board, _target)

for _family, _stem, _roles in (
    ("heltec-wireless-tracker", "Heltec_Wireless_Tracker", ("repeater", "room_server")),
    ("heltec-wireless-paper", "Heltec_Wireless_Paper", ("repeater", "room_server")),
    ("heltec-tracker-v2", "heltec_tracker_v2", ("repeater", "room_server", "sensor")),
    ("heltec-v2", "Heltec_v2", ("repeater", "room_server")),
    ("heltec-v3", "Heltec_v3", ("repeater", "room_server", "sensor")),
    ("heltec-wsl3", "Heltec_WSL3", ("repeater", "room_server", "sensor")),
    ("xiao-s3", "Xiao_S3", ("repeater", "room_server", "sensor")),
    ("xiao-c3", "Xiao_C3", ("repeater", "room_server")),
    ("mke-s3", "MKE_s3", ("repeater", "room_server", "sensor")),
    ("rak-3112", "RAK_3112", ("repeater", "room_server", "sensor")),
    ("heltec-e213", "Heltec_E213", ("repeater", "room_server")),
    ("heltec-e290", "Heltec_E290", ("repeater", "room_server")),
    ("heltec-rc32", "heltec_rc32", ("repeater", "room_server", "sensor")),
    ("heltec-v4-tft", "heltec_v4_tft", ("repeater", "room_server", "sensor")),
    ("heltec-v4-r8", "heltec_v4_r8", ("repeater", "room_server", "sensor")),
    ("heltec-v4-r8-tft", "heltec_v4_r8_tft", ("repeater", "room_server", "sensor")),
    ("lilygo-tbeam-1w", "LilyGo_TBeam_1W", ("repeater", "room_server")),
    ("meshnology-w12", "meshnology_w12", ("repeater", "room_server", "sensor")),
):
    for _role in _roles:
        _catalog(f"{_family}-{_role.replace('_', '-')}", f"{_stem}_{_role}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def integer(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ExpansionError(f"Invalid {name} in partition expansion metadata.")
    return value


def safe_json(data: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ExpansionError("Duplicate key in partition expansion metadata.")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError):
        raise ExpansionError("Invalid partition expansion JSON metadata.") from None


def read_file(path: Path, limit: int = MAX_ARCHIVE_BYTES) -> bytes:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            raise ExpansionError("A required partition expansion input is missing or too large.")
        return path.read_bytes()
    except OSError:
        raise ExpansionError("Cannot read a required partition expansion input.") from None


def parse_table(data: bytes, flash_bytes: int) -> list[dict]:
    if len(data) != TABLE_SIZE:
        raise ExpansionError("Partition table must contain exactly 4096 bytes.")
    parts, names = [], set()
    for offset in range(0, TABLE_SIZE, 32):
        entry = data[offset:offset + 32]
        if entry[:2] == b"\xff\xff":
            if data[offset:] != b"\xff" * (TABLE_SIZE - offset):
                raise ExpansionError("Partition table has malformed trailing data.")
            break
        if entry[:2] == b"\xeb\xeb":
            if entry[2:16] != b"\xff" * 14 or entry[16:] != hashlib.md5(data[:offset]).digest():
                raise ExpansionError("Partition table MD5 verification failed.")
            if data[offset + 32:] != b"\xff" * (TABLE_SIZE - offset - 32):
                raise ExpansionError("Partition table has entries after its checksum.")
            break
        if entry[:2] != b"\xaa\x50":
            raise ExpansionError("Partition table has an invalid entry.")
        kind, subtype, address, size, name_raw, flags = struct.unpack_from("<BBII16sI", entry, 2)
        try:
            name = name_raw.split(b"\0", 1)[0].decode("ascii")
        except UnicodeError:
            raise ExpansionError("Partition table has an invalid label.") from None
        if (not name or name in names or not size or address < 0x9000
                or address % 0x1000 or size % 0x1000 or address + size > flash_bytes
                or flags & ~3 or (kind == 0 and address % 0x10000)):
            raise ExpansionError("Partition table contains invalid, duplicate or out-of-flash geometry.")
        names.add(name)
        parts.append({"name": name, "type": kind, "subtype": subtype,
                      "offset": address, "size": size, "flags": flags})
    if not parts:
        raise ExpansionError("Partition table is empty.")
    ordered = sorted(parts, key=lambda part: part["offset"])
    if any(left["offset"] + left["size"] > right["offset"]
           for left, right in zip(ordered, ordered[1:])):
        raise ExpansionError("Partition table contains overlapping partitions.")
    return parts


def canonical_table(flash_bytes: int) -> bytes:
    if flash_bytes not in TARGET_LAYOUTS:
        raise ExpansionError("Partition expansion supports reviewed 4, 8 or 16 MiB plans only.")
    slot, app1, fs_address, fs_size = TARGET_LAYOUTS[flash_bytes]
    entries = [("nvs", 1, 2, NVS_OFFSET, NVS_SIZE),
               ("otadata", 1, 0, OTA_OFFSET, OTA_SIZE),
               ("app0", 0, 0x10, 0x10000, slot),
               ("app1", 0, 0x11, app1, slot),
               ("spiffs", 1, 0x82, fs_address, fs_size)]
    if flash_bytes > 4 << 20:
        entries.append(("coredump", 1, 3, flash_bytes - 0x10000, 0x10000))
    body = b"".join(struct.pack("<2sBBII16sI", b"\xaa\x50", kind, subtype,
                                address, size, name.encode(), 0)
                    for name, kind, subtype, address, size in entries)
    body += b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(body).digest()
    return body.ljust(TABLE_SIZE, b"\xff")


def flash_identity(text: str) -> tuple[int, int]:
    sizes = re.findall(r"(?im)^\s*(?:Detected\s+)?Flash\s+size\s*:\s*(\d+)\s*(MB|MiB)\b", text)
    capacities = {int(number) << 20 for number, _unit in sizes}
    chips = re.findall(r"(?im)^\s*(?:Chip\s+(?:is|type\s*:)|Detecting\s+chip\s+type\s*\.\.\.)\s*(ESP32(?:-[A-Z0-9]+)?)\b", text)
    identities = {name.upper() for name in chips}
    # Classic ESP32 revisions are often shown as ESP32-D0WDQ6/ESP32-PICO-D4.
    identities = {"ESP32" if name.startswith(("ESP32-D", "ESP32-PICO", "ESP32-U")) else name
                  for name in identities}
    if len(capacities) != 1 or len(identities) != 1:
        raise ExpansionError("Physical ESP32 chip and flash capacity were not unambiguously detected.")
    flash_bytes, chip_name = capacities.pop(), identities.pop()
    reverse = {value: key for key, value in CHIP_NAMES.items()}
    if chip_name not in reverse:
        raise ExpansionError("This ESP32 chip family has no reviewed partition expansion bridge.")
    return flash_bytes, reverse[chip_name]


def image_header(image: bytes) -> tuple[int, int]:
    if (len(image) < 32 or image[0] != 0xE9 or not 1 <= image[1] <= 16
            or image[2] > 3 or image[23] not in (0, 1)):
        raise ExpansionError("Partition expansion requires a valid ESP32 application-only image.")
    chip = struct.unpack_from("<H", image, 12)[0]
    flash_code = image[3] >> 4
    if flash_code > 7:
        raise ExpansionError("ESP32 image declares an unsupported flash capacity.")
    return chip, 1 << (20 + flash_code)


def endf_identity(image: bytes) -> tuple[int, int, str]:
    if len(image) < 56:
        raise ExpansionError("Selected firmware has no verified MeshCore EndF identity.")
    trailer = image[-56:]
    if (trailer[:4] != b"EndF" or struct.unpack_from("<I", trailer, 4)[0] != len(image) - 56
            or trailer[8:16] != hashlib.sha256(image[:-56]).digest()[:8]):
        raise ExpansionError("Selected firmware has no verified MeshCore EndF identity.")
    version, target = struct.unpack_from("<II", trailer, 16)
    try:
        hardware = trailer[24:].rstrip(b"\0").decode("ascii")
    except UnicodeError:
        raise ExpansionError("MeshCore firmware hardware identity is invalid.") from None
    if not version or not target or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", hardware):
        raise ExpansionError("MeshCore firmware identity is missing or invalid.")
    return version, target, hardware


def release_identity(filename: str) -> tuple[str, str] | None:
    match = re.search(r"(?:^|[-_])(v\d+(?:\.\d+){2,3}-[A-Za-z0-9][A-Za-z0-9._-]*?)-([0-9a-f]{8,40})\.bin$", filename)
    return (match[1], match[2]) if match else None


def numeric_version(version: str) -> int:
    match = re.match(r"^v(\d+(?:\.\d+){2,3})(?:-|$)", version)
    if not match:
        raise ExpansionError("Migration firmware version is invalid.")
    numbers = [int(number) for number in match[1].split(".")]
    numbers += [0] * (4 - len(numbers))
    if any(number > 255 for number in numbers):
        raise ExpansionError("Migration firmware version is outside the EndF range.")
    return sum(number << shift for number, shift in zip(numbers, (24, 16, 8, 0)))


def download(url: str, limit: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "meshfirmware-partition-expansion", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if not response.geturl().startswith("https://"):
                raise ExpansionError("Migration download redirected to an insecure location.")
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ExpansionError("Migration download exceeded its permitted size.")
            return data
    except (urllib.error.URLError, OSError):
        raise ExpansionError("The exact release-matched migration package could not be downloaded.") from None


def resolve_package(version: str, source: str, board: str) -> tuple[bytes, str]:
    tag = f"utility-{version}-{source[:8]}"
    filename = f"{board}-{version}-{source[:8]}-migration.zip"
    release = safe_json(download(f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}", MAX_METADATA_BYTES))
    if not isinstance(release, dict) or release.get("tag_name") != tag or not isinstance(release.get("assets"), list):
        raise ExpansionError("Migration utility release metadata does not match the selected firmware.")
    assets = [item for item in release["assets"] if isinstance(item, dict) and item.get("name") == filename]
    if len(assets) != 1:
        raise ExpansionError("No exact board/role partition bridge is published for this firmware release.")
    asset = assets[0]
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{filename}"
    if asset.get("browser_download_url") != url or integer(asset.get("size"), "archive size") > MAX_ARCHIVE_BYTES:
        raise ExpansionError("Migration release asset metadata is invalid.")
    archive = download(url, MAX_ARCHIVE_BYTES)
    if len(archive) != asset["size"]:
        raise ExpansionError("Migration release asset download is incomplete.")
    return archive, url


def unpack_package(archive: bytes, *, usb_only: bool = False) -> tuple[dict, dict[str, bytes]]:
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise ExpansionError("Migration archive exceeds the permitted size.")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipper:
            infos = zipper.infolist()
            if not 4 <= len(infos) <= 32 or sum(info.file_size for info in infos) > MAX_ARCHIVE_BYTES:
                raise ExpansionError("Migration archive inventory or expanded size is invalid.")
            names, files = set(), {}
            for info in infos:
                name = info.filename
                if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name)
                        or PurePosixPath(name).name != name or name in names
                        or stat.S_ISLNK(info.external_attr >> 16) or info.flag_bits & 1
                        or info.file_size <= 0 or info.compress_size > MAX_ARCHIVE_BYTES):
                    raise ExpansionError("Migration archive has unsafe paths or invalid entries.")
                names.add(name)
                files[name] = zipper.read(info)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
        raise ExpansionError("Migration archive integrity verification failed.") from None
    if "manifest.json" not in files or len(files["manifest.json"]) > MAX_METADATA_BYTES:
        raise ExpansionError("Migration archive has no usable manifest.")
    manifest = safe_json(files["manifest.json"])
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        raise ExpansionError("Migration manifest file inventory is invalid.")
    inventory = manifest["files"]
    if set(files) != set(inventory) | {"manifest.json", "SHA256SUMS.txt"}:
        raise ExpansionError("Migration archive and manifest inventories differ.")
    for name, record in inventory.items():
        if (not isinstance(record, dict) or integer(record.get("bytes"), "file size") != len(files[name])
                or record.get("sha256") != digest(files[name])):
            raise ExpansionError("Migration archive file size or SHA-256 verification failed.")
    required = {"README.md"} if usb_only else {"wifi-bridge.bin", "target-partitions.bin", "full-application.bin", "capabilities.json"}
    if not required <= inventory.keys():
        raise ExpansionError("Migration archive is missing required application/bridge metadata.")
    expected_sums = {name: digest(data) for name, data in files.items() if name != "SHA256SUMS.txt"}
    actual_sums = {}
    try:
        for line in files["SHA256SUMS.txt"].decode("ascii").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
            if not match or match[2] in actual_sums:
                raise ExpansionError("Migration archive checksum inventory is invalid.")
            actual_sums[match[2]] = match[1]
    except UnicodeError:
        raise ExpansionError("Migration archive checksum inventory is invalid.") from None
    if actual_sums != expected_sums:
        raise ExpansionError("Migration archive checksum inventory does not match its files.")
    return manifest, files


def validate_usb_metadata(usb: dict, chip: int) -> bool:
    return (isinstance(usb, dict)
            and usb.get("automatic_rom_return") is (chip != 0)
            and usb.get("uart_completion_status") is (chip == 0)
            and usb.get("host_software_bootloader_entry") is True
            and usb.get("application_usb_cdc") is False)


def validate_usb_image(bridge: bytes, chip: int, flash_bytes: int) -> None:
    if USB_BRIDGE_MARKER not in bridge or USB_NVS_GUARD_MARKER not in bridge:
        raise ExpansionError("The USB migration bridge lacks its reviewed automatic-ROM runtime marker or NVS startup guard.")
    bridge_chip, bridge_flash = image_header(bridge)
    if bridge_chip != chip or bridge_flash != flash_bytes or len(bridge) > 0x140000:
        raise ExpansionError("Migration bridge has an incompatible chip, flash header or legacy size.")


def usb_bridge_from_archive(archive: bytes, chip: int, flash_bytes: int) -> tuple[bytes, dict]:
    manifest, files = unpack_package(archive, usb_only=True)
    if (manifest.get("format") != "meshcore-usb-partition-bridges-v1"
            or not isinstance(manifest.get("source_commit"), str)
            or not re.fullmatch(r"[0-9a-f]{8,40}", manifest["source_commit"])
            or not isinstance(manifest.get("working_tree_dirty"), bool)
            or not isinstance(manifest.get("source_tree_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", manifest["source_tree_sha256"])
            or not isinstance(manifest.get("bridges"), list)):
        raise ExpansionError("The standalone USB migration set has invalid source/format metadata.")
    profiles, names, selected = set(), set(), None
    for record in manifest["bridges"]:
        if not isinstance(record, dict):
            raise ExpansionError("The USB migration set profile metadata is invalid.")
        profile = (integer(record.get("chip"), "USB chip profile"),
                   integer(record.get("flash_bytes"), "USB flash profile"))
        name = record.get("file")
        if (profile not in USB_PROFILES or profile in profiles or name in names
                or name not in files or not validate_usb_metadata(record, profile[0])):
            raise ExpansionError("The USB migration set has missing, duplicate or incompatible profiles.")
        validate_usb_image(files[name], *profile)
        profiles.add(profile)
        names.add(name)
        if profile == (chip, flash_bytes):
            selected = files[name]
    if profiles != USB_PROFILES or set(files) != names | {"manifest.json", "SHA256SUMS.txt", "README.md"}:
        raise ExpansionError("The USB migration set must contain exactly the six reviewed chip/flash profiles.")
    if selected is None:
        raise ExpansionError("No compatible USB bridge exists in this migration set.")
    return selected, {"usb_set_sha256": digest(archive),
                      "usb_source_commit": manifest["source_commit"],
                      "usb_source_tree_sha256": manifest["source_tree_sha256"],
                      "usb_working_tree_dirty": manifest["working_tree_dirty"]}


def usb_bridge_from_set(path: Path, chip: int, flash_bytes: int) -> tuple[bytes, dict]:
    bridge, provenance = usb_bridge_from_archive(read_file(path), chip, flash_bytes)
    return bridge, {"usb_set_file": str(path.resolve()), **provenance}


def resolve_published_usb_set(directory: Path, chip: int, flash_bytes: int) -> tuple[bytes, dict]:
    """Fetch one qualified utility release, never GitHub's moving latest asset.

    Cached artifacts are SHA-256 checked again before every use. Validate the
    complete six-profile archive before caching any bytes; a local corrupt cache
    is rejected rather than used or silently replaced.
    """
    path = directory / "usb-sets" / PUBLISHED_USB_SET_SHA256 / "meshcore-usb-partition-bridges.zip"
    cached = path.exists()
    if cached:
        archive = read_file(path)
    else:
        try:
            archive = download(PUBLISHED_USB_SET_URL, MAX_ARCHIVE_BYTES)
        except ExpansionError:
            raise ExpansionError("The pinned USB migration set could not be downloaded. Set MESHFIRMWARE_USB_MIGRATION_SET to its local ZIP for offline use.") from None
    if digest(archive) != PUBLISHED_USB_SET_SHA256:
        raise ExpansionError("Published USB migration set SHA-256 verification failed; no bridge will be used.")
    bridge, provenance = usb_bridge_from_archive(archive, chip, flash_bytes)
    if not cached:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".usb-set-", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(archive)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return bridge, {"usb_set_url": PUBLISHED_USB_SET_URL,
                    "usb_set_file": str(path.resolve()), **provenance}


def validate_source(parts: list[dict], bridge_bytes: int) -> list[dict]:
    def one(kind: int, subtype: int) -> dict:
        candidates = [part for part in parts if part["type"] == kind and part["subtype"] == subtype]
        if len(candidates) != 1:
            raise ExpansionError("Source partition layout lacks unique required migration partitions.")
        return candidates[0]
    nvs, ota = one(1, 2), one(1, 0)
    one(1, 0x82)
    apps = sorted((part for part in parts if part["type"] == 0), key=lambda part: part["subtype"])
    if ((nvs["offset"], nvs["size"]) != (NVS_OFFSET, NVS_SIZE)
            or (ota["offset"], ota["size"]) != (OTA_OFFSET, OTA_SIZE)
            or [part["subtype"] for part in apps] != [0x10, 0x11]
            or any(part["flags"] for part in parts)
            or any(bridge_bytes > part["size"] for part in apps)):
        raise ExpansionError("Source layout cannot safely run the reviewed partition bridge.")
    # The Wi-Fi bridge must be capable of selecting/copying to future app0.
    # Its runtime uses source app0 as the future app0 boot slot descriptor.
    if apps[0]["offset"] != 0x10000:
        raise ExpansionError("Source OTA app0 does not begin at the reviewed future app0 address.")
    return apps


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".expansion-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def app_write_order(parts: list[dict], ota_path: Path | None) -> tuple[list[int], int, dict | None]:
    apps = [part for part in parts if part["type"] == 0]
    factories = [part for part in apps if part["subtype"] == 0]
    ota_apps = [part for part in apps if 0x10 <= part["subtype"] <= 0x1F]
    if (not apps or len(factories) > 1 or len({part["subtype"] for part in apps}) != len(apps)
            or len(apps) != len(factories) + len(ota_apps)):
        raise ExpansionError("ESP32 app layout is missing, duplicate or unsupported.")
    otas = [part for part in parts if part["type"] == 1 and part["subtype"] == 0]
    if ota_apps:
        if len(otas) != 1 or otas[0]["size"] < OTA_SIZE or ota_path is None:
            raise ExpansionError("An actual OTA metadata snapshot is required to safely order ESP32 writes.")
        active = active_ota_offset(parts, read_file(ota_path, OTA_SIZE))
        ota = otas[0]
    elif len(factories) == 1:
        active, ota = factories[0]["offset"], None
    else:
        raise ExpansionError("ESP32 layout has no supported bootable app slot.")
    ordered = sorted(apps, key=lambda part: part["subtype"])
    return [part["offset"] for part in ordered if part["offset"] != active] + [active], active, ota


def make_plan(firmware: Path, table_path: Path, flash_output: Path,
              output_dir: Path, package_path: Path | None = None,
              ota_path: Path | None = None, device_mac: str | None = None,
              nvs_path: Path | None = None, usb_set_path: Path | None = None) -> dict:
    image = read_file(firmware)
    table = read_file(table_path, TABLE_SIZE)
    try:
        flash_text = read_file(flash_output, MAX_METADATA_BYTES).decode("utf-8-sig")
    except UnicodeError:
        raise ExpansionError("ESP32 flash identification output is not valid text.") from None
    flash_bytes, rom_chip = flash_identity(flash_text)
    parts = parse_table(table, flash_bytes)
    chip, image_flash = image_header(image)
    if chip != rom_chip or image_flash > flash_bytes:
        raise ExpansionError("Selected application does not match the connected ESP32 chip/flash capacity.")
    app_slots = [part for part in parts if part["type"] == 0]
    app_offsets, active, ota = app_write_order(parts, ota_path)
    nvss = [part for part in parts if part["type"] == 1 and part["subtype"] == 2]
    if len(nvss) > 1:
        raise ExpansionError("ESP32 table has ambiguous NVS partitions for migration-state verification.")
    markers = {"namespace_exists": False, "namespace_empty": False, "cfg-restored": False,
               "cfg-pending": False, "id-pending": False}
    if nvss:
        if nvs_path is None:
            raise ExpansionError("An actual NVS snapshot is required to check for unfinished partition migration.")
        nvs_data = read_file(nvs_path)
        if len(nvs_data) != nvss[0]["size"]:
            raise ExpansionError("NVS snapshot size does not match its actual partition geometry.")
        markers = parse_nvs_markers(nvs_data, allow_missing=True, exact_size=False)
    normalized_mac = None
    if device_mac is not None:
        normalized_mac = re.sub(r"[:-]", "", device_mac).upper()
        if not re.fullmatch(r"[0-9A-F]{12}", normalized_mac):
            raise ExpansionError("The verified ESP32 device MAC is invalid.")
    firmware_hash = digest(image)
    output_dir = output_dir.resolve()
    plan_path = output_dir / firmware_hash / "plan.json"
    fits = all(len(image) <= part["size"] for part in app_slots)
    # The caller supplies a cache directory specific to the verified ROM MAC.
    # Merely preparing a plan does not create a blocking pending migration;
    # `begin` marks it immediately before the first actual bridge write.
    pending = []
    for candidate in output_dir.glob("*/plan.json"):
        existing = safe_json(read_file(candidate, MAX_METADATA_BYTES))
        if not isinstance(existing, dict) or existing.get("format") != FORMAT:
            raise ExpansionError("Device cache contains invalid partition expansion state.")
        if existing.get("started") is True and existing.get("completed") is not True:
            pending.append((candidate, existing))
    if pending:
        if len(pending) != 1:
            raise ExpansionError("Device has ambiguous pending partition expansion state.")
        candidate, existing = pending[0]
        if existing.get("firmware_sha256") != firmware_hash:
            raise ExpansionError("A partition expansion is pending; select its original exact firmware before updating another image.")
        if (existing.get("flash_bytes") != flash_bytes or existing.get("chip") != chip
                or (existing.get("device_mac") and existing.get("device_mac") != normalized_mac)):
            raise ExpansionError("Pending partition expansion belongs to another physical device.")
        table_hash = digest(table)
        if table_hash not in (existing.get("source_table_sha256"), existing.get("target_table_sha256")):
            raise ExpansionError("Pending partition expansion layout changed unexpectedly; recovery is required.")
        existing.update(ok=True, needed=True, resume=table_hash == existing.get("target_table_sha256"),
                        plan_file=str(candidate.resolve()), firmware_file=str(firmware.resolve()),
                        app_offsets=app_offsets, active_offset=active)
        atomic_json(candidate, existing)
        return existing
    if fits:
        if (markers["cfg-pending"] or markers["id-pending"]
                or (markers["namespace_exists"] and not markers["namespace_empty"]
                    and not markers["cfg-restored"])):
            raise ExpansionError("Live NVS reports unfinished partition migration; restore the original bridge handoff before final flashing.")
        return {"ok": True, "needed": False, "firmware_sha256": firmware_hash,
                "flash_bytes": flash_bytes, "app_bytes": len(image),
                "app_offsets": app_offsets, "active_offset": active,
                "ota_offset": ota["offset"] if ota else None,
                "ota_size": OTA_SIZE if ota else None,
                "nvs_offset": nvss[0]["offset"] if nvss else None,
                "nvs_size": nvss[0]["size"] if nvss else None,
                "nvs_migration": markers}
    if flash_bytes not in TARGET_LAYOUTS:
        raise ExpansionError("No reviewed partition expansion plan exists for this physical flash size.")
    if chip not in (0, 5, 9):
        raise ExpansionError("This ESP32 chip family has no reviewed partition expansion bridge.")
    version_number, target_id, hardware_id = endf_identity(image)
    selected_release = release_identity(firmware.name)
    catalog = CATALOG.get(target_id)
    if catalog is None:
        raise ExpansionError("No reviewed partition expansion package exists for this exact hardware/role.")
    board, target = catalog
    if package_path is not None:
        archive, artifact = read_file(package_path), str(package_path.resolve())
    else:
        if selected_release is None:
            raise ExpansionError("Cannot determine the exact firmware release; supply its matching migration ZIP.")
        archive, artifact = resolve_package(*selected_release, board)
    manifest, files = unpack_package(archive)
    release_version, source = manifest.get("firmware_version"), manifest.get("source_commit")
    if (not isinstance(release_version, str) or not isinstance(source, str)
            or not re.fullmatch(r"[0-9a-f]{8,40}", source)
            or numeric_version(release_version) != version_number
            or (selected_release is not None and (release_version != selected_release[0]
                                                  or source[:8] != selected_release[1][:8]))
            or manifest.get("board") != board or manifest.get("target") != target
            or manifest.get("hardware_id") != hardware_id
            or manifest.get("target_id") != f"0x{target_id:08x}"
            or manifest.get("role") not in ("repeater", "room-server", "sensor")
            or integer(manifest.get("flash_bytes"), "physical flash capacity") != flash_bytes
            or manifest.get("atomic_power_loss_recovery") is not False
            or integer(manifest.get("legacy_slot_bytes"), "legacy slot size") != 0x140000
            or manifest.get("files", {}).get("full-application.bin", {}).get("sha256") != firmware_hash
            or files["full-application.bin"] != image):
        raise ExpansionError("Migration package does not match the exact selected firmware, target or release.")
    expected_table = canonical_table(flash_bytes)
    if files["target-partitions.bin"] != expected_table:
        raise ExpansionError("Migration target partition table does not match the reviewed expansion plan.")
    target_parts = parse_table(expected_table, flash_bytes)
    target_apps = [part for part in target_parts if part["type"] == 0]
    if (integer(manifest.get("expanded_slot_bytes"), "expanded slot size") != target_apps[0]["size"]
            or any(len(image) > part["size"] for part in target_apps)):
        raise ExpansionError("Selected firmware does not fit the reviewed expanded OTA slots.")
    caps = safe_json(files["capabilities.json"])
    if (not isinstance(caps, dict) or caps.get("target") != target
            or caps.get("build_profile") != "full" or caps.get("platform") != "ESP32_PLATFORM"
            or caps.get("ota_update_verified") is not True):
        raise ExpansionError("Migration package Full application qualification does not match its target.")
    usb_provenance = {}
    if usb_set_path is not None:
        bridge, usb_provenance = usb_bridge_from_set(usb_set_path, chip, flash_bytes)
    elif "usb_migration" not in manifest and "usb-bridge.bin" not in files:
        # An older exact Full package can use a separately qualified USB set.
        # Malformed/partially present embedded USB metadata must still fail.
        bridge, usb_provenance = resolve_published_usb_set(output_dir, chip, flash_bytes)
    else:
        usb = manifest.get("usb_migration")
        if (not validate_usb_metadata(usb, chip)
                or usb.get("format") != "meshcore-usb-partition-migration-v1"
                or usb.get("bridge") != "usb-bridge.bin"
                or "usb-bridge.bin" not in files):
            raise ExpansionError("This package has no verified USB-safe migration bridge. Obtain its USB migration release or set MESHFIRMWARE_USB_MIGRATION_SET; the Wi-Fi bridge can require physical BOOT access and will not be substituted.")
        bridge = files["usb-bridge.bin"]
        validate_usb_image(bridge, chip, flash_bytes)
    source_apps = validate_source(parts, len(bridge))
    if table == expected_table:
        raise ExpansionError("Already-expanded layout cannot be expanded further for this firmware.")
    directory = plan_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    bridge_path, target_path = directory / "usb-bridge.bin", directory / "target-partitions.bin"
    # Only fully validated public artifacts are extracted. No device data is
    # ever written into this cache by the helper.
    bridge_path.write_bytes(bridge)
    target_path.write_bytes(expected_table)
    result = {"format": FORMAT, "ok": True, "needed": True, "resume": False,
              "started": False, "completed": False, "verified": False,
              "plan_file": str(plan_path), "artifact": artifact, "device_mac": normalized_mac,
              "artifact_sha256": digest(archive), "board": board, "target": target,
              "hardware_id": hardware_id, "target_id": target_id,
              "firmware_version": release_version, "source_commit": source,
              "firmware_file": str(firmware.resolve()), "firmware_sha256": firmware_hash,
              "firmware_bytes": len(image), "flash_bytes": flash_bytes, "chip": chip,
              "bridge_file": str(bridge_path), "bridge_bytes": len(bridge),
              "bridge_sha256": digest(bridge), "bridge_offsets": app_offsets,
              "usb_safe": True, "automatic_rom_return": chip != 0,
              "uart_completion_status": chip == 0,
              "host_software_bootloader_entry": True, "application_usb_cdc": False,
              "app_offsets": app_offsets, "active_offset": active,
              "target_table_file": str(target_path), "target_table_sha256": digest(expected_table),
              "source_table_sha256": digest(table), "nvs_offset": NVS_OFFSET, "nvs_size": NVS_SIZE,
              "ota_offset": OTA_OFFSET, "ota_size": OTA_SIZE,
              "atomic_power_loss_recovery": False}
    result.update(usb_provenance)
    atomic_json(plan_path, result)
    return result


def parse_nvs_markers(data: bytes, *, allow_missing: bool = False,
                      exact_size: bool = True) -> dict[str, bool]:
    """Read live primitive flags, never return blobs or other private data.

    See ESP-IDF nvs_partition_tool/nvs_parser.py: CRC32 seed FFFFFFFF,
    header excludes page state, and erased records retain bytes but are not
    authoritative. Children of blob/string records must not be parsed as keys.
    """
    if exact_size and len(data) != NVS_SIZE:
        raise ExpansionError("Migration NVS read must contain exactly 20480 bytes.")
    if not data or len(data) % 4096:
        raise ExpansionError("NVS snapshot must contain complete flash sectors.")
    absent = {"namespace_exists": False, "namespace_empty": False, "cfg-restored": False,
              "cfg-pending": False, "id-pending": False}
    pages = []
    for offset in range(0, len(data), 4096):
        page = data[offset:offset + 4096]
        if page == b"\xff" * 4096:
            continue
        state, sequence = struct.unpack_from("<II", page)
        crc = struct.unpack_from("<I", page, 28)[0]
        if (state not in (0xFFFFFFFE, 0xFFFFFFFC) or page[8] not in (0xFF, 0xFE)
                or page[9:28] != b"\xff" * 19
                or crc != zlib.crc32(page[4:28], 0xFFFFFFFF) & 0xFFFFFFFF):
            raise ExpansionError("Migration NVS page verification failed or requires recovery.")
        pages.append((sequence, page))
    if not pages and allow_missing:
        return absent
    if not pages or len({sequence for sequence, _page in pages}) != len(pages):
        raise ExpansionError("Migration NVS has missing or ambiguous page ordering.")
    if sum(struct.unpack_from("<I", page)[0] == 0xFFFFFFFE for _seq, page in pages) > 1:
        raise ExpansionError("Migration NVS has multiple active pages and requires recovery.")
    oldest = next((seq for seq, _page in pages
                   if all(((other - seq) & 0xFFFFFFFF) < 0x80000000 for other, _ in pages)), None)
    if oldest is None:
        raise ExpansionError("Migration NVS sequence ordering is ambiguous.")
    pages.sort(key=lambda item: (item[0] - oldest) & 0xFFFFFFFF)
    records: dict[tuple[int, str], tuple[int, bytes]] = {}
    primitive_types = {1, 2, 4, 8, 0x11, 0x12, 0x14, 0x18}
    for _sequence, page in pages:
        bitmap = int.from_bytes(page[32:64], "little")
        index = 0
        while index < 126:
            entry_state = (bitmap >> (2 * index)) & 3
            entry = page[64 + 32 * index:96 + 32 * index]
            if entry_state in (0, 3):
                index += 1
                continue
            if entry_state != 2:
                raise ExpansionError("Migration NVS contains an invalid entry state.")
            namespace, kind, span, chunk = entry[:4]
            stored_crc = struct.unpack_from("<I", entry, 4)[0]
            if stored_crc != zlib.crc32(entry[:4] + entry[8:], 0xFFFFFFFF) & 0xFFFFFFFF:
                raise ExpansionError("Migration NVS entry CRC verification failed.")
            key_raw = entry[8:24]
            try:
                key = key_raw.split(b"\0", 1)[0].decode("ascii")
            except UnicodeError:
                raise ExpansionError("Migration NVS contains an invalid key.") from None
            if (b"\0" not in key_raw or not key or not 1 <= span <= 126 - index
                    or kind not in primitive_types | {0x21, 0x41, 0x42, 0x48}):
                raise ExpansionError("Migration NVS entry format is invalid or unsupported.")
            if kind in primitive_types | {0x48}:
                if span != 1 or chunk != 0xFF:
                    raise ExpansionError("Migration NVS primitive entry geometry is invalid.")
                records[(namespace, key)] = (kind, entry[24:32])
            else:
                size = struct.unpack_from("<H", entry, 24)[0]
                if (span < 2 or size > (span - 1) * 32
                        or any(((bitmap >> (2 * child)) & 3) != 2
                               for child in range(index + 1, index + span))):
                    raise ExpansionError("Migration NVS variable-length entry is incomplete.")
                body = page[64 + 32 * (index + 1):64 + 32 * (index + span)][:size]
                if struct.unpack_from("<I", entry, 28)[0] != zlib.crc32(body, 0xFFFFFFFF) & 0xFFFFFFFF:
                    raise ExpansionError("Migration NVS data CRC verification failed.")
                # A newer live key of another type supersedes an older bool
                # too. Ignoring variable-length keys could trust a stale true
                # marker during an interrupted type-changing update.
                records[(namespace, key)] = (kind, entry[24:32])
            index += span
    namespace_record = records.get((0, "mesh-pt-migrate"))
    if namespace_record is None and allow_missing:
        return absent
    if namespace_record is None or namespace_record[0] != 1 or not 1 <= namespace_record[1][0] <= 254:
        raise ExpansionError("No verified partition migration NVS namespace exists.")
    namespace = namespace_record[1][0]
    if any(key != "mesh-pt-migrate" and kind == 1 and raw[0] == namespace
           for (ns, key), (kind, raw) in records.items() if ns == 0):
        raise ExpansionError("Partition migration NVS namespace identity is ambiguous.")
    # Old application identity probes opened this namespace read/write even
    # before a migration, creating a legitimate empty namespace. A bridge must
    # commit staged identity/pending state before publishing a partition table.
    # Only zero validated live keys are harmless: false completion flags,
    # pending flags, staged blobs and unknown keys all make it nonempty.
    markers = {"namespace_exists": True,
               "namespace_empty": not any(ns == namespace for ns, _key in records)}
    for key in ("cfg-restored", "cfg-pending", "id-pending"):
        item = records.get((namespace, key))
        if item is not None and (item[0] != 1 or item[1][0] not in (0, 1)):
            raise ExpansionError("Partition migration NVS completion flag has an invalid type/value.")
        markers[key] = bool(item[1][0]) if item is not None else False
    return markers


def active_ota_offset(parts: list[dict], data: bytes) -> int:
    if len(data) != OTA_SIZE:
        raise ExpansionError("OTA metadata read must contain exactly 8192 bytes.")
    apps = sorted((part for part in parts if part["type"] == 0 and 0x10 <= part["subtype"] <= 0x1F),
                  key=lambda part: part["subtype"])
    if not apps or [part["subtype"] for part in apps] != list(range(0x10, 0x10 + len(apps))):
        raise ExpansionError("OTA table does not have unique contiguous OTA slot identities.")
    sequences = []
    for offset in (0, 0x1000):
        entry = data[offset:offset + 32]
        sequence = struct.unpack_from("<I", entry)[0]
        state, crc = struct.unpack_from("<II", entry, 24)
        expected = zlib.crc32(struct.pack("<I", sequence), 0xFFFFFFFF) & 0xFFFFFFFF
        if sequence not in (0, 0xFFFFFFFF) and crc == expected and state not in (3, 4):
            sequences.append(sequence)
    if not sequences:
        # Erased initial otadata without a factory partition boots ota_0.
        if data[:32] != b"\xff" * 32 or data[4096:4128] != b"\xff" * 32:
            raise ExpansionError("OTA metadata has no valid active sequence and is not erased initial data.")
        factory = next((part for part in parts if part["type"] == 0 and part["subtype"] == 0), None)
        return factory["offset"] if factory else apps[0]["offset"]
    newest = sequences[0]
    for sequence in sequences[1:]:
        delta = (sequence - newest) & 0xFFFFFFFF
        if delta == 0x80000000:
            raise ExpansionError("OTA active sequence ordering is ambiguous.")
        if 0 < delta < 0x80000000:
            newest = sequence
    return apps[(newest - 1) % len(apps)]["offset"]


def begin_plan(plan_path: Path) -> dict:
    plan = safe_json(read_file(plan_path, MAX_METADATA_BYTES))
    if (not isinstance(plan, dict) or plan.get("format") != FORMAT
            or plan.get("needed") is not True or plan.get("completed") is True):
        raise ExpansionError("A valid uncompleted partition expansion plan is required before bridge flashing.")
    if (digest(read_file(Path(plan.get("firmware_file", "")))) != plan.get("firmware_sha256")
            or digest(read_file(Path(plan.get("bridge_file", "")))) != plan.get("bridge_sha256")
            or digest(read_file(Path(plan.get("target_table_file", "")), TABLE_SIZE)) != plan.get("target_table_sha256")):
        raise ExpansionError("Partition expansion artifacts changed before the bridge write.")
    if plan.get("usb_safe") is not True or not validate_usb_metadata(plan, plan.get("chip")):
        raise ExpansionError("The cached partition expansion is not a reviewed USB-safe plan.")
    validate_usb_image(read_file(Path(plan["bridge_file"])), plan["chip"], plan["flash_bytes"])
    plan["started"] = True
    atomic_json(plan_path, plan)
    return {"ok": True, "started": True, "plan_file": str(plan_path.resolve())}


def verify_plan(plan_path: Path, table_path: Path, nvs_path: Path, ota_path: Path) -> dict:
    plan = safe_json(read_file(plan_path, MAX_METADATA_BYTES))
    if (not isinstance(plan, dict) or plan.get("format") != FORMAT
            or plan.get("needed") is not True or plan.get("started") is not True):
        raise ExpansionError("A valid pending partition expansion plan is required.")
    flash_bytes = integer(plan.get("flash_bytes"), "physical flash capacity")
    expected = canonical_table(flash_bytes)
    table = read_file(table_path, TABLE_SIZE)
    if (table != expected or digest(table) != plan.get("target_table_sha256")
            or read_file(Path(plan.get("target_table_file", "")), TABLE_SIZE) != expected):
        raise ExpansionError("Expanded partition table has not been verified against the exact bridge plan.")
    image = read_file(Path(plan.get("firmware_file", "")))
    bridge = read_file(Path(plan.get("bridge_file", "")))
    if digest(image) != plan.get("firmware_sha256") or len(image) != plan.get("firmware_bytes"):
        raise ExpansionError("Selected final firmware changed after the expansion plan was prepared.")
    if digest(bridge) != plan.get("bridge_sha256") or len(bridge) != plan.get("bridge_bytes"):
        raise ExpansionError("Partition expansion bridge changed after the plan was prepared.")
    validate_usb_image(bridge, integer(plan.get("chip"), "USB chip profile"), flash_bytes)
    if (plan.get("nvs_offset"), plan.get("nvs_size"), plan.get("ota_offset"), plan.get("ota_size")) != (NVS_OFFSET, NVS_SIZE, OTA_OFFSET, OTA_SIZE):
        raise ExpansionError("Partition expansion metadata offsets are not the reviewed stable locations.")
    parts = parse_table(table, flash_bytes)
    markers = parse_nvs_markers(read_file(nvs_path, NVS_SIZE))
    if not markers["cfg-restored"] or markers["cfg-pending"] or markers["id-pending"]:
        raise ExpansionError("Partition bridge has not finished verified identity/configuration restoration; final flashing is refused.")
    active = active_ota_offset(parts, read_file(ota_path, OTA_SIZE))
    apps = sorted((part for part in parts if part["type"] == 0), key=lambda part: part["subtype"])
    if any(len(image) > part["size"] for part in apps):
        raise ExpansionError("Selected firmware does not fit the verified expanded OTA layout.")
    offsets = [part["offset"] for part in apps if part["offset"] != active] + [active]
    plan["verified"] = True
    plan["completed"] = True
    atomic_json(plan_path, plan)
    return {"ok": True, "verified": True, "target": plan.get("target"),
            "firmware_sha256": plan["firmware_sha256"], "flash_bytes": flash_bytes,
            "app_offsets": offsets, "active_offset": active,
            "identity_restored": True, "configuration_restored": True}


def uart_serial_module():
    try:
        import serial
    except ImportError:
        raise ExpansionError("USB-UART migration requires pyserial in the selected Python environment.") from None
    if not callable(getattr(serial, "Serial", None)):
        raise ExpansionError("The selected Python environment has no usable pyserial API.")
    return serial


def wait_uart_bridge(port: str, device_mac: str, timeout: float = 180) -> dict:
    """Await a settled classic-ESP32 bridge before any host-driven reset.

    This public status is only permission to enter ROM. Exact raw table/NVS
    restoration verification is still mandatory afterwards. Never print a
    line from the serial stream, which may contain unrelated private data.
    """
    expected = re.sub(r"[:-]", "", device_mac).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", expected) or not 0 < timeout <= 600:
        raise ExpansionError("Invalid UART migration wait identity or timeout.")
    serial = uart_serial_module()
    stream = serial.Serial(port=None, baudrate=115200, timeout=0.5, write_timeout=1)
    try:
        # Do not assert control lines or run esptool reset while restoration
        # is in progress. Classic ESP32 has an external USB-UART, not USB CDC.
        stream.dtr = False
        stream.rts = False
        stream.port = port
        stream.open()
        deadline = time.monotonic() + timeout
        pending = bytearray()
        prefix = b"MESHCORE_USB_MIGRATION_STATE "
        while time.monotonic() < deadline:
            for byte in stream.read(256):
                if byte == 10:
                    line = bytes(pending).rstrip(b"\r")
                    pending.clear()
                    if not line.startswith(prefix):
                        continue
                    try:
                        state = safe_json(line[len(prefix):])
                    except ExpansionError:
                        continue
                    if not isinstance(state, dict) or state.get("format") != "meshcore-usb-partition-migration-v1":
                        continue
                    if not isinstance(state.get("device_mac"), str) or state["device_mac"].upper() != expected:
                        raise ExpansionError("The UART migration bridge reported a different chip MAC; refusing reset or final write.")
                    if state.get("settled") is True and isinstance(state.get("restored"), bool):
                        return {"ok": True, "settled": True, "restored": state["restored"],
                                "device_mac": expected}
                elif len(pending) < 4096:
                    pending.append(byte)
                else:
                    pending.clear()
        raise ExpansionError("The USB-UART migration bridge did not report settled state in time. No reset or final write is allowed; keep power connected and retry.")
    finally:
        stream.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("plan")
    for name in ("firmware", "partition-table", "flash-id-output", "output-dir"):
        prepare.add_argument("--" + name, type=Path, required=True)
    prepare.add_argument("--package", type=Path)
    prepare.add_argument("--otadata", type=Path)
    prepare.add_argument("--nvs", type=Path)
    prepare.add_argument("--device-mac")
    prepare.add_argument("--usb-set", type=Path)
    begin = commands.add_parser("begin")
    begin.add_argument("--plan", type=Path, required=True)
    verify = commands.add_parser("verify")
    for name in ("plan", "partition-table", "nvs", "otadata"):
        verify.add_argument("--" + name, type=Path, required=True)
    wait_uart = commands.add_parser("wait-uart")
    wait_uart.add_argument("--port", required=True)
    wait_uart.add_argument("--device-mac", required=True)
    wait_uart.add_argument("--timeout", type=float, default=180)
    commands.add_parser("preflight-uart")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result = make_plan(args.firmware, args.partition_table, args.flash_id_output,
                               args.output_dir,
                               args.package or (Path(os.environ["MESHFIRMWARE_PARTITION_PACKAGE"])
                                                if os.environ.get("MESHFIRMWARE_PARTITION_PACKAGE") else None),
                               args.otadata, args.device_mac, args.nvs,
                               args.usb_set or (Path(os.environ["MESHFIRMWARE_USB_MIGRATION_SET"])
                                               if os.environ.get("MESHFIRMWARE_USB_MIGRATION_SET") else None))
        elif args.command == "begin":
            result = begin_plan(args.plan)
        elif args.command == "wait-uart":
            result = wait_uart_bridge(args.port, args.device_mac, args.timeout)
        elif args.command == "preflight-uart":
            uart_serial_module()
            result = {"ok": True, "serial_api": "pyserial"}
        else:
            result = verify_plan(args.plan, args.partition_table, args.nvs, args.otadata)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (ExpansionError, OSError, ValueError, TypeError, KeyError):
        exc = sys.exc_info()[1]
        message = str(exc) if isinstance(exc, ExpansionError) else "Partition expansion preparation or verification failed."
        print(json.dumps({"ok": False, "error": message}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
