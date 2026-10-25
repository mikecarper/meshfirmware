#!/usr/bin/env python3
"""Hermetic planning/verification tests: no network or serial devices."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("partition_expansion", ROOT / "tools" / "meshcore_partition_expansion.py")
EXP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXP)
VERSION = "v1.17.1.9-halo-keymind-cascade-dev"
SOURCE = "88c85108"
TARGET = "heltec_v4_repeater"
TARGET_ID = int.from_bytes(EXP.hashlib.sha256(TARGET.encode()).digest()[:4], "little")


def esp_image(size: int, *, chip: int = 9, flash_mb: int = 16,
              target: int = TARGET_ID, hardware: str = "heltec_v4", endf: bool = True) -> bytes:
    body = bytearray(size - (56 if endf else 0))
    body[0:4] = bytes((0xE9, 1, 2, (flash_mb.bit_length() - 1) << 4))
    struct.pack_into("<H", body, 12, chip)
    if not endf:
        return bytes(body)
    trailer = (b"EndF" + struct.pack("<I", len(body))
               + EXP.hashlib.sha256(body).digest()[:8]
               + struct.pack("<II", EXP.numeric_version(VERSION), target)
               + hardware.encode().ljust(32, b"\0"))
    return bytes(body) + trailer


def table(entries: list[tuple], md5: bool = True) -> bytes:
    body = b"".join(struct.pack("<2sBBII16sI", b"\xaa\x50", kind, subtype,
                                address, size, name.encode(), flags)
                    for name, kind, subtype, address, size, flags in entries)
    if md5:
        body += b"\xeb\xeb" + b"\xff" * 14 + EXP.hashlib.md5(body).digest()
    return body.ljust(4096, b"\xff")


def usb_bridge_image(size: int = 4096, *, chip: int = 9, flash_mb: int = 16,
                     nvs_guard: bool = True) -> bytes:
    body = bytearray(esp_image(size, chip=chip, flash_mb=flash_mb, endf=False))
    body[100:100 + len(EXP.USB_BRIDGE_MARKER)] = EXP.USB_BRIDGE_MARKER
    if nvs_guard:
        body[200:200 + len(EXP.USB_NVS_GUARD_MARKER)] = EXP.USB_NVS_GUARD_MARKER
    return bytes(body)


USB_PROFILES = ((0, 4), (0, 8), (5, 4), (9, 4), (9, 8), (9, 16))


def usb_bridge_set_archive(*, manifest_updates: dict | None = None,
                           replacements: dict | None = None,
                           omit_profiles: tuple = (), damaged_members: dict | None = None) -> bytes:
    files = {"README.md": b"Callback-free USB partition bridge fixtures; exact Full package also required.\n"}
    bridges = []
    for chip, flash_mb in USB_PROFILES:
        if (chip, flash_mb) in omit_profiles:
            continue
        name = f"usb-bridge-chip{chip}-{flash_mb}mb.bin"
        files[name] = usb_bridge_image(chip=chip, flash_mb=flash_mb)
        bridges.append({"chip": chip, "flash_bytes": flash_mb << 20, "file": name,
                        "automatic_rom_return": chip != 0, "uart_completion_status": chip == 0,
                        "host_software_bootloader_entry": True, "application_usb_cdc": False})
    if replacements:
        files.update(replacements)
    manifest = {"format": "meshcore-usb-partition-bridges-v1", "source_commit": "a" * 40,
                "working_tree_dirty": False, "source_tree_sha256": "b" * 64,
                "bridges": bridges,
                "files": {name: {"bytes": len(data), "sha256": EXP.digest(data)}
                          for name, data in files.items()}}
    if manifest_updates:
        manifest.update(manifest_updates)
    files["manifest.json"] = json.dumps(manifest).encode()
    files["SHA256SUMS.txt"] = "".join(f"{EXP.digest(data)}  {name}\n"
                                     for name, data in sorted(files.items())).encode()
    if damaged_members:
        files.update(damaged_members)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipper:
        for name, data in files.items():
            zipper.writestr(name, data)
    return stream.getvalue()


def legacy_entries() -> list[tuple]:
    return [("nvs", 1, 2, 0x9000, 0x5000, 0), ("otadata", 1, 0, 0xE000, 0x2000, 0),
            ("app0", 0, 0x10, 0x10000, 0x140000, 0),
            ("app1", 0, 0x11, 0x150000, 0x140000, 0),
            ("spiffs", 1, 0x82, 0x290000, 0x160000, 0)]


def migration_archive(image: bytes, *, manifest_updates: dict | None = None,
                      replacements: dict | None = None, legacy_usb: bool = False,
                      omit_usb_metadata: bool = False) -> bytes:
    files = {"wifi-bridge.bin": esp_image(4096, endf=False),
             "usb-bridge.bin": usb_bridge_image(),
             "full-application.bin": image,
             "target-partitions.bin": EXP.canonical_table(16 << 20),
             "capabilities.json": json.dumps({"target": TARGET, "build_profile": "full",
                                               "platform": "ESP32_PLATFORM", "ota_update_verified": True}).encode(),
             "README.md": b"Exact fixture migration package.\n"}
    if replacements:
        files.update(replacements)
    if legacy_usb:
        files.pop("usb-bridge.bin")
    manifest = {"board": "heltec-v4", "role": "repeater", "target": TARGET,
                "target_id": f"0x{TARGET_ID:08x}", "hardware_id": "heltec_v4",
                "source_commit": SOURCE, "firmware_version": VERSION,
                "flash_bytes": 16 << 20, "legacy_slot_bytes": 0x140000,
                "expanded_slot_bytes": 0x640000, "atomic_power_loss_recovery": False,
                "usb_migration": {"format": "meshcore-usb-partition-migration-v1",
                                  "bridge": "usb-bridge.bin", "automatic_rom_return": True,
                                  "uart_completion_status": False, "host_software_bootloader_entry": True,
                                  "application_usb_cdc": False},
                "files": {name: {"bytes": len(data), "sha256": EXP.digest(data)}
                          for name, data in files.items()}}
    if legacy_usb or omit_usb_metadata:
        manifest.pop("usb_migration")
    if manifest_updates:
        manifest.update(manifest_updates)
    files["manifest.json"] = json.dumps(manifest).encode()
    files["SHA256SUMS.txt"] = "".join(f"{EXP.digest(data)}  {name}\n"
                                     for name, data in sorted(files.items())).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipper:
        for name, data in files.items():
            zipper.writestr(name, data)
    return stream.getvalue()


def ota_data(first: int | None = 1, second: int | None = None, *, state: int = 2) -> bytes:
    data = bytearray(b"\xff" * 8192)
    for offset, sequence in zip((0, 4096), (first, second)):
        if sequence is None:
            continue
        struct.pack_into("<I", data, offset, sequence)
        crc = zlib.crc32(struct.pack("<I", sequence), 0xFFFFFFFF) & 0xFFFFFFFF
        struct.pack_into("<II", data, offset + 24, state, crc)
    return bytes(data)


def nvs_entry(namespace: int, key: str, value: int, *, kind: int = 1) -> bytes:
    entry = bytearray(b"\xff" * 32)
    entry[0:4] = bytes((namespace, kind, 1, 0xFF))
    entry[8:24] = key.encode().ljust(16, b"\0")
    entry[24] = value
    crc = zlib.crc32(entry[:4] + entry[8:], 0xFFFFFFFF) & 0xFFFFFFFF
    struct.pack_into("<I", entry, 4, crc)
    return bytes(entry)


def nvs_page(sequence: int, entries: list[tuple[bytes, int]], *, active: bool = True) -> bytes:
    page = bytearray(b"\xff" * 4096)
    struct.pack_into("<II", page, 0, 0xFFFFFFFE if active else 0xFFFFFFFC, sequence)
    page[8] = 0xFE
    struct.pack_into("<I", page, 28, zlib.crc32(page[4:28], 0xFFFFFFFF) & 0xFFFFFFFF)
    bitmap = (1 << 256) - 1
    for index, (entry, state) in enumerate(entries):
        bitmap = (bitmap & ~(3 << (index * 2))) | (state << (index * 2))
        page[64 + index * 32:96 + index * 32] = entry
    page[32:64] = bitmap.to_bytes(32, "little")
    return bytes(page)


def finished_nvs(*, restored: int = 1, config_pending: int | None = None,
                 identity_pending: int | None = None) -> bytes:
    entries = [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
               (nvs_entry(3, "cfg-restored", restored), 2)]
    for key, value in (("cfg-pending", config_pending), ("id-pending", identity_pending)):
        if value is not None:
            entries.append((nvs_entry(3, key, value), 2))
    return nvs_page(7, entries) + b"\xff" * (4 * 4096)


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        network_guard = mock.patch.object(EXP, "download", side_effect=AssertionError("tests must not use the network"))
        network_guard.start()
        self.addCleanup(network_guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.image = esp_image(0x140000 + 128)
        self.firmware = self.folder / f"{TARGET}-full-usa-{VERSION}-{SOURCE}.bin"
        self.firmware.write_bytes(self.image)
        self.old = self.folder / "old.bin"
        self.old.write_bytes(table(legacy_entries()))
        self.flash = self.folder / "flash.txt"
        self.flash.write_text("Chip type:          ESP32-S3 (QFN56) (revision v0.2)\nDetected flash size: 16MB\n")
        self.ota = self.folder / "otadata.bin"
        self.ota.write_bytes(ota_data())
        self.package = self.folder / "migration.zip"
        self.package.write_bytes(migration_archive(self.image))
        self.cache = self.folder / "device-cache"
        self.mac = "AA:BB:CC:DD:EE:FF"
        self.new = self.folder / "new.bin"
        self.new.write_bytes(EXP.canonical_table(16 << 20))
        self.nvs = self.folder / "nvs.bin"
        self.nvs.write_bytes(finished_nvs())

    def plan(self, **kwargs) -> dict:
        return EXP.make_plan(kwargs.pop("firmware", self.firmware), kwargs.pop("table_path", self.old),
                             self.flash, self.cache, kwargs.pop("package_path", self.package),
                             kwargs.pop("ota_path", self.ota), kwargs.pop("device_mac", self.mac),
                             kwargs.pop("nvs_path", self.nvs), kwargs.pop("usb_set_path", None))

    def started_plan(self) -> dict:
        result = self.plan()
        EXP.begin_plan(Path(result["plan_file"]))
        return result

    def verify(self, plan: dict) -> dict:
        return EXP.verify_plan(Path(plan["plan_file"]), self.new, self.nvs, self.ota)

    def test_exact_package_plan_and_public_cache(self):
        result = self.plan()
        self.assertTrue(result["needed"])
        self.assertFalse(result["started"])
        self.assertEqual(result["bridge_offsets"], [0x150000, 0x10000])
        self.assertEqual(result["nvs_offset"], 0x9000)
        self.assertEqual(result["nvs_size"], 0x5000)
        self.assertEqual(result["ota_offset"], 0xE000)
        self.assertEqual(result["ota_size"], 0x2000)
        self.assertEqual(result["device_mac"], "AABBCCDDEEFF")
        self.assertEqual(result["firmware_sha256"], EXP.digest(self.image))
        self.assertEqual(Path(result["bridge_file"]).read_bytes(), usb_bridge_image())
        self.assertEqual({file.name for file in Path(result["plan_file"]).parent.iterdir()},
                         {"usb-bridge.bin", "target-partitions.bin", "plan.json"})
        self.assertTrue(result["usb_safe"])
        self.assertTrue(result["automatic_rom_return"])

    def test_already_fits_has_no_download_or_cache(self):
        with mock.patch.object(EXP, "download", side_effect=AssertionError("must not download")):
            result = self.plan(table_path=self.new, package_path=None)
        self.assertFalse(result["needed"])
        self.assertEqual(result["app_offsets"], [0x650000, 0x10000])
        self.assertFalse(self.cache.exists())

    def test_wifi_only_or_mislabelled_usb_package_is_not_substituted(self):
        for metadata in (None, {}, {"format": "meshcore-usb-partition-migration-v1",
                                    "bridge": "wifi-bridge.bin", "automatic_rom_return": True,
                                    "application_usb_cdc": False}):
            self.package.write_bytes(migration_archive(self.image, manifest_updates={"usb_migration": metadata}))
            with self.subTest(metadata=metadata), self.assertRaisesRegex(EXP.ExpansionError, "USB-safe"):
                self.plan()
        self.package.write_bytes(migration_archive(self.image, replacements={"usb-bridge.bin": esp_image(4096, endf=False)}))
        with self.assertRaisesRegex(EXP.ExpansionError, "runtime marker"):
            self.plan()

    def test_exact_full_package_can_use_standalone_usb_bridge_set(self):
        self.package.write_bytes(migration_archive(self.image, manifest_updates={"usb_migration": None}))
        usb_set = self.folder / "usb-bridges.zip"
        usb_set.write_bytes(usb_bridge_set_archive())
        result = self.plan(usb_set_path=usb_set)
        self.assertTrue(result["needed"])
        self.assertTrue(result["usb_safe"])
        self.assertTrue(result["automatic_rom_return"])
        self.assertFalse(result["uart_completion_status"])
        self.assertEqual(Path(result["bridge_file"]).read_bytes(), usb_bridge_image())
        self.assertEqual(result["firmware_sha256"], EXP.digest(self.image))
        self.assertEqual(result["app_offsets"], [0x150000, 0x10000])
        self.assertEqual(result["usb_source_commit"], "a" * 40)
        self.assertEqual(result["usb_source_tree_sha256"], "b" * 64)
        self.assertIs(result["usb_working_tree_dirty"], False)
        self.assertEqual(result["usb_set_sha256"], EXP.digest(usb_set.read_bytes()))

    def test_legacy_full_package_automatically_uses_pinned_published_usb_set(self):
        self.package.write_bytes(migration_archive(self.image, legacy_usb=True))
        archive = usb_bridge_set_archive()
        with mock.patch.object(EXP, "PUBLISHED_USB_SET_SHA256", EXP.digest(archive)), \
                mock.patch.object(EXP, "download", return_value=archive) as downloader:
            result = self.plan()
        downloader.assert_called_once_with(EXP.PUBLISHED_USB_SET_URL, EXP.MAX_ARCHIVE_BYTES)
        self.assertTrue(result["needed"])
        self.assertTrue(result["usb_safe"])
        self.assertEqual(Path(result["bridge_file"]).read_bytes(), usb_bridge_image())
        self.assertEqual(result["usb_set_url"], EXP.PUBLISHED_USB_SET_URL)
        self.assertEqual(result["usb_set_sha256"], EXP.digest(archive))
        self.assertEqual(result["usb_source_commit"], "a" * 40)
        cached = self.cache / "usb-sets" / EXP.digest(archive) / "meshcore-usb-partition-bridges.zip"
        self.assertEqual(Path(result["usb_set_file"]), cached)
        self.assertEqual(cached.read_bytes(), archive)

    def test_published_usb_set_cache_reuse_revalidates_without_download(self):
        archive = usb_bridge_set_archive()
        checksum = EXP.digest(archive)
        cached = self.cache / "usb-sets" / checksum / "meshcore-usb-partition-bridges.zip"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(archive)
        with mock.patch.object(EXP, "PUBLISHED_USB_SET_SHA256", checksum), \
                mock.patch.object(EXP, "download", side_effect=AssertionError("cached set must not download")) as downloader:
            bridge, provenance = EXP.resolve_published_usb_set(self.cache, 9, 16 << 20)
        downloader.assert_not_called()
        self.assertEqual(bridge, usb_bridge_image())
        self.assertEqual(provenance["usb_set_file"], str(cached.resolve()))
        self.assertEqual(provenance["usb_set_url"], EXP.PUBLISHED_USB_SET_URL)

    def test_published_usb_set_rejects_corrupt_cache_even_when_zip_valid(self):
        archive = usb_bridge_set_archive()
        checksum = EXP.digest(archive)
        cached = self.cache / "usb-sets" / checksum / "meshcore-usb-partition-bridges.zip"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(usb_bridge_set_archive(manifest_updates={"source_commit": "c" * 40}))
        with mock.patch.object(EXP, "PUBLISHED_USB_SET_SHA256", checksum), \
                mock.patch.object(EXP, "download", side_effect=AssertionError("corrupt cache must be rejected")) as downloader, \
                self.assertRaisesRegex(EXP.ExpansionError, "SHA|checksum|pin|hash"):
            EXP.resolve_published_usb_set(self.cache, 9, 16 << 20)
        downloader.assert_not_called()

    def test_published_usb_set_download_hash_must_match_pin(self):
        archive = usb_bridge_set_archive()
        with mock.patch.object(EXP, "PUBLISHED_USB_SET_SHA256", "0" * 64), \
                mock.patch.object(EXP, "download", return_value=archive), \
                self.assertRaisesRegex(EXP.ExpansionError, "SHA|checksum|pin|hash"):
            EXP.resolve_published_usb_set(self.cache, 9, 16 << 20)
        self.assertFalse(any(self.cache.rglob("*.zip")))
        self.assertFalse(any(self.cache.rglob("plan.json")))

    def test_published_usb_set_offline_failure_creates_no_plan_or_bridge(self):
        self.package.write_bytes(migration_archive(self.image, legacy_usb=True))
        with mock.patch.object(EXP, "download", side_effect=EXP.ExpansionError("published USB set offline")), \
                self.assertRaisesRegex(EXP.ExpansionError, "offline"):
            self.plan()
        self.assertFalse(any(self.cache.rglob("plan.json")))
        self.assertFalse(any(self.cache.rglob("usb-bridge.bin")))

    def test_published_usb_set_hash_match_still_requires_valid_zip_and_profiles(self):
        invalid_archives = (b"not a zip", usb_bridge_set_archive(omit_profiles=((5, 4),)),
                            usb_bridge_set_archive(replacements={"usb-bridge-chip5-4mb.bin": usb_bridge_image(chip=9, flash_mb=4)}))
        for index, archive in enumerate(invalid_archives):
            with self.subTest(index=index), mock.patch.object(EXP, "PUBLISHED_USB_SET_SHA256", EXP.digest(archive)), \
                    mock.patch.object(EXP, "download", return_value=archive), self.assertRaises(EXP.ExpansionError):
                EXP.resolve_published_usb_set(self.cache / str(index), 9, 16 << 20)
            self.assertFalse(any((self.cache / str(index)).rglob("*.zip")))
        archive = usb_bridge_set_archive()
        with mock.patch.object(EXP, "PUBLISHED_USB_SET_SHA256", EXP.digest(archive)), \
                mock.patch.object(EXP, "download", return_value=archive), \
                self.assertRaisesRegex(EXP.ExpansionError, "compatible|profile|chip"):
            EXP.resolve_published_usb_set(self.cache / "wrong-profile", 5, 8 << 20)

    def test_embedded_and_explicit_usb_set_precede_published_download(self):
        with mock.patch.object(EXP, "download", side_effect=AssertionError("embedded set must not download")) as downloader:
            embedded = self.plan()
        downloader.assert_not_called()
        self.assertNotIn("usb_set_url", embedded)
        self.package.write_bytes(migration_archive(self.image, legacy_usb=True))
        explicit = self.folder / "explicit-usb.zip"
        explicit.write_bytes(usb_bridge_set_archive(manifest_updates={"source_commit": "d" * 40}))
        with mock.patch.object(EXP, "download", side_effect=AssertionError("explicit set must not download")) as downloader:
            result = self.plan(usb_set_path=explicit)
        downloader.assert_not_called()
        self.assertEqual(result["usb_source_commit"], "d" * 40)
        self.assertNotIn("usb_set_url", result)

    def test_published_fallback_never_relaxes_exact_full_package_validation(self):
        self.package.write_bytes(migration_archive(self.image + b"wrong full image", legacy_usb=True))
        with mock.patch.object(EXP, "download", side_effect=AssertionError("Full mismatch must stop before USB download")) as downloader, \
                self.assertRaisesRegex(EXP.ExpansionError, "exact selected firmware"):
            self.plan()
        downloader.assert_not_called()
        self.assertFalse(self.cache.exists())

    def test_partial_or_invalid_embedded_usb_metadata_never_uses_published_fallback(self):
        for metadata in (None, {}, {"format": "wrong"}):
            self.package.write_bytes(migration_archive(self.image, manifest_updates={"usb_migration": metadata}))
            with self.subTest(metadata=metadata), \
                    mock.patch.object(EXP, "download", side_effect=AssertionError("invalid embedded metadata must not download")) as downloader, \
                    self.assertRaisesRegex(EXP.ExpansionError, "USB-safe"):
                self.plan()
            downloader.assert_not_called()
        self.package.write_bytes(migration_archive(self.image, omit_usb_metadata=True))
        with mock.patch.object(EXP, "download", side_effect=AssertionError("undeclared USB member must not download")) as downloader, \
                self.assertRaisesRegex(EXP.ExpansionError, "USB-safe"):
            self.plan()
        downloader.assert_not_called()
        # A missing bridge with an existing metadata declaration is malformed,
        # not a legacy package eligible for the independent published set.
        self.package.write_bytes(migration_archive(self.image, legacy_usb=True,
                                                 manifest_updates={"usb_migration": None}))
        with mock.patch.object(EXP, "download", side_effect=AssertionError("partial USB declaration must not download")) as downloader, \
                self.assertRaisesRegex(EXP.ExpansionError, "USB-safe"):
            self.plan()
        downloader.assert_not_called()

    def test_standalone_usb_set_alone_is_not_a_full_application_package(self):
        self.package.write_bytes(usb_bridge_set_archive())
        with self.assertRaisesRegex(EXP.ExpansionError, "missing required.*application|does not match"):
            self.plan(usb_set_path=self.package)

    def test_standalone_usb_set_all_native_and_uart_profiles_select_exact_bytes(self):
        usb_set = self.folder / "usb-bridges.zip"
        usb_set.write_bytes(usb_bridge_set_archive())
        for chip, flash_mb in USB_PROFILES:
            with self.subTest(chip=chip, flash_mb=flash_mb):
                bridge, provenance = EXP.usb_bridge_from_set(usb_set, chip, flash_mb << 20)
                self.assertEqual(bridge, usb_bridge_image(chip=chip, flash_mb=flash_mb))
                self.assertEqual(provenance["usb_set_sha256"], EXP.digest(usb_set.read_bytes()))

    def test_standalone_usb_set_does_not_relax_exact_full_image_match(self):
        self.package.write_bytes(migration_archive(self.image + b"changed", manifest_updates={"usb_migration": None}))
        usb_set = self.folder / "usb-bridges.zip"
        usb_set.write_bytes(usb_bridge_set_archive())
        with self.assertRaisesRegex(EXP.ExpansionError, "match|exact|selected"):
            self.plan(usb_set_path=usb_set)

    def test_standalone_usb_set_requires_all_six_profiles(self):
        self.package.write_bytes(migration_archive(self.image, manifest_updates={"usb_migration": None}))
        usb_set = self.folder / "usb-bridges.zip"
        usb_set.write_bytes(usb_bridge_set_archive(omit_profiles=((5, 4),)))
        with self.assertRaisesRegex(EXP.ExpansionError, "six|profile|complete|coverage"):
            self.plan(usb_set_path=usb_set)

    def test_standalone_usb_set_rejects_damaged_member_checksums(self):
        self.package.write_bytes(migration_archive(self.image, manifest_updates={"usb_migration": None}))
        usb_set = self.folder / "usb-bridges.zip"
        usb_set.write_bytes(usb_bridge_set_archive(damaged_members={"usb-bridge-chip9-16mb.bin": b"damaged"}))
        with self.assertRaisesRegex(EXP.ExpansionError, "checksum|hash|inventory|size|length"):
            self.plan(usb_set_path=usb_set)

    def test_standalone_usb_set_checks_each_image_chip_and_flash_header(self):
        self.package.write_bytes(migration_archive(self.image, manifest_updates={"usb_migration": None}))
        usb_set = self.folder / "usb-bridges.zip"
        for bad_image in (usb_bridge_image(chip=5), usb_bridge_image(flash_mb=8)):
            usb_set.write_bytes(usb_bridge_set_archive(replacements={"usb-bridge-chip9-16mb.bin": bad_image}))
            with self.subTest(header=bad_image[:24]), self.assertRaisesRegex(EXP.ExpansionError, "chip|flash|geometry|header"):
                self.plan(usb_set_path=usb_set)
        # An unselected profile must be validated too: set-wide publication
        # cannot disguise a broken classic/C3 bridge behind the selected S3.
        usb_set.write_bytes(usb_bridge_set_archive(replacements={"usb-bridge-chip5-4mb.bin": usb_bridge_image(chip=9, flash_mb=4)}))
        with self.assertRaisesRegex(EXP.ExpansionError, "chip|flash|geometry|header"):
            self.plan(usb_set_path=usb_set)

    def test_usb_bridge_requires_no_autoerase_startup_guard_marker(self):
        self.package.write_bytes(migration_archive(self.image, replacements={"usb-bridge.bin": usb_bridge_image(nvs_guard=False)}))
        with self.assertRaisesRegex(EXP.ExpansionError, "NVS|guard|startup|autoerase"):
            self.plan()
        self.package.write_bytes(migration_archive(self.image, manifest_updates={"usb_migration": None}))
        usb_set = self.folder / "usb-bridges.zip"
        usb_set.write_bytes(usb_bridge_set_archive(replacements={"usb-bridge-chip9-16mb.bin": usb_bridge_image(nvs_guard=False)}))
        with self.assertRaisesRegex(EXP.ExpansionError, "NVS|guard|startup|autoerase"):
            self.plan(usb_set_path=usb_set)

    def test_uart_completion_status_never_discloses_serial_lines(self):
        state = {"format": "meshcore-usb-partition-migration-v1", "device_mac": "AABBCCDDEEFF",
                 "settled": True, "restored": True}
        serial = mock.Mock()
        stream = serial.Serial.return_value
        stream.read.side_effect = [b"unrelated private data\nMESHCORE_USB_MIGRATION_STATE " + json.dumps(state).encode() + b"\n"]
        with mock.patch.dict(sys.modules, {"serial": serial}):
            result = EXP.wait_uart_bridge("COM7", "aa:bb:cc:dd:ee:ff", 1)
        self.assertEqual(result, {"ok": True, "settled": True, "restored": True, "device_mac": "AABBCCDDEEFF"})
        self.assertFalse(stream.dtr)
        self.assertFalse(stream.rts)
        stream.close.assert_called_once()

    def test_uart_wrong_mac_and_timeout_cannot_authorize_reset(self):
        serial = mock.Mock()
        stream = serial.Serial.return_value
        stream.read.return_value = b'MESHCORE_USB_MIGRATION_STATE {"format":"meshcore-usb-partition-migration-v1","device_mac":"112233445566","settled":true,"restored":true}\n'
        with mock.patch.dict(sys.modules, {"serial": serial}), self.assertRaisesRegex(EXP.ExpansionError, "different chip MAC"):
            EXP.wait_uart_bridge("COM7", "AABBCCDDEEFF", 1)
        with mock.patch.dict(sys.modules, {"serial": serial}), mock.patch.object(EXP.time, "monotonic", side_effect=[0, 2]), self.assertRaisesRegex(EXP.ExpansionError, "in time"):
            EXP.wait_uart_bridge("COM7", "AABBCCDDEEFF", 1)
        with self.assertRaisesRegex(EXP.ExpansionError, "identity or timeout"):
            EXP.wait_uart_bridge("COM7", "bad", 1)

    def test_uart_dependency_preflight_requires_callable_pyserial_without_port_access(self):
        with mock.patch.dict(sys.modules, {"serial": None}), self.assertRaisesRegex(EXP.ExpansionError, "requires pyserial"):
            EXP.uart_serial_module()
        unusable_serial = mock.Mock(Serial=None)
        with mock.patch.dict(sys.modules, {"serial": unusable_serial}), self.assertRaisesRegex(EXP.ExpansionError, "no usable pyserial API"):
            EXP.uart_serial_module()
        serial = mock.Mock()
        with mock.patch.dict(sys.modules, {"serial": serial}):
            self.assertIs(EXP.uart_serial_module(), serial)
        serial.Serial.assert_not_called()

    def test_uart_nonstring_reported_mac_is_cleanly_rejected_and_closed(self):
        for value in (None, [], {}, 1234):
            serial = mock.Mock()
            state = {"format": "meshcore-usb-partition-migration-v1", "device_mac": value,
                     "settled": True, "restored": True}
            stream = serial.Serial.return_value
            stream.read.return_value = b"MESHCORE_USB_MIGRATION_STATE " + json.dumps(state).encode() + b"\n"
            with self.subTest(value=value), mock.patch.dict(sys.modules, {"serial": serial}), \
                    self.assertRaisesRegex(EXP.ExpansionError, "different chip MAC"):
                EXP.wait_uart_bridge("COM7", "AABBCCDDEEFF", 1)
            stream.close.assert_called_once()

    def test_normal_single_factory_c6_update(self):
        self.firmware.write_bytes(esp_image(1024, chip=13, flash_mb=4, endf=False))
        self.flash.write_text("Chip is ESP32-C6\nFlash size: 4MB\n")
        self.old.write_bytes(table([("nvs", 1, 2, 0x9000, 0x5000, 0),
                                    ("factory", 0, 0, 0x10000, 0x200000, 0)]))
        self.nvs.write_bytes(b"\xff" * 0x5000)
        result = self.plan(ota_path=None)
        self.assertFalse(result["needed"])
        self.assertEqual(result["app_offsets"], [0x10000])
        self.assertIsNone(result["ota_offset"])

    def test_fast_fit_preserves_actual_nonstandard_ota_offset(self):
        entries = legacy_entries()
        entries[1] = ("otadata", 1, 0, 0x3F0000, 0x2000, 0)
        self.old.write_bytes(table(entries))
        self.firmware.write_bytes(esp_image(1024))
        self.ota.write_bytes(ota_data(2))
        result = self.plan()
        self.assertFalse(result["needed"])
        self.assertEqual(result["ota_offset"], 0x3F0000)
        self.assertEqual(result["app_offsets"], [0x10000, 0x150000])

    def test_source_overlap_and_md5_corruption_are_rejected(self):
        entries = legacy_entries()
        entries[-1] = ("spiffs", 1, 0x82, 0x280000, 0x160000, 0)
        self.old.write_bytes(table(entries))
        with self.assertRaisesRegex(EXP.ExpansionError, "overlapping"):
            self.plan()
        data = bytearray(table(legacy_entries()))
        data[4] ^= 1
        self.old.write_bytes(data)
        with self.assertRaises(EXP.ExpansionError):
            self.plan()

    def test_missing_stable_metadata_and_encryption_are_rejected(self):
        for change in (("nvs", 1, 2, 0xA000, 0x4000, 0),
                       ("nvs", 1, 2, 0x9000, 0x5000, 1)):
            entries = legacy_entries()
            entries[0] = change
            self.old.write_bytes(table(entries))
            self.nvs.write_bytes(finished_nvs()[:change[4]])
            with self.assertRaisesRegex(EXP.ExpansionError, "Source layout"):
                self.plan()

    def test_tiny_source_slot_cannot_run_bridge(self):
        self.package.write_bytes(migration_archive(self.image, replacements={"usb-bridge.bin": usb_bridge_image(0x140001)}))
        with self.assertRaisesRegex(EXP.ExpansionError, "legacy size"):
            self.plan()

    def test_app_without_endf_is_not_eligible_for_expansion(self):
        self.firmware.write_bytes(esp_image(0x140080, endf=False))
        with self.assertRaisesRegex(EXP.ExpansionError, "EndF"):
            self.plan()

    def test_flash_capacity_and_chip_must_match(self):
        self.flash.write_text("Chip type: ESP32-C3\nDetected flash size: 16MB\n")
        with self.assertRaisesRegex(EXP.ExpansionError, "chip/flash"):
            self.plan()
        self.flash.write_text("Chip type: ESP32-S3\nDetected flash size: 8MB\n")
        with self.assertRaisesRegex(EXP.ExpansionError, "chip/flash"):
            self.plan()

    def test_ambiguous_and_missing_physical_flash_are_rejected(self):
        for text in ("Chip type: ESP32-S3\n", "Chip type: ESP32-S3\nFlash size: 16MB\nFlash size: 8MB\n"):
            self.flash.write_text(text)
            with self.assertRaisesRegex(EXP.ExpansionError, "unambiguously"):
                self.plan()

    def test_exact_firmware_hash_not_just_same_board_release(self):
        different = bytearray(self.image)
        different[100] = 1
        body = bytes(different[:-56])
        different[-48:-40] = EXP.hashlib.sha256(body).digest()[:8]
        self.package.write_bytes(migration_archive(bytes(different)))
        with self.assertRaisesRegex(EXP.ExpansionError, "exact selected firmware"):
            self.plan()

    def test_package_board_role_release_and_identity_are_pinned(self):
        for field, value in (("target", "heltec_v4_sensor"), ("board", "heltec-v4-tft-repeater"),
                             ("source_commit", "deadbeef"), ("hardware_id", "other_board"),
                             ("target_id", "0x00000001"), ("firmware_version", "v1.17.1.8-halo-keymind-cascade-dev"),
                             ("flash_bytes", 8 << 20)):
            self.package.write_bytes(migration_archive(self.image, manifest_updates={field: value}))
            with self.subTest(field=field), self.assertRaisesRegex(EXP.ExpansionError, "exact selected firmware"):
                self.plan()

    def test_target_table_and_bridge_chip_are_pinned(self):
        self.package.write_bytes(migration_archive(self.image, replacements={"target-partitions.bin": table(legacy_entries())}))
        with self.assertRaisesRegex(EXP.ExpansionError, "target partition table"):
            self.plan()
        self.package.write_bytes(migration_archive(self.image, replacements={"usb-bridge.bin": usb_bridge_image(chip=5)}))
        with self.assertRaisesRegex(EXP.ExpansionError, "incompatible chip"):
            self.plan()

    def test_final_app_too_large_for_expanded_target(self):
        image = esp_image(0x640001)
        self.firmware.write_bytes(image)
        self.package.write_bytes(migration_archive(image))
        with self.assertRaisesRegex(EXP.ExpansionError, "expanded OTA slots"):
            self.plan()

    def test_archive_unsafe_path_duplicate_and_hash_are_rejected(self):
        source = self.package.read_bytes()
        for extra in ("../escape.bin", "C:\\escape.bin", "wifi-bridge.bin"):
            stream = io.BytesIO(source)
            with zipfile.ZipFile(stream, "a") as zipper:
                zipper.writestr(extra, b"unexpected")
            with self.subTest(extra=extra), self.assertRaises(EXP.ExpansionError):
                EXP.unpack_package(stream.getvalue())
        stream = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(source)) as original, zipfile.ZipFile(stream, "w") as modified:
            for item in original.infolist():
                data = original.read(item)
                if item.filename == "wifi-bridge.bin":
                    data = data[:-1] + b"changed"
                modified.writestr(item.filename, data)
        with self.assertRaisesRegex(EXP.ExpansionError, "SHA-256"):
            EXP.unpack_package(stream.getvalue())

    def test_automatic_resolver_uses_exact_individual_utility_asset(self):
        archive = self.package.read_bytes()
        tag = f"utility-{VERSION}-{SOURCE}"
        name = f"heltec-v4-{VERSION}-{SOURCE}-migration.zip"
        url = f"https://github.com/{EXP.REPOSITORY}/releases/download/{tag}/{name}"
        release = json.dumps({"tag_name": tag, "assets": [{"name": name, "size": len(archive),
                                                          "browser_download_url": url}]}).encode()
        with mock.patch.object(EXP, "download", side_effect=[release, archive]) as downloader:
            result = self.plan(package_path=None)
        self.assertEqual(result["artifact"], url)
        self.assertEqual(downloader.call_count, 2)
        self.assertNotIn("release.zip", downloader.call_args_list[1].args[0])

    def test_missing_exact_release_asset_never_uses_latest(self):
        release = json.dumps({"tag_name": f"utility-{VERSION}-{SOURCE}", "assets": []}).encode()
        with mock.patch.object(EXP, "download", return_value=release) as downloader:
            with self.assertRaisesRegex(EXP.ExpansionError, "No exact board/role"):
                self.plan(package_path=None)
        self.assertEqual(downloader.call_count, 1)

    def test_verify_requires_begin_and_completed_markers(self):
        result = self.plan()
        with self.assertRaisesRegex(EXP.ExpansionError, "pending"):
            self.verify(result)
        EXP.begin_plan(Path(result["plan_file"]))
        self.nvs.write_bytes(finished_nvs(restored=0))
        with self.assertRaisesRegex(EXP.ExpansionError, "restoration"):
            self.verify(result)
        self.nvs.write_bytes(finished_nvs())
        verified = self.verify(result)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["app_offsets"], [0x650000, 0x10000])
        stored = json.loads(Path(result["plan_file"]).read_text())
        self.assertTrue(stored["completed"])

    def test_verify_pending_identity_or_configuration_refuses_final_write(self):
        result = self.started_plan()
        for flags in ({"config_pending": 1}, {"identity_pending": 1}):
            self.nvs.write_bytes(finished_nvs(**flags))
            with self.subTest(flags=flags), self.assertRaisesRegex(EXP.ExpansionError, "restoration"):
                self.verify(result)

    def test_verify_unchanged_final_bridge_and_table(self):
        result = self.started_plan()
        self.firmware.write_bytes(self.image + b"extra")
        with self.assertRaisesRegex(EXP.ExpansionError, "final firmware changed"):
            self.verify(result)
        self.firmware.write_bytes(self.image)
        Path(result["bridge_file"]).write_bytes(b"changed")
        with self.assertRaisesRegex(EXP.ExpansionError, "bridge changed"):
            self.verify(result)

    def test_canceled_plan_is_not_pending_and_started_plan_blocks_other_image(self):
        result = self.plan()
        other = self.folder / "other.bin"
        other.write_bytes(esp_image(1024))
        self.assertFalse(self.plan(firmware=other)["needed"])
        EXP.begin_plan(Path(result["plan_file"]))
        with self.assertRaisesRegex(EXP.ExpansionError, "original exact firmware"):
            self.plan(firmware=other, table_path=self.new)

    def test_resuming_expanded_and_original_layout(self):
        result = self.started_plan()
        with mock.patch.object(EXP, "download", side_effect=AssertionError("no new download")):
            resumed = self.plan(table_path=self.new, package_path=None)
        self.assertTrue(resumed["resume"])
        self.assertEqual(resumed["plan_file"], result["plan_file"])
        self.assertEqual(resumed["app_offsets"], [0x650000, 0x10000])
        original = self.plan()
        self.assertFalse(original["resume"])
        self.assertTrue(original["started"])
        self.verify(resumed)
        self.assertFalse(self.plan(table_path=self.new)["needed"])

    def test_pending_device_mac_cannot_change(self):
        self.started_plan()
        with self.assertRaisesRegex(EXP.ExpansionError, "physical device"):
            self.plan(device_mac="11:22:33:44:55:66", table_path=self.new)

    def test_cross_host_expanded_pending_migration_cannot_bypass_verification(self):
        for flags in ({"restored": 0}, {"config_pending": 1}, {"identity_pending": 1}):
            self.nvs.write_bytes(finished_nvs(**flags))
            with self.subTest(flags=flags), self.assertRaisesRegex(EXP.ExpansionError, "Live NVS"):
                self.plan(table_path=self.new)
        self.assertFalse(self.cache.exists())

    def test_ordinary_nvs_without_migration_namespace_is_allowed(self):
        page = nvs_page(1, [(nvs_entry(0, "wifi", 2), 2), (nvs_entry(2, "channel", 7), 2)])
        self.nvs.write_bytes(page + b"\xff" * (4 * 4096))
        self.assertFalse(self.plan(table_path=self.new)["needed"])

    def test_legacy_empty_migration_namespace_is_not_an_unfinished_handoff(self):
        page = nvs_page(1, [(nvs_entry(0, "wifi", 2), 2),
                            (nvs_entry(2, "channel", 7), 2),
                            (nvs_entry(0, "mesh-pt-migrate", 3), 2)])
        self.nvs.write_bytes(page + b"\xff" * (4 * 4096))
        # A normal small app update on both a legacy and already-expanded table.
        self.firmware.write_bytes(esp_image(1024))
        for layout in (self.old, self.new):
            with self.subTest(layout=layout.name):
                proof = self.plan(table_path=layout)
                self.assertFalse(proof["needed"])
                self.assertEqual(proof["nvs_migration"], {
                    "namespace_exists": True, "namespace_empty": True,
                    "cfg-restored": False, "cfg-pending": False, "id-pending": False})
                self.assertTrue(all(type(value) is bool for value in proof["nvs_migration"].values()))
                self.assertNotIn("channel", json.dumps(proof["nvs_migration"]))
        self.assertFalse(self.cache.exists())

    def test_nonempty_migration_namespace_without_completion_always_blocks(self):
        for key in ("cfg-restored", "cfg-pending", "id-pending", "identity", "cfg-meta",
                    "cfg-0", "resume-slot", "unknown-private"):
            for value in (0, 1):
                with self.subTest(key=key, value=value):
                    if key == "cfg-restored" and value == 1:
                        continue  # The existing legitimate completed state stays supported.
                    page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                                        (nvs_entry(3, key, value), 2)])
                    self.nvs.write_bytes(page + b"\xff" * (4 * 4096))
                    with self.assertRaisesRegex(EXP.ExpansionError, "Live NVS"):
                        self.plan(table_path=self.new)
        self.assertFalse(self.cache.exists())

    def test_empty_namespace_never_proves_a_started_migration_complete(self):
        started = self.started_plan()
        page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2)])
        self.nvs.write_bytes(page + b"\xff" * (4 * 4096))
        with self.assertRaisesRegex(EXP.ExpansionError, "not finished"):
            self.verify(started)

    def test_actual_nonstandard_nvs_geometry_and_missing_snapshot(self):
        entries = legacy_entries()
        entries[0] = ("nvs", 1, 2, 0x9000, 0x3000, 0)
        self.old.write_bytes(table(entries))
        self.firmware.write_bytes(esp_image(1024))
        self.nvs.write_bytes(b"\xff" * 0x3000)
        result = self.plan()
        self.assertFalse(result["needed"])
        self.assertEqual(result["nvs_size"], 0x3000)
        with self.assertRaisesRegex(EXP.ExpansionError, "actual NVS"):
            self.plan(nvs_path=None)

    def test_corrupt_ordinary_nvs_is_not_assumed_complete(self):
        self.nvs.write_bytes(b"unknown-encrypted-NVS".ljust(0x5000, b"\xff"))
        with self.assertRaisesRegex(EXP.ExpansionError, "NVS page"):
            self.plan(table_path=self.new)

    def test_cli_failures_are_json_without_snapshot_secrets(self):
        result = self.started_plan()
        self.nvs.write_bytes(b"PRIVATE-KEY-NOT-FOR-OUTPUT".ljust(EXP.NVS_SIZE, b"\xff"))
        command = [sys.executable, str(ROOT / "tools" / "meshcore_partition_expansion.py"), "verify",
                   "--plan", result["plan_file"], "--partition-table", str(self.new),
                   "--nvs", str(self.nvs), "--otadata", str(self.ota)]
        process = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(process.returncode, 1)
        self.assertFalse(json.loads(process.stdout)["ok"])
        self.assertNotIn("PRIVATE-KEY", process.stdout + process.stderr)


class NvsAndOtaTests(unittest.TestCase):
    def test_empty_namespace_counts_only_validated_live_keys(self):
        page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                            (nvs_entry(3, "cfg-restored", 0), 0),
                            (nvs_entry(3, "private-staged", 1), 0)])
        flags = EXP.parse_nvs_markers(page + b"\xff" * (4 * 4096))
        self.assertTrue(flags["namespace_exists"])
        self.assertTrue(flags["namespace_empty"])
        self.assertFalse(flags["cfg-restored"])
        for key in ("cfg-restored", "cfg-pending", "id-pending", "private-staged"):
            page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                                (nvs_entry(3, key, 0), 2)])
            with self.subTest(key=key):
                self.assertFalse(EXP.parse_nvs_markers(page + b"\xff" * (4 * 4096))["namespace_empty"])

    def test_empty_namespace_still_rejects_crc_or_ambiguous_identity(self):
        page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2)])
        corrupted = bytearray(page + b"\xff" * (4 * 4096))
        corrupted[64 + 24] ^= 1
        with self.assertRaisesRegex(EXP.ExpansionError, "verification"):
            EXP.parse_nvs_markers(bytes(corrupted))
        alias = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                             (nvs_entry(0, "alias", 3), 2)])
        with self.assertRaisesRegex(EXP.ExpansionError, "ambiguous"):
            EXP.parse_nvs_markers(alias + b"\xff" * (4 * 4096))

    def test_namespace_and_erased_stale_flags(self):
        page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                            (nvs_entry(3, "cfg-restored", 1), 0),
                            (nvs_entry(3, "cfg-restored", 0), 2)])
        flags = EXP.parse_nvs_markers(page + b"\xff" * (4 * 4096))
        self.assertFalse(flags["cfg-restored"])
        wrong = nvs_page(1, [(nvs_entry(0, "other-namespace", 3), 2),
                             (nvs_entry(3, "cfg-restored", 1), 2)])
        with self.assertRaisesRegex(EXP.ExpansionError, "namespace"):
            EXP.parse_nvs_markers(wrong + b"\xff" * (4 * 4096))

    def test_latest_current_record_and_page_sequence_not_physical_position(self):
        old = nvs_page(10, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                            (nvs_entry(3, "cfg-restored", 1), 2)], active=False)
        new = nvs_page(11, [(nvs_entry(3, "cfg-restored", 0), 2)])
        self.assertFalse(EXP.parse_nvs_markers(new + old + b"\xff" * (3 * 4096))["cfg-restored"])
        wrapping_old = nvs_page(0xFFFFFFFE, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                                             (nvs_entry(3, "cfg-restored", 0), 2)], active=False)
        wrapping_new = nvs_page(1, [(nvs_entry(3, "cfg-restored", 1), 2)])
        self.assertTrue(EXP.parse_nvs_markers(wrapping_new + wrapping_old + b"\xff" * (3 * 4096))["cfg-restored"])

    def test_live_entry_or_page_crc_corruption_is_rejected(self):
        for offset in (4, 28, 64 + 24, 96 + 24):
            data = bytearray(finished_nvs())
            data[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(EXP.ExpansionError, "verification"):
                EXP.parse_nvs_markers(bytes(data))

    def test_stale_true_in_blob_payload_cannot_become_completion_flag(self):
        child = nvs_entry(3, "cfg-restored", 1)
        parent = bytearray(b"\xff" * 32)
        parent[:4] = bytes((3, 0x42, 2, 0))
        parent[8:24] = b"privateblob".ljust(16, b"\0")
        struct.pack_into("<H", parent, 24, len(child))
        struct.pack_into("<I", parent, 28, zlib.crc32(child, 0xFFFFFFFF) & 0xFFFFFFFF)
        struct.pack_into("<I", parent, 4, zlib.crc32(parent[:4] + parent[8:], 0xFFFFFFFF) & 0xFFFFFFFF)
        page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                            (bytes(parent), 2), (child, 2)])
        flags = EXP.parse_nvs_markers(page + b"\xff" * (4 * 4096))
        self.assertFalse(flags["cfg-restored"])
        self.assertFalse(flags["namespace_empty"])

    def test_new_variable_marker_cannot_leave_old_bool_authoritative(self):
        child = b"not-a-completion-bool".ljust(32, b"\0")
        parent = bytearray(b"\xff" * 32)
        parent[:4] = bytes((3, 0x21, 2, 0xFF))
        parent[8:24] = b"cfg-restored".ljust(16, b"\0")
        struct.pack_into("<H", parent, 24, len(child))
        struct.pack_into("<I", parent, 28, zlib.crc32(child, 0xFFFFFFFF) & 0xFFFFFFFF)
        struct.pack_into("<I", parent, 4, zlib.crc32(parent[:4] + parent[8:], 0xFFFFFFFF) & 0xFFFFFFFF)
        page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2),
                            (nvs_entry(3, "cfg-restored", 1), 2),
                            (bytes(parent), 2), (child, 2)])
        with self.assertRaisesRegex(EXP.ExpansionError, "flag"):
            EXP.parse_nvs_markers(page + b"\xff" * (4 * 4096))

    def test_invalid_flag_type_bool_or_multiple_active_pages(self):
        for entry in (nvs_entry(3, "cfg-restored", 2), nvs_entry(3, "cfg-restored", 1, kind=0x11)):
            page = nvs_page(1, [(nvs_entry(0, "mesh-pt-migrate", 3), 2), (entry, 2)])
            with self.assertRaisesRegex(EXP.ExpansionError, "flag"):
                EXP.parse_nvs_markers(page + b"\xff" * (4 * 4096))
        with self.assertRaisesRegex(EXP.ExpansionError, "multiple active"):
            EXP.parse_nvs_markers(finished_nvs()[:4096] + nvs_page(8, []) + b"\xff" * (3 * 4096))

    def test_ota_active_slot_crc_newest_and_wrap(self):
        parts = EXP.parse_table(EXP.canonical_table(16 << 20), 16 << 20)
        self.assertEqual(EXP.active_ota_offset(parts, ota_data(2, 3)), 0x10000)
        self.assertEqual(EXP.active_ota_offset(parts, ota_data(1, 2)), 0x650000)
        self.assertEqual(EXP.active_ota_offset(parts, ota_data(0xFFFFFFFE, 1)), 0x10000)
        self.assertEqual(EXP.active_ota_offset(parts, ota_data(None)), 0x10000)
        corrupt = bytearray(ota_data(2))
        corrupt[28] ^= 1
        with self.assertRaisesRegex(EXP.ExpansionError, "no valid active"):
            EXP.active_ota_offset(parts, bytes(corrupt))
        with self.assertRaisesRegex(EXP.ExpansionError, "8192"):
            EXP.active_ota_offset(parts, b"\xff" * 4096)


if __name__ == "__main__":
    unittest.main()
