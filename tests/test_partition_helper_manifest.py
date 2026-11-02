#!/usr/bin/env python3
"""Check the real helper/callers contract, without imports of unverified code."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("partition_manifest_generator", ROOT / "tools/generate_partition_helper_manifest.py")
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class PartitionHelperManifestTests(unittest.TestCase):
    def test_real_bundled_contract_matches_without_overriding_production_hashes(self):
        manifest = json.loads((ROOT / "tools" / GEN.MANIFEST).read_text())
        self.assertEqual(manifest, GEN.describe(ROOT / "tools" / GEN.HELPER))
        self.assertEqual((manifest["api_version"], manifest["plan_format"]),
                         (1, "meshcore-usb-partition-expansion-v2"))
        self.assertEqual(GEN.main(["--check"]), 0)

    def test_both_callers_share_an_immutable_known_fallback_not_mutable_main(self):
        linux = (ROOT / "mcfirmware.sh").read_text()
        windows = (ROOT / "firmware.cmd").read_text()
        def value(source, name):
            found = re.search(r"(?m)^\$?" + name + r"\s*=\s*['\"]([^'\"]+)['\"]", source)
            self.assertIsNotNone(found, name)
            return found[1]
        url = value(linux, "MESHCORE_PARTITION_EXPANSION_TOOL_URL")
        self.assertRegex(url, r"^https://raw\.githubusercontent\.com/mikecarper/meshfirmware/[0-9a-f]{40}/tools/meshcore_partition_expansion\.py$")
        self.assertEqual(url, value(windows, "MESHCORE_PARTITION_TOOL_URL"))
        digest = value(linux, "MESHCORE_PARTITION_EXPANSION_TOOL_SHA256")
        self.assertEqual(digest, "f91b2102865ef6a7378dd6a072d83895d972b17826cd5f1981bd98d2a13f2f64")
        self.assertEqual(digest, value(windows, "MESHCORE_PARTITION_TOOL_SHA256"))

    def test_lf_and_crlf_have_the_same_canonical_identity(self):
        with tempfile.TemporaryDirectory() as scratch:
            helper = Path(scratch) / GEN.HELPER
            text = b'API_VERSION = 1\nFORMAT = "meshcore-usb-partition-expansion-v2"\n'
            helper.write_bytes(text)
            identity = GEN.describe(helper)
            helper.write_bytes(text.replace(b"\n", b"\r\n"))
            self.assertEqual(GEN.describe(helper), identity)

    def test_future_compatible_source_only_needs_a_regenerated_sidecar(self):
        with tempfile.TemporaryDirectory() as scratch:
            helper, manifest = Path(scratch) / GEN.HELPER, Path(scratch) / GEN.MANIFEST
            helper.write_text('API_VERSION = 1\nFORMAT = "meshcore-usb-partition-expansion-v2"\n')
            args = ["--helper", str(helper), "--output", str(manifest)]
            self.assertEqual(GEN.main(args), 0)
            previous = json.loads(manifest.read_text())
            helper.write_text(helper.read_text() + "# A future compatible implementation change.\n")
            self.assertEqual(GEN.main(args + ["--check"]), 1)
            self.assertEqual(GEN.main(args), 0)
            current = json.loads(manifest.read_text())
            self.assertNotEqual(previous["sha256"], current["sha256"])
            self.assertEqual(previous["api_version"], current["api_version"])
            self.assertEqual(GEN.main(args + ["--check"]), 0)

    def test_generator_does_not_execute_helper_code(self):
        with tempfile.TemporaryDirectory() as scratch:
            helper = Path(scratch) / GEN.HELPER
            helper.write_text('API_VERSION = 1\nFORMAT = "meshcore-usb-partition-expansion-v2"\nraise RuntimeError("must not execute")\n')
            self.assertEqual(GEN.describe(helper)["api_version"], 1)

    def test_invalid_or_ambiguous_contracts_are_refused(self):
        for declaration in ("API_VERSION = True", "API_VERSION = 0", "API_VERSION = '1'",
                            "API_VERSION = dangerous()", "API_VERSION = 1\nAPI_VERSION = 2"):
            with self.subTest(declaration=declaration), tempfile.TemporaryDirectory() as scratch:
                helper = Path(scratch) / GEN.HELPER
                helper.write_text(declaration + '\nFORMAT = "meshcore-usb-partition-expansion-v2"\n')
                with self.assertRaises(ValueError):
                    GEN.describe(helper)

    def test_incompatible_api_is_recorded_not_disguised_as_compatible(self):
        with tempfile.TemporaryDirectory() as scratch:
            helper = Path(scratch) / GEN.HELPER
            helper.write_text('API_VERSION = 2\nFORMAT = "meshcore-usb-partition-expansion-v3"\n')
            self.assertEqual(GEN.describe(helper)["api_version"], 2)
            self.assertEqual(GEN.describe(helper)["plan_format"], "meshcore-usb-partition-expansion-v3")

    def test_git_checkout_keeps_hashed_sources_and_sidecar_lf(self):
        attributes = (ROOT / ".gitattributes").read_text()
        for name in (GEN.HELPER, GEN.MANIFEST):
            self.assertIn("tools/" + name + " text eol=lf", attributes)


if __name__ == "__main__":
    unittest.main()
