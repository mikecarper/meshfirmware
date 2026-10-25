"""Native version-query fixture; no dependencies, package installs, or USB.

The environment selects success, stderr-only warnings, a failing interpreter,
malformed/ambiguous JSON, or incompatible metadata. The optional marker proves
the caller never executes a helper whose bytes fail its checksum gate. Keep
this fixture above the standalone downloader's minimum helper size so the
download regression exercises validation rather than the truncated-file guard.
"""

import json
import os
from pathlib import Path
import sys

assert sys.argv[1:] == ["version"], sys.argv
marker = os.environ.get("MESHFIRMWARE_TEST_VERSION_MARKER")
if marker:
    Path(marker).touch()

mode = os.environ.get("MESHFIRMWARE_TEST_VERSION_MODE", "ok")
if mode == "failed":
    print("SyntaxError: simulated incompatible Python runtime", file=sys.stderr)
    raise SystemExit(7)
if mode == "empty":
    raise SystemExit(0)
if mode == "invalid":
    print("{not json}")
    raise SystemExit(0)
if mode == "ambiguous":
    print('{}\n{}')
    raise SystemExit(0)

summary = {
    "ok": mode != "not-ok",
    "schema": "wrong/schema" if mode == "schema" else "org.meshfirmware.meshcore-backup/v1",
    "tool_version": "0.0.0" if mode == "version" else "0.2.3",
}
print(json.dumps(summary), flush=True)
if mode == "stderr":
    print("harmless version-query warning", file=sys.stderr, flush=True)
