#!/usr/bin/env python3
"""Generate/check the bundled partition helper's integrity and CLI contract.

Reads Python literals without importing or executing the helper. Compatible
helper changes regenerate one sidecar; native callers need no new file hash.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
HELPER = "meshcore_partition_expansion.py"
MANIFEST = "meshcore_partition_expansion.json"
SCHEMA = "org.meshfirmware.partition-helper/v1"
MAX_BYTES = 262144


def describe(path: Path) -> dict:
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    if not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("partition helper exceeds its bounded source size")
    values = {}
    for node in ast.parse(raw.decode("utf-8")).body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in ("API_VERSION", "FORMAT"):
                if target.id in values:
                    raise ValueError("duplicate partition helper contract declaration")
                values[target.id] = ast.literal_eval(node.value)
    api, plan_format = values.get("API_VERSION"), values.get("FORMAT")
    if type(api) is not int or api <= 0 or not isinstance(plan_format, str) or not plan_format:
        raise ValueError("partition helper must declare literal API_VERSION and FORMAT")
    return {"schema": SCHEMA, "helper": HELPER, "api_version": api,
            "plan_format": plan_format, "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed sidecar is stale")
    parser.add_argument("--helper", type=Path, default=ROOT / HELPER)
    parser.add_argument("--output", type=Path, default=ROOT / MANIFEST)
    args = parser.parse_args(argv)
    try:
        data = (json.dumps(describe(args.helper), indent=2) + "\n").encode("ascii")
        if args.check:
            if not args.output.is_file() or args.output.read_bytes().replace(b"\r\n", b"\n") != data:
                raise ValueError("partition helper manifest is stale; run python tools/generate_partition_helper_manifest.py")
            print("Partition helper manifest and source contract match.")
        else:
            args.output.write_bytes(data)
            print("Updated " + str(args.output))
        return 0
    except (OSError, ValueError, SyntaxError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
