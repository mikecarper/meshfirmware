"""Native child fixture for PS5 dependency-launcher regression tests; no pip/USB."""

import os
import sys

assert sys.argv[1:] == ["dependencies", "--install", "--text"], sys.argv
print("meshcore: installed 2.3.9.1; supported >=2.3.9,<3.0.0; API OK", flush=True)
print("meshcore-cli: installed 1.6.3; supported >=1.6.3,<2.0.0; API OK", flush=True)
print("PyNaCl: installed 1.6.2; supported >=1.5.0,<2.0.0; API OK", flush=True)
print("harmless pip stderr diagnostic", file=sys.stderr, flush=True)
print("", file=sys.stderr, flush=True)
raise SystemExit(int(os.environ.get("MESHFIRMWARE_TEST_DEPENDENCY_EXIT", "0")))
