#!/usr/bin/env python3
"""
decode_meshtastic.py  –  Meshtastic share-URL → YAML

Pure standard-library solution:
  • clones the Meshtastic protobuf repo (once, to ~/meshtastic-protobufs)
  • uses `protoc --decode` to dump the ChannelSet in text format
  • parses that text and emits YAML with the exact layout requested

Requires only two CLI tools already in Ubuntu/Debian repos:
  sudo apt install git protobuf-compiler
"""

import argparse, base64, os, re, shutil, subprocess, sys
from collections import OrderedDict

# -----------------------------------------------------------------------------
# helpers ---------------------------------------------------------------------
def need(tool: str):
    if shutil.which(tool) is None:
        sys.exit(f"'{tool}' not found in PATH – please install it.")

def camel(s: str) -> str:
    """snake_case -> camelCase"""
    return re.sub(r"_([a-z])", lambda m: m.group(1).upper(), s, 0)

def b64_from_raw(proto_bytes: str) -> str:
    """turn text-proto escape string (e.g. '\\001') → base-64"""
    raw = bytes(proto_bytes, "latin1").decode("unicode_escape").encode("latin1")
    return base64.b64encode(raw).decode()

def yaml_dump(obj, indent=0):
    sp = "  " * indent
    if isinstance(obj, list):
        for item in obj:
            print(sp + "-", end="")
            if isinstance(item, (dict, list)):
                print()
                yaml_dump(item, indent + 1)
            else:
                print(f" {item if not isinstance(item,str) else repr(item)}")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                print(f"{sp}{k}:")
                yaml_dump(v, indent + 1)
            else:
                out = v if not isinstance(v, str) else f"\"{v}\""
                print(f"{sp}{k}: {out}")

# -----------------------------------------------------------------------------
def main():
    need("git"); need("protoc")

    ap = argparse.ArgumentParser(description="Meshtastic share URL → YAML")
    ap.add_argument(
        "url",
        nargs="?",                         # <- optional now
        help="Meshtastic share URL (reads stdin if omitted)",
    )
    args = ap.parse_args()

    # -------- where to get the URL string ----------
    if args.url and args.url != "-":
        url_text = args.url
    else:                                  # piped or '-' sentinel
        url_text = sys.stdin.read().strip()
        if not url_text:
            sys.exit("No URL provided on stdin.")
    # Grab the first token that looks like a share-URL
    m = re.search(r"https?://\S+#\w+", url_text)
    if not m:
        sys.exit("Could not find a share-URL in the input.")
    url = m.group(0)

    # ---- make sure the protobuf repo is ready -----------------------------
    home = os.path.expanduser("~")
    proto_repo = os.path.join(home, "meshtastic-protobufs")
    if not os.path.isdir(proto_repo):
        print("Cloning Meshtastic protobuf repo …")
        subprocess.check_call(
            ["git", "clone",
             "https://github.com/meshtastic/protobufs.git", proto_repo]
        )

    # ---- extract + pad Base-64 ---------------------------------------------
    b64 = url.split("#")[-1].replace("-", "+").replace("_", "/")
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    binary = base64.b64decode(b64)

    # ---- protoc → text-proto ----------------------------------------------
    proc = subprocess.run(
        [
            "protoc",
            f"-I{proto_repo}",
            "--decode=meshtastic.ChannelSet",
            "meshtastic/apponly.proto",
        ],
        input=binary,
        stdout=subprocess.PIPE,
        check=True,
    )
    text = proc.stdout.decode()

    # ---- parse text-proto --------------------------------------------------
    root = OrderedDict(channels=[], config=OrderedDict(lora=OrderedDict()))
    stack = []  # stack of dicts
    cur = None

    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if ln.endswith("{"):                     # open block
            key = ln[:-1].strip()
            new = OrderedDict()
            if key == "settings":
                root["channels"].append(new); cur = new
            elif key == "lora_config":
                cur = root["config"]["lora"]
            else:
                cur[key] = new; cur = new
            stack.append(cur)
            continue
        if ln == "}":                            # close block
            stack.pop()
            cur = stack[-1] if stack else None
            continue

        # key: value line
        k, v = map(str.strip, ln.split(":", 1))
        if k == "psk":
            v = b64_from_raw(v.strip('"'))
        elif v.startswith('"'):
            v = v.strip('"')
        elif v in ("true", "false"):
            v = v == "true"
        else:
            try:
                v = int(v)
            except ValueError:
                try:
                    v = float(v)
                except ValueError:
                    pass
        if cur is root["config"]["lora"]:
            k = camel(k)
        cur[k] = v

    # ---- reorder channels (name, psk first) --------------------------------
    for ch in root["channels"]:
        ordered = OrderedDict()
        if "name" in ch:
            ordered["name"] = ch.pop("name")
        if "psk" in ch:
            ordered["psk"] = ch.pop("psk")
        ordered.update(ch)
        ch.clear(); ch.update(ordered)

    # ---- preferred order inside lora block ---------------------------------
    lora = root["config"]["lora"]
    lora_pref = sorted(lora.keys())  
    ordered_lora = OrderedDict()
    for k in lora_pref:
        if k in lora:
            ordered_lora[k] = lora.pop(k)
    ordered_lora.update(lora)            # any leftovers
    root["config"]["lora"] = ordered_lora

    # ---- YAML out ----------------------------------------------------------
    yaml_dump(root)

if __name__ == "__main__":
    main()

