#!/usr/bin/env python3
"""
encode_meshtastic.py   (pure-stdlib + PyYAML)

STDIN (or -f yaml_file)  →  https://meshtastic.org/e/#<payload>

Requires only:
  • python3-yaml   (PyYAML distro package)
  • git + protobuf-compiler (for protoc --encode)
"""

import argparse, base64, os, re, shutil, subprocess, sys, yaml
from collections import OrderedDict

# ─────────────────────────────────────────────────────────────────────────────
def need(tool):
    if shutil.which(tool) is None:
        sys.exit(f"'{tool}' not in PATH – install it first.")

def snake(s):                                  # camelCase → snake_case
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()

def psk_raw_from_b64(b64str):                  # Base-64 → text-proto escapes
    raw = base64.b64decode(b64str)
    return "".join(f"\\{i:03o}" for i in raw)  # octal escapes

# ─────────────────────────────────────────────────────────────────────────────
def yaml_to_textproto(data):
    """Turn our YAML dict into the text-proto expected by ChannelSet."""
    out = []

    # --- settings (channels) -------------------------------------------------
    for ch in data.get("channels", []):
        out.append("settings {")
        # name / psk first
        for key in ("name", "psk"):
            if key in ch:
                if key == "psk":
                    val = psk_raw_from_b64(ch[key])
                    out.append(f'  psk: "{val}"')
                else:
                    out.append(f'  name: "{ch[key]}"')
        # remainder (nested dicts handled too)
        for k, v in ch.items():
            if k in ("name", "psk"): continue
            if isinstance(v, dict):
                out.append(f"  {k} {{")
                for sk, sv in v.items():
                    out.append(f"    {snake(sk)}: {sv}")
                out.append("  }")
            else:
                out.append(f"  {snake(k)}: {str(v).lower() if isinstance(v,bool) else v}")
        out.append("}")

    # --- lora_config ---------------------------------------------------------
    out.append("lora_config {")
    for k, v in data.get("config", {}).get("lora", {}).items():
        proto_key = snake(k)
        out.append(f"  {proto_key}: {str(v).lower() if isinstance(v,bool) else v}")
    out.append("}")

    return "\n".join(out) + "\n"

# ─────────────────────────────────────────────────────────────────────────────
def main():
    need("git"); need("protoc")

    ap = argparse.ArgumentParser(description="YAML → Meshtastic share URL")
    ap.add_argument("yaml", nargs="?", help="YAML file (default: stdin)")
    args = ap.parse_args()

    # Decide where to read from:
    #  • if a filename was given and not "-", read that file
    #  • else read stdin
    if args.yaml and args.yaml != "-":
        yaml_src = open(args.yaml, "r", encoding="utf-8")
    else:
        yaml_src = sys.stdin

    data = yaml.safe_load(yaml_src)
    if yaml_src is not sys.stdin:
        yaml_src.close()

    home = os.path.expanduser("~")
    proto_repo = os.path.join(home, "meshtastic-protobufs")
    if not os.path.isdir(proto_repo):
        print("Cloning Meshtastic protobuf repo …")
        subprocess.check_call(
            ["git", "clone", "https://github.com/meshtastic/protobufs.git", proto_repo]
        )

    text_proto = yaml_to_textproto(data)

    # --- encode -------------------------------------------------------------
    proc = subprocess.run(
        ["protoc",
         f"-I{proto_repo}",
         "--encode=meshtastic.ChannelSet",
         "meshtastic/apponly.proto"],
        input=text_proto.encode(),
        stdout=subprocess.PIPE,
        check=True,
    )
    binary = proc.stdout
    b64 = base64.b64encode(binary).decode().rstrip("=") \
           .replace("+", "-").replace("/", "_")  # URL-safe, no padding

    print(f"https://meshtastic.org/e/#{b64}")

if __name__ == "__main__":
    main()

