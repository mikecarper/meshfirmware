#!/usr/bin/env bash

set -euo pipefail

# Ensure protoc is present
if ! command -v protoc >/dev/null 2>&1; then
    echo "protobuf-compiler not found – installing..."
    sudo apt update && sudo apt install -y protobuf-compiler
fi

PROTO_DIR="$HOME/meshtastic-protobufs"   # git clone https://github.com/meshtastic/protobufs.git
PROTO_FILE="meshtastic/apponly.proto"    # contains ChannelSet
URL="$1"                                 # share URL passed on the cmd-line

[ -d "$PROTO_DIR" ] || {
    echo "Meshtastic protobuf folder not found – cloning…"
    git clone https://github.com/meshtastic/protobufs.git "$PROTO_DIR"
}



# ---------- extract & pad Base-64 ----------
b64=${URL##*#}
case $(( ${#b64} % 4 )) in 2) b64+='==';; 3) b64+='=';; esac
b64=${b64//-/+}; b64=${b64//_/\/}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
echo "$b64" | base64 -d > "$tmp"

# ---------- decode proto text ----------
proto_txt=$(protoc --proto_path="$PROTO_DIR" \
                   --decode=meshtastic.ChannelSet "$PROTO_FILE" < "$tmp")

# ---------- pull PSK once & make Base-64 ----------
psk_b64=$(printf '%s\n' "$proto_txt" |
           awk '/psk:/ {match($0,/psk:[[:space:]]*"(.*)"/,m); print m[1]; exit}' |
           xargs printf '%b' | base64 -w0)

# ---------- parse & emit YAML ----------
printf '%s\n' "$proto_txt" | awk -v psk="$psk_b64" '
# --- helpers -------------------------------------------------------------
function trim(s){sub(/^[ \t\r\n]+/, "", s); sub(/[ \t\r\n]+$/, "", s); return s}
function drop_quotes(v){sub(/^"/,"",v); sub(/"$/,"",v); return v}
function camel(k){            # snake_case → camelCase
  while(match(k,/_./)){s=substr(k,RSTART+1,1); k=substr(k,1,RSTART-1) toupper(s) substr(k,RSTART+2)}
  return k
}
function print_channel(idx) {
  if(!idx) return
  printf "  -"
  if("name" in CH[idx]) {
    printf " name: \"%s\"\n", CH[idx]["name"]
    delete CH[idx]["name"]
  } else { print "" }
  if("psk" in CH[idx]) {
    printf "    psk: \"%s\"\n", CH[idx]["psk"]; delete CH[idx]["psk"]
  }
  for(k in CH[idx]) printf "    %s: %s\n", k, CH[idx][k]
}
# --- main ---------------------------------------------------------------
BEGIN{depth=0; inSet=0; inLora=0; chan_idx=0}
# open / close braces ----------------------------------------------------
/^{/ {depth++; next}
/^}/ {
  depth--
  if(inSet && depth==set_depth) { inSet=0; print_channel(chan_idx) }
  else if(inLora && depth==lora_depth) inLora=0
  next
}
# detect blocks ----------------------------------------------------------
/^settings[[:space:]]*{/   { inSet=1; set_depth=depth; ++chan_idx; next }
/^lora_config[[:space:]]*{/ { inLora=1; lora_depth=depth; next }
# collect settings -------------------------------------------------------
inSet && match($0,/^[ \t]*([^:]+):[ \t]*(.*)$/,m) {
  key=trim(m[1]); val=trim(m[2])
  val=drop_quotes(val)
  if(key=="psk") val=psk
  CH[chan_idx][key]=val
  next
}
# collect lora_config ----------------------------------------------------
inLora && match($0,/^[ \t]*([^:]+):[ \t]*(.*)$/,m) {
  key=camel(trim(m[1])); val=trim(m[2])
  val=drop_quotes(val)
  LORA[key]=val
  next
}
END{
  # ----- output YAML -----
  print "channels:"
  for(i=1;i<=chan_idx;i++) print_channel(i)

  print "config:"
  print "  lora:"
  # stable key order (matches your sample)
  order="configOkToMqtt hopLimit modemPreset region sx126xRxBoostedGain txEnabled txPower usePreset"
  n=split(order,arr," ")
  for(i=1;i<=n;i++){
     k=arr[i]; if(k in LORA) printf "    %s: %s\n", k, LORA[k]
  }
}
'


