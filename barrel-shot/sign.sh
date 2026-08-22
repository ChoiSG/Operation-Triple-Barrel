#!/bin/bash
set -e

INPUT_DLL="$1"
OUTPUT_DLL="$2"

if [ -z "$INPUT_DLL" ] || [ -z "$OUTPUT_DLL" ]; then
    echo "[sign] usage: sign.sh <input-dll> <output-dll>"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

SUBJECT=""

# Try osslsigncode verify to get the actual signer subject (not the CA chain)
if osslsigncode extract-signature -pem -in "$INPUT_DLL" -out "$TMPDIR/sig.pem" 2>/dev/null; then
    openssl pkcs7 -in "$TMPDIR/sig.pem" -inform PEM -print_certs -out "$TMPDIR/chain.pem" 2>/dev/null || true
    if [ -s "$TMPDIR/chain.pem" ]; then
        # Split PEM chain into individual certs
        csplit -z -f "$TMPDIR/cert-" -b '%02d.pem' "$TMPDIR/chain.pem" \
            '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null || true

        # Find the end-entity code-signing cert (has codeSigning EKU, is not a CA)
        for CERT in "$TMPDIR"/cert-*.pem; do
            [ -s "$CERT" ] || continue
            # Skip CA certs
            if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
                continue
            fi
            # Prefer certs with Code Signing EKU
            if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -q "Code Signing"; then
                RAW=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | sed 's/^subject= *//; s/^subject=//')
                if [ -n "$RAW" ]; then
                    if [ "${RAW:0:1}" != "/" ]; then
                        SUBJECT="/$(echo "$RAW" | sed 's/ *= */=/g; s/, */\//g')"
                    else
                        SUBJECT="$RAW"
                    fi
                    break
                fi
            fi
        done

        # Fallback: first non-CA cert if no code signing EKU found
        if [ -z "$SUBJECT" ]; then
            for CERT in "$TMPDIR"/cert-*.pem; do
                [ -s "$CERT" ] || continue
                if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
                    continue
                fi
                RAW=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | sed 's/^subject= *//; s/^subject=//')
                if [ -n "$RAW" ]; then
                    if [ "${RAW:0:1}" != "/" ]; then
                        SUBJECT="/$(echo "$RAW" | sed 's/ *= */=/g; s/, */\//g')"
                    else
                        SUBJECT="$RAW"
                    fi
                    break
                fi
            done
        fi
    fi
fi

if [ -z "$SUBJECT" ]; then
    BASENAME=$(basename "$INPUT_DLL" .dll)
    SUBJECT="/CN=$BASENAME/O=$BASENAME"
    echo "[sign] No Authenticode signature in $(basename "$INPUT_DLL"), using fallback: $SUBJECT"
else
    echo "[sign] Cloned subject: $SUBJECT"
fi

openssl req -x509 -newkey rsa:2048 \
    -keyout "$TMPDIR/key.pem" -out "$TMPDIR/cert.pem" \
    -days 365 -nodes -subj "$SUBJECT" \
    -addext "extendedKeyUsage=codeSigning" 2>/dev/null

TS_URL="${TIMESTAMP_URL:-http://timestamp.sectigo.com/rfc3161}"

osslsigncode sign \
    -certs "$TMPDIR/cert.pem" -key "$TMPDIR/key.pem" \
    -h sha256 -n "$(basename "$OUTPUT_DLL")" \
    -ts "$TS_URL" \
    -in "$OUTPUT_DLL" -out "$TMPDIR/signed.dll"

mv "$TMPDIR/signed.dll" "$OUTPUT_DLL"
echo "[sign] Signed $(basename "$OUTPUT_DLL")"
