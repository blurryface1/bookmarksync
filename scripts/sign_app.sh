#!/bin/bash
# Import only into a disposable keychain; never change the login/default keychain.
set -euo pipefail
: "${MACOS_SIGNING_P12_BASE64:?Signing certificate secret is required}"
: "${MACOS_SIGNING_P12_PASSWORD:?Signing certificate password secret is required}"
APP_PATH="${1:?Usage: sign_app.sh path/to/BookmarkSync.app}"
SIGNING_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERTIFICATE="$SIGNING_ROOT/signing/BookmarkSync-Signing.crt"
IDENTITY="$(openssl x509 -in "$CERTIFICATE" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
WORK_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bookmarksync-signing.XXXXXX")"
KEYCHAIN_PATH="$WORK_DIR/signing.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -hex 32)"
PREV_KEYCHAINS=()
while IFS= read -r line; do
    kc="${line#*\"}"
    kc="${kc%\"*}"
    if [[ -n "$kc" ]]; then
        PREV_KEYCHAINS+=("$kc")
    fi
done < <(security list-keychains -d user)
cleanup() {
    if ((${#PREV_KEYCHAINS[@]} > 0)); then
        security list-keychains -d user -s "${PREV_KEYCHAINS[@]}" >/dev/null 2>&1 || true
    fi
    security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
umask 077
printf '%s' "$MACOS_SIGNING_P12_BASE64" | /usr/bin/base64 --decode > "$WORK_DIR/signing.p12"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 3600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
if ((${#PREV_KEYCHAINS[@]} > 0)); then
    security list-keychains -d user -s "$KEYCHAIN_PATH" "${PREV_KEYCHAINS[@]}"
else
    security list-keychains -d user -s "$KEYCHAIN_PATH"
fi
security import "$WORK_DIR/signing.p12" -k "$KEYCHAIN_PATH" -P "$MACOS_SIGNING_P12_PASSWORD" -T /usr/bin/codesign -A >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null
security find-identity -p codesigning "$KEYCHAIN_PATH"
codesign --force --deep --timestamp=none --keychain "$KEYCHAIN_PATH" --sign "$IDENTITY" "$APP_PATH"
codesign --verify --deep --strict "$APP_PATH"
# Explicitly check that the app is anchored to the committed public certificate.
codesign --verify -R "=identifier \"app.xazi.BookmarkSync\" and anchor H\"$IDENTITY\"" "$APP_PATH"
codesign --display --requirements - "$APP_PATH" > "$WORK_DIR/requirements.txt" 2>&1
cat "$WORK_DIR/requirements.txt"
if grep -q 'cdhash' "$WORK_DIR/requirements.txt"; then
    echo 'Error: signature identity is tied to this build instead of the certificate.' >&2
    exit 1
fi
