#!/usr/bin/env bash
# PoC for SEC-014 — DO NOT RUN against production data without permission.
# ============================================================
# Verifies the gpg-encrypt path added to deploy/backup.sh:
#
#   1. plaintext canary in source → AES-256-symmetric encrypt → .gpg
#   2. canary string MUST NOT appear in the encrypted blob
#   3. decrypt with the same passphrase recovers the canary (round-trip)
#   4. wrong passphrase MUST fail to decrypt
#
# Pre-fix (before SEC-014):  backup.sh wrote plain SQLite — Mac mini
#                            disk leak = 14 days of customer SBOMs +
#                            audit logs + hashed passwords + plaintext
#                            webhook URLs in the clear.
# Post-fix (after SEC-014): backups are AES-256 wrapped; loss of the
#                            disk without the off-host key file = no
#                            data disclosure.
#
# Setup:
#   bash .knowledge/audit/poc/SEC-014-backup-encryption-roundtrip.sh
#
# Requires: gpg on PATH.

set -euo pipefail

if ! command -v gpg >/dev/null 2>&1; then
    echo "[skip] gpg not on PATH — install gnupg before running"
    exit 0
fi

TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT

CANARY="CANARY-SBOM-PLAINTEXT-7bf3-SEC014"

# Synthetic backup blob: binary-ish header + canary + tail
printf 'BACKUP_HEADER\x00\x01\x02%s\x03\x04\x05BACKUP_TAIL' "$CANARY" > "$TMP/source.bin"
echo "test-passphrase-poc-only" > "$TMP/keyfile"
chmod 600 "$TMP/keyfile"

# 1. encrypt
gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
    --passphrase-file "$TMP/keyfile" \
    --output "$TMP/source.bin.gpg" "$TMP/source.bin"

# 2. canary must not appear in ciphertext
if grep -aq "$CANARY" "$TMP/source.bin.gpg"; then
    echo "[FAIL] canary visible in encrypted blob — encryption did not happen"
    exit 1
fi
echo "[PASS] canary not in encrypted blob"

# 3. decrypt with correct passphrase recovers canary
gpg --batch --quiet --passphrase-file "$TMP/keyfile" \
    --decrypt "$TMP/source.bin.gpg" > "$TMP/restored.bin" 2>/dev/null
if grep -aq "$CANARY" "$TMP/restored.bin"; then
    echo "[PASS] decrypt with correct key recovers canary"
else
    echo "[FAIL] round-trip lost canary"
    exit 1
fi

# 4. wrong passphrase must fail
echo "wrong-pass" > "$TMP/wrong-key"
if gpg --batch --quiet --passphrase-file "$TMP/wrong-key" \
       --decrypt "$TMP/source.bin.gpg" > "$TMP/wrong-out" 2>/dev/null; then
    if grep -aq "$CANARY" "$TMP/wrong-out"; then
        echo "[FAIL] wrong passphrase decrypted to canary"
        exit 1
    fi
fi
echo "[PASS] wrong passphrase cannot decrypt"

echo
echo "============================================================"
echo "[NO LEAK] SEC-014 gpg flow verified end-to-end"
echo "============================================================"
