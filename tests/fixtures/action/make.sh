#!/bin/sh
# Build the fixture repository the action test runs against: a repository with
# one sops-encrypted payload and a throwaway age identity. Everything is
# generated per run, so no key is ever committed.
#   make.sh <dir>            (needs age-keygen and sops on PATH; SOPS overrides)
set -eu

dir=${1:?usage: make.sh <dir>}
sops=${SOPS:-sops}
command -v age-keygen >/dev/null 2>&1 || { echo "age-keygen is required" >&2; exit 1; }
command -v "$sops" >/dev/null 2>&1 || { echo "sops is required (SOPS=<path> to override)" >&2; exit 1; }

rm -rf "$dir"
mkdir -p "$dir/secrets"

age-keygen -o "$dir/.identity" 2>/dev/null
chmod 0600 "$dir/.identity"
recipient=$(grep -o 'age1[0-9a-z]*' "$dir/.identity" | head -1)
[ -n "$recipient" ] || { echo "could not read the generated recipient" >&2; exit 1; }

printf 'creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: %s # admin\n' "$recipient" \
    > "$dir/.sops.yaml"
printf 'TOKEN=s3cret\n' > "$dir/secrets/plain.env"
"$sops" --encrypt --age "$recipient" --input-type dotenv --output-type dotenv \
    "$dir/secrets/plain.env" > "$dir/secrets/dev.env"
rm "$dir/secrets/plain.env"

grep -q 'ENC\[' "$dir/secrets/dev.env" || { echo "payload was not encrypted" >&2; exit 1; }
echo "fixture ready: $dir (identity: .identity, payload: secrets/dev.env)"
