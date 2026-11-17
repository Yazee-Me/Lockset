#!/bin/sh
# Smoke-test a lockset image: doctor and run with the image's own pinned sops,
# a real sops-encrypted payload, env and file custody, non-root, and no secrets
# in the layers. Usage: container-smoke.sh <image>
set -eu

image=${1:?usage: container-smoke.sh <image>}
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v age-keygen >/dev/null 2>&1 || {
    echo "age-keygen is required (install the age package) to create the test identity" >&2
    exit 1
}

work=$(mktemp -d)
keydir=$(mktemp -d)
cleanup() { rm -rf "$work" "$keydir"; }
trap cleanup EXIT
mkdir -p "$work/secrets"

age-keygen -o "$work/age-key.txt" 2>/dev/null
recipient=$(grep -o 'age1[0-9a-z]*' "$work/age-key.txt" | head -1)
chmod 0600 "$work/age-key.txt"

printf 'creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: %s # admin\n' "$recipient" \
    > "$work/.sops.yaml"
printf 'TOKEN=s3cret\n' > "$work/secrets/plain.env"

# The image runs as uid 10001, and a bind mount keeps host ownership on Linux
# runners; `mktemp -d` is 0700, so the container cannot even traverse $work.
# Docker Desktop on macOS hides this by remapping ownership.
chmod -R a+rX "$work"

echo "== the image ships a pinned sops"
docker run --rm --entrypoint sops "$image" --version

echo "== encrypt with the image's sops (public key only)"
docker run --rm -v "$work:/repo" -w /repo --entrypoint sops "$image" \
    --encrypt --age "$recipient" --input-type dotenv --output-type dotenv \
    secrets/plain.env > "$work/secrets/dev.env"
rm "$work/secrets/plain.env"
grep -q 'ENC\[' "$work/secrets/dev.env" || { echo "payload was not encrypted" >&2; exit 1; }

echo "== doctor with env custody"
doctor=$(docker run --rm -e LOCKSET_AGE_KEY="$(cat "$work/age-key.txt")" \
    -v "$work:/repo" -w /repo "$image" doctor)
printf '%s\n' "$doctor"
printf '%s\n' "$doctor" | grep -q '^sops .*ok' || { echo "doctor did not accept sops" >&2; exit 1; }
printf '%s\n' "$doctor" | grep -q '^identity .*ok' || { echo "doctor did not accept the identity" >&2; exit 1; }

echo "== run with env custody"
docker run --rm -e LOCKSET_AGE_KEY="$(cat "$work/age-key.txt")" \
    -v "$work:/repo" -w /repo "$image" \
    run --payload secrets/dev.env -- sh -c 'test "$TOKEN" = s3cret'

echo "== file custody, with the container running as the file's owner"
mkdir -p "$keydir/run/secrets"
cp "$work/age-key.txt" "$keydir/run/secrets/age-key"
chmod 0600 "$keydir/run/secrets/age-key"
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$work:/repo" -v "$keydir/run/secrets:/run/secrets:ro" -w /repo "$image" \
    --custody file:/run/secrets/age-key status >/dev/null
echo "status via file custody: ok"

echo "== non-root by default"
uid=$(docker run --rm --entrypoint id "$image" -u)
[ "$uid" = "10001" ] || { echo "expected uid 10001, got $uid" >&2; exit 1; }

echo "== no secrets in the image or its layers"
if docker history --no-trunc "$image" | grep -q 'AGE-SECRET-KEY'; then
    echo "the image history contains a private key" >&2
    exit 1
fi
if docker run --rm --entrypoint sh "$image" -c 'test -e /repo/.sops.yaml -o -e /repo/secrets'; then
    echo "the image workspace is not empty" >&2
    exit 1
fi

echo "container smoke test passed: doctor, run, sops, non-root, no baked secrets"
