#!/bin/sh
# Install a pinned lockset release for the current platform. Used by the
# composite action and runnable by hand:
#   scripts/ci-install.sh 0.1.0
#   scripts/ci-install.sh 0.1.0 file:///tmp/fake-release false
# Prints the directory holding the binary; the caller adds it to PATH.
set -eu

version=${1:?usage: ci-install.sh <version> [download-base-url] [verify-attestation]}
base=${2:-https://github.com/Yazee-Me/Lockset/releases/download}
verify=${3:-false}

case "$(uname -s)" in
    Linux) os=unknown-linux-musl ;;
    Darwin) os=apple-darwin ;;
    MINGW*|MSYS*|CYGWIN*) os=pc-windows-msvc ;;
    *) echo "unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    arm64|aarch64) arch=aarch64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

case "$os" in
    pc-windows-*) target="$arch-$os"; ext=zip ;;
    *) target="$arch-$os"; ext=tar.xz ;;
esac

url="$base/v$version/lockset-$target.$ext"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "downloading $url" >&2
# A private release needs a token. Pass it through stdin so it never appears in
# curl's argv; the action supplies LOCKSET_GITHUB_TOKEN.
fetch() {
    if [ -n "${LOCKSET_GITHUB_TOKEN:-}" ]; then
        printf 'Authorization: Bearer %s\n' "$LOCKSET_GITHUB_TOKEN" |
            curl -fsSL -H @- -o "$1" "$2"
    else
        curl -fsSL -o "$1" "$2"
    fi
}

# GitHub's public download URL returns 404 for a private repository even with
# an authorization header. The API (through gh) is the supported path; other
# bases, including mirrors and the test server, use plain curl.
if [ -n "${LOCKSET_GITHUB_TOKEN:-}" ] &&
    [ "$base" = "https://github.com/Yazee-Me/Lockset/releases/download" ]; then
    if ! command -v gh >/dev/null 2>&1; then
        echo "gh is required to download a private release" >&2
        exit 1
    fi
    GH_TOKEN=$LOCKSET_GITHUB_TOKEN gh release download "v$version" \
        --repo Yazee-Me/Lockset \
        --pattern "lockset-$target.$ext" \
        --pattern "lockset-$target.$ext.sha256" \
        --dir "$work" --clobber
    mv "$work/lockset-$target.$ext" "$work/archive"
    mv "$work/lockset-$target.$ext.sha256" "$work/archive.sha256"
else
    fetch "$work/archive" "$url"
    fetch "$work/archive.sha256" "$url.sha256"
fi

expected=$(awk '{print $1}' "$work/archive.sha256")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$work/archive" | awk '{print $1}')
else
    actual=$(shasum -a 256 "$work/archive" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || {
    echo "checksum mismatch for $url" >&2
    echo "expected $expected" >&2
    echo "actual   $actual" >&2
    exit 1
}
echo "checksum ok: $expected" >&2

if [ "$verify" = "true" ]; then
    if command -v gh >/dev/null 2>&1; then
        gh attestation verify "$work/archive" --repo Yazee-Me/Lockset >&2
    else
        echo "gh is not installed; skipping the GitHub artifact attestation check" >&2
    fi
fi

mkdir -p "$work/unpacked"
case "$ext" in
    zip)
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "$work/archive" -d "$work/unpacked"
        else
            tar -xf "$work/archive" -C "$work/unpacked"
        fi
        ;;
    *) tar -xJf "$work/archive" -C "$work/unpacked" ;;
esac
binary=$(find "$work/unpacked" -type f -name 'lockset*' ! -name '*.sha256' | head -1)
[ -n "$binary" ] || { echo "no lockset binary in $url" >&2; exit 1; }
chmod +x "$binary"

dest="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/lockset-bin"
rm -rf "$dest"
mkdir -p "$dest"
cp "$binary" "$dest/"
"$dest/lockset" --version >&2
printf '%s\n' "$dest"
