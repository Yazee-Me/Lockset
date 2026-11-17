#!/bin/sh
# Install a pinned lockset release for the current platform. Used by the
# composite action and runnable by hand:
#   scripts/ci-install.sh 0.1.0
#   scripts/ci-install.sh 0.1.0 file:///tmp/fake-release false
# Prints the directory holding the binary; the caller adds it to PATH.
set -eu

version=${1:?usage: ci-install.sh <version> [download-base-url] [verify-attestation]}
base=${2:-https://github.com/Yazee-Me/Lockset/releases/download}
verify=${3:-true}

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
curl -fsSLo "$work/archive" "$url"
curl -fsSLo "$work/archive.sha256" "$url.sha256"

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
