#!/bin/sh
# Verify a directory of release artifacts the way a user would: check every
# published SHA-256 against its archive, unpack it, and run the binary. Used by
# the release-verify workflow and runnable by hand after `dist build`.
set -eu

dir=${1:?usage: verify-artifacts.sh <artifact-dir>}

hash_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

checked=0
for sum in "$dir"/*.sha256; do
    [ -e "$sum" ] || continue
    line=$(cat "$sum")
    expected=$(printf '%s' "$line" | awk '{print $1}')
    name=$(printf '%s' "$line" | awk '{print $2}')
    name=${name#\*}
    [ -f "$dir/$name" ] || { echo "checksum names a missing file: $name" >&2; exit 1; }
    actual=$(hash_of "$dir/$name")
    [ "$actual" = "$expected" ] || { echo "checksum mismatch: $name" >&2; exit 1; }
    echo "$name: OK"
    checked=$((checked + 1))
done

# The combined SHA256SUMS file, when the release has one.
if [ -e "$dir/SHA256SUMS" ]; then
    while read -r expected name; do
        [ -n "$name" ] || continue
        name=${name#\*}
        [ -f "$dir/$name" ] || { echo "SHA256SUMS names a missing file: $name" >&2; exit 1; }
        actual=$(hash_of "$dir/$name")
        [ "$actual" = "$expected" ] || { echo "SHA256SUMS mismatch: $name" >&2; exit 1; }
        checked=$((checked + 1))
    done < "$dir/SHA256SUMS"
    echo "SHA256SUMS: OK"
fi

if [ "$checked" -eq 0 ]; then
    echo "no checksums in $dir" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

unpacked=0
for archive in "$dir"/*.tar.xz "$dir"/*.tar.gz "$dir"/*.zip; do
    [ -e "$archive" ] || continue
    case "$archive" in
        *.zip)
            command -v unzip >/dev/null 2>&1 || { echo "unzip missing for $archive" >&2; exit 1; }
            unzip -q "$archive" -d "$work"
            ;;
        *.tar.gz) tar -xzf "$archive" -C "$work" ;;
        *) tar -xJf "$archive" -C "$work" ;;
    esac
    unpacked=$((unpacked + 1))
done

if [ "$unpacked" -eq 0 ]; then
    echo "no archives in $dir" >&2
    exit 1
fi

# Run the binary this host can execute; a foreign-target archive only gets its
# checksum verified above.
ran=0
for binary in "$work"/*/lockset "$work"/*/lockset.exe; do
    [ -x "$binary" ] || continue
    "$binary" --version
    "$binary" --help >/dev/null
    ran=$((ran + 1))
done

echo "verified $checked checksum(s), $unpacked archive(s), $ran local binary/ies"
[ "$ran" -gt 0 ] || echo "no binary runs on this host (foreign target)"
