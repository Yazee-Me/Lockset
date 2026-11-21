# Install Lockset

Lockset is released privately on GitHub. The binaries are target archives on
the `v0.1.0` release; each has a published `.sha256`.

## Check what is already there

```sh
command -v lockset && lockset --version
sops --version                # needs 3.13 or newer
```

If `lockset` is missing, install it. If `sops` is missing or older, install
`sops` 3.13+ first (`brew install sops`, or the project's mise pin).

## Confirm access

```sh
gh auth status
```

The account must be able to read `Yazee-Me/Lockset`. The anonymous
`releases/latest/download/...` URLs return 404 for a private repository; do not
use the installer one-liner.

## Download the archive

```sh
mkdir -p ~/.local/bin
tmp=$(mktemp -d)
gh release download v0.1.0 --repo Yazee-Me/Lockset \
  --pattern 'lockset-aarch64-apple-darwin.tar.xz*' --dir "$tmp"
(cd "$tmp" && shasum -a 256 -c lockset-aarch64-apple-darwin.tar.xz.sha256 \
  && tar -xJf lockset-aarch64-apple-darwin.tar.xz)
install -m 0755 "$tmp/lockset-aarch64-apple-darwin/lockset" ~/.local/bin/lockset
rm -rf "$tmp"
lockset --version
```

Use `sha256sum -c` instead of `shasum -a 256 -c` on Linux. On Windows, unzip
the archive with `Expand-Archive` and put `lockset.exe` on `PATH`.

Replace the pattern with the machine's target:

| Platform | Asset |
| --- | --- |
| macOS Apple Silicon | `lockset-aarch64-apple-darwin.tar.xz` |
| macOS Intel | `lockset-x86_64-apple-darwin.tar.xz` |
| Linux x86_64 | `lockset-x86_64-unknown-linux-musl.tar.xz` (static) |
| Linux ARM64 | `lockset-aarch64-unknown-linux-musl.tar.xz` (static) |
| Windows x86_64 | `lockset-x86_64-pc-windows-msvc.zip` |

The GNU Linux archives also work on a glibc host; prefer musl for containers
and unknown hosts.

## PATH

Install to a directory already on `PATH` (`~/.local/bin` is common), or add it:

```sh
export PATH="$HOME/.local/bin:$PATH"       # put this in ~/.zshrc or ~/.bashrc
hash -r
```

## Upgrade

Download the new tag's archive and replace the binary; the release carries a
checksum for every archive. `lockset --version` must report the tag.

## No `gh`, or building from source

Download the archive from the private release page in a browser while signed
in to an account with access. Do not bypass the checksum.

From a clone:

```sh
git clone https://github.com/Yazee-Me/Lockset.git
cd Lockset
git checkout v0.1.0
mise install
mise run install            # links target/release/lockset into ~/.local/bin
```

## Container (optional)

The image is private and pins sops:

```sh
echo "$PAT" | docker login ghcr.io -u <user> --password-stdin   # PAT: read:packages
docker run --rm -v "$PWD:/repo" -w /repo \
  ghcr.io/yazee-me/lockset@sha256:c69124f9321ee15f3485b07f64f0a52571588ad216d3a36c01de976f71c3644a \
  --version
```

Mount the repository at `/repo`; the image runs as uid 10001 and does not
contain secrets.
