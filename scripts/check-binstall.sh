#!/bin/sh
# Validate the [package.metadata.binstall] template against what a tag would
# publish: every release archive a supported target needs must exist in the
# cargo-dist plan, with the binary layout binstall expects.
# Requires `cargo` and `dist` (cargo-dist) on PATH.
set -eu

version=$(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "lockset"))')
plan=$(dist plan --tag="v$version" --output-format=json)

python3 - "$version" <<PY
import json, subprocess, sys

version = sys.argv[1]
meta = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"]))
package = next(p for p in meta["packages"] if p["name"] == "lockset")
binstall = package["metadata"]["binstall"]
plan = json.loads(subprocess.check_output(["dist", "plan", "--tag", f"v{version}", "--output-format=json"]))
artifacts = plan["artifacts"]

def expand(template, target, fmt):
    return (template
            .replace("{ repo }", package["repository"])
            .replace("{ version }", version)
            .replace("{ name }", package["name"])
            .replace("{ target }", target)
            .replace("{ archive-format }", fmt)
            .replace("{ binary-ext }", ".exe" if "windows" in target else ""))

targets = {}
for name in artifacts:
    for target in artifacts[name].get("target_triples", []):
        if artifacts[name]["kind"] == "executable-zip":
            targets[target] = artifacts[name]["name"]

if len(targets) < 7:
    sys.exit(f"expected the seven release targets, found {sorted(targets)}")

overrides = binstall.get("overrides", {})
for target, archive in sorted(targets.items()):
    settings = dict(binstall)
    settings.update(overrides.get(target, {}))
    fmt = settings["pkg-fmt"]
    expected = f"{package['name']}-{target}." + ("zip" if fmt == "zip" else "tar.xz")
    if expected != archive:
        sys.exit(f"{target}: binstall would fetch {expected}, the release publishes {archive}")
    url = expand(settings["pkg-url"], target, "zip" if fmt == "zip" else "tar.xz")
    if not url.endswith("/" + archive):
        sys.exit(f"{target}: pkg-url does not end with the published archive: {url}")
    binary = expand(settings["bin-dir"], target, "")
    want = f"lockset-{target}/lockset" + (".exe" if "windows" in target else "")
    if binary != want:
        sys.exit(f"{target}: bin-dir is {binary}, the archive holds {want}")

print(f"binstall metadata matches the {len(targets)} release archives for v{version}")
PY
