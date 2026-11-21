# Run Lockset in CI

The identity is the only secret the pipeline needs. Keep it in the CI secret
store, never in the repository, and never in a command line.

## GitHub Actions (composite action)

The repository is private, so the caller must pass a token with read access to
`Yazee-Me/Lockset`:

```yaml
- uses: Yazee-Me/Lockset@v0.1.0
  env:
    LOCKSET_AGE_KEY: ${{ secrets.LOCKSET_AGE_KEY }}
  with:
    github-token: ${{ secrets.LOCKSET_TOKEN }}   # read access to Yazee-Me/Lockset
    version: 0.1.0
    payload: secrets/prod/deploy.env
    command: ./deploy.sh
```

`command` runs through `lockset run --payload ... -- bash -c ...`, so the child
gets the values and not the identity. To export values instead:

```yaml
- uses: Yazee-Me/Lockset@v0.1.0
  env:
    LOCKSET_AGE_KEY: ${{ secrets.LOCKSET_AGE_KEY }}
  with:
    github-token: ${{ secrets.LOCKSET_TOKEN }}
    version: 0.1.0
    payload: secrets/prod/deploy.env
    export-env: "true"
```

Exported values are masked with `::add-mask::` before reaching `$GITHUB_ENV`.
The action verifies the archive checksum; attestation verification is off
while the release is private (`verify-attestation: "true"` once public
attestations exist).

## Other CI: install the binary

```sh
# GH_TOKEN must be able to read the private repository.
gh release download v0.1.0 --repo Yazee-Me/Lockset \
  --pattern 'lockset-x86_64-unknown-linux-musl.tar.xz*' --dir /tmp/lockset
(cd /tmp/lockset && sha256sum -c lockset-x86_64-unknown-linux-musl.tar.xz.sha256 \
  && tar -xJf lockset-x86_64-unknown-linux-musl.tar.xz)
install -m 0755 /tmp/lockset/lockset-x86_64-unknown-linux-musl/lockset /usr/local/bin/
lockset --version
```

The `lockset` and `lockset-core` crates are not on crates.io, so
`cargo install lockset` does not work. Build from source only if the release
archive cannot be fetched.

## Custody in CI

Set the identity through a masked variable:

```sh
export LOCKSET_AGE_KEY="$LOCKSET_AGE_KEY"   # already provided by the CI secret store
lockset doctor                              # fails before any secret is touched
lockset run --payload secrets/prod/deploy.env -- ./deploy.sh
```

Or mount a key file and select it explicitly:

```sh
lockset doctor --custody file:/run/secrets/age-key
lockset run --custody file:/run/secrets/age-key --payload secrets/prod/deploy.env -- ./deploy.sh
```

Non-interactive `auto` does not use the keychain. Without an explicit source
the command exits 3 with `no identity in custody`.

## Container (optional)

The image is private and contains the pinned `sops`:

```yaml
# GitLab CI
deploy:
  image:
    name: ghcr.io/yazee-me/lockset@sha256:c69124f9321ee15f3485b07f64f0a52571588ad216d3a36c01de976f71c3644a
    entrypoint: [""]
  variables:
    LOCKSET_AGE_KEY: $LOCKSET_AGE_KEY   # masked CI variable
  script:
    - lockset doctor
    - lockset run --payload secrets/prod/deploy.env -- ./deploy.sh
```

Docker pulls need `read:packages` on the registry token:
`echo "$PAT" | docker login ghcr.io -u <user> --password-stdin`.

## Ground rules

- Run `lockset doctor` before the first mutation; treat exit 1 as a failing job.
- Mask every exported value; never `echo` a decrypted payload.
- Do not put the age identity in the workflow file, a build arg, or a command
  line.
- Do not use the anonymous `releases/latest/download/...` installer while the
  repository is private; it returns 404.
