# Action fixture

`make.sh` builds the repository the composite-action test runs against:

- `secrets/dev.env` — a real sops-encrypted payload (`TOKEN=s3cret`).
- `.identity` — the throwaway age identity that decrypts it.
- `.sops.yaml` — one creation rule for `secrets/.*\.env$` with that recipient.

Everything is generated per run (`make.sh <dir>`), so no private key is
committed; `SOPS=<path>` selects the sops binary when it is not on `PATH`.
