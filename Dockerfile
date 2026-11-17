# syntax=docker/dockerfile:1
#
# ghcr.io/yazee-me/lockset: lockset plus the sops it runs, on a small runtime
# image, as a non-root user. Build for a platform with buildx
# (`--platform linux/amd64` / `linux/arm64`); the binary is compiled for that
# platform, and sops is pinned by version and SHA-256 per architecture.

ARG RUST_VERSION=1.99
FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY lockset-core/Cargo.toml lockset-core/Cargo.toml
COPY lockset-tools/Cargo.toml lockset-tools/Cargo.toml
COPY lockset/Cargo.toml lockset/Cargo.toml
COPY lockset-core/src lockset-core/src
COPY lockset-tools/src lockset-tools/src
COPY lockset/src lockset/src
RUN cargo build --release --locked -p lockset --bin lockset

# The sops release assets and their checksums from
# https://github.com/getsops/sops/releases/download/v3.13.3/sops-v3.13.3.checksums.txt
FROM debian:bookworm-slim AS sops
ARG SOPS_VERSION=3.13.3
ARG SOPS_SHA256_AMD64=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b
ARG SOPS_SHA256_ARM64=53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    case "${TARGETARCH:-amd64}" in \
        amd64) sops_sum="${SOPS_SHA256_AMD64}" ;; \
        arm64) sops_sum="${SOPS_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /usr/local/bin/sops \
        "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.${TARGETARCH:-amd64}"; \
    echo "${sops_sum}  /usr/local/bin/sops" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/sops; \
    sops --version

FROM debian:bookworm-slim AS runtime
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 10001 lockset; \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin lockset

COPY --from=sops /usr/local/bin/sops /usr/local/bin/sops
COPY --from=build /src/target/release/lockset /usr/local/bin/lockset

# The repository is mounted here; nothing secret is part of the image.
WORKDIR /repo
USER 10001:10001
ENTRYPOINT ["lockset"]
CMD ["--help"]
