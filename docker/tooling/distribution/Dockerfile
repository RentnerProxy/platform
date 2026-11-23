FROM mirror.gcr.io/library/rust:1.100.0-alpine3.24 AS verifier-build
WORKDIR /build
COPY core/distribution-tooling/Cargo.toml core/distribution-tooling/Cargo.lock ./
COPY core/distribution-tooling/src/ ./src/
RUN cargo test --locked \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/rentnerproxy-distribution-verify /out/rentnerproxy-distribution-verify

FROM mirror.gcr.io/oven/bun:1.4.5

USER root
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        apt-utils ca-certificates cpio createrepo-c curl dpkg-dev git gnupg gpgv \
        iproute2 podman rpm rpm2cpio shellcheck skopeo systemd systemd-container \
    && rm -rf /var/lib/apt/lists/*
COPY --from=verifier-build /out/rentnerproxy-distribution-verify /usr/local/bin/
WORKDIR /work
ENTRYPOINT ["bun", "--no-env-file"]
