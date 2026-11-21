FROM mirror.gcr.io/library/rust:1.100-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8 AS verifier-build
WORKDIR /build
COPY core/distribution-tooling/Cargo.toml core/distribution-tooling/Cargo.lock ./
COPY core/distribution-tooling/src/ ./src/
RUN target="$(uname -m)-unknown-linux-musl" \
    && rustup target add "$target" \
    && cargo test --locked \
    && cargo build --release --locked --target "$target" \
    && install -D -m 0755 "target/$target/release/rentnerproxy-distribution-verify" /out/rentnerproxy-distribution-verify

FROM mirror.gcr.io/oven/bun:1.4.5@sha256:3aa040e5445efa09d75bb428a64ba50db13e2b3ac9b6b0c7f145615f62b2ee18

USER root
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        apt-utils ca-certificates cpio createrepo-c curl dpkg-dev git gnupg gpgv \
        iproute2 podman rpm rpm2cpio shellcheck skopeo systemd systemd-container \
    && rm -rf /var/lib/apt/lists/*
COPY --from=verifier-build /out/rentnerproxy-distribution-verify /usr/local/bin/
WORKDIR /work
ENTRYPOINT ["bun", "--no-env-file"]
