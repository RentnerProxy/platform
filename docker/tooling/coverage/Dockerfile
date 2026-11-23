# syntax=mirror.gcr.io/docker/dockerfile:1.24.0

FROM mirror.gcr.io/oven/bun:1.4.5 AS bun

FROM mirror.gcr.io/library/rust:1.100.0-trixie AS controller
WORKDIR /build
COPY core/Cargo.toml core/Cargo.lock ./
COPY core/src ./src
# Only the binary leaves this step so CI can cache the image without exporting target/.
RUN --mount=type=cache,id=rentnerproxy-cargo-registry,target=/usr/local/cargo/registry \
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked \
    && install -D -m 0755 target/debug/rentnerproxy-controller /out/rentnerproxy-controller \
    && rm -rf target

FROM mirror.gcr.io/library/postgres:18.7-trixie AS tooling
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun

RUN apt-get update \
    && apt-get install -y --no-install-recommends git jq ca-certificates apt-utils createrepo-c gnupg gpgv podman rpm rpm2cpio skopeo \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10002 rentnerproxy \
    && useradd --uid 10002 --gid rentnerproxy --no-create-home rentnerproxy \
    && groupadd --gid 10003 crowdsec \
    && useradd --uid 10003 --gid crowdsec --no-create-home crowdsec \
    && git config --system --add safe.directory /workspace

WORKDIR /workspace
ENV RENTNERPROXY_PACKAGE_TEST=1
ENTRYPOINT ["bun", "--no-env-file"]

FROM tooling AS coverage
COPY --from=controller /out/rentnerproxy-controller /usr/local/libexec/rentnerproxy-test-controller
