FROM mirror.gcr.io/oven/bun:1.4.5@sha256:3aa040e5445efa09d75bb428a64ba50db13e2b3ac9b6b0c7f145615f62b2ee18 AS bun

FROM mirror.gcr.io/library/rust:1.100-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8 AS controller
WORKDIR /build
COPY core/Cargo.toml core/Cargo.lock ./
COPY core/src ./src
RUN CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked

FROM mirror.gcr.io/library/postgres:18.7@sha256:9f4fd4aa918f52ae3d6f3b687f1de90d8f867cd4d520021545a9a50c120eae3b AS tooling
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
COPY --from=controller /build/target/debug/rentnerproxy-controller /usr/local/libexec/rentnerproxy-test-controller
