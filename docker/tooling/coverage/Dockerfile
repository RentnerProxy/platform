# syntax=mirror.gcr.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

FROM mirror.gcr.io/oven/bun:1.4.5@sha256:3aa040e5445efa09d75bb428a64ba50db13e2b3ac9b6b0c7f145615f62b2ee18 AS bun

FROM mirror.gcr.io/library/rust:1.100-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31 AS controller
WORKDIR /build
COPY core/Cargo.toml core/Cargo.lock ./
COPY core/src ./src
# Only the binary leaves this step so CI can cache the image without exporting target/.
RUN --mount=type=cache,id=rentnerproxy-cargo-registry,target=/usr/local/cargo/registry \
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked \
    && install -D -m 0755 target/debug/rentnerproxy-controller /out/rentnerproxy-controller \
    && rm -rf target

FROM mirror.gcr.io/library/postgres:19.0@sha256:bb6e70add742cd868fb62cb3b2f67d1dd2bdd2b65a521e778420748753687c60 AS tooling
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
