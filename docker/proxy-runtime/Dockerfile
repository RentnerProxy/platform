# syntax=mirror.gcr.io/docker/dockerfile:1.24.0

# The controller-dependencies, controller-build and caddy-build stages (and this frontend)
# intentionally match docker/production/Dockerfile instruction for instruction: CI builds both
# images on one BuildKit builder, which then compiles the controller and Caddy only once.
FROM mirror.gcr.io/library/rust:1.100.0-alpine3.24 AS controller-dependencies

WORKDIR /build
RUN apk add --no-cache build-base cmake perl
COPY core/Cargo.toml core/Cargo.lock ./
# Compile the locked dependency graph against placeholder targets. This layer depends only on the
# manifests, so source-only changes reuse it from the build cache and rebuild just the controller.
RUN --mount=type=cache,id=rentnerproxy-cargo-registry,target=/usr/local/cargo/registry \
    set -eu; \
    mkdir src; \
    printf 'fn main() {}\n' > src/main.rs; \
    : > src/lib.rs; \
    cargo build --locked --release; \
    cargo clean --release --package rentnerproxy-controller; \
    rm -rf src

FROM controller-dependencies AS controller-build

ARG TARGETOS
ARG TARGETARCH
COPY core/src ./src
ARG RENTNERPROXY_BUILD_VERSION
RUN --mount=type=cache,id=rentnerproxy-cargo-registry,target=/usr/local/cargo/registry \
    set -eu; \
    case "$TARGETOS/$TARGETARCH" in \
        linux/amd64) rust_host=x86_64-unknown-linux-musl ;; \
        linux/arm64) rust_host=aarch64-unknown-linux-musl ;; \
        *) echo 'Unsupported controller platform' >&2; exit 1 ;; \
    esac; \
    test "$(rustc -vV | sed -n 's/^host: //p')" = "$rust_host"; \
    RENTNERPROXY_BUILD_VERSION="${RENTNERPROXY_BUILD_VERSION:-}" cargo build --locked --release; \
    linkage=$(readelf --wide --program-headers --dynamic target/release/rentnerproxy-controller); \
    if printf '%s\n' "$linkage" | grep -Eq '^[[:space:]]*INTERP[[:space:]]|\(NEEDED\)'; then \
        echo 'Expected a static musl controller' >&2; exit 1; \
    fi; \
    install -D -m 0755 target/release/rentnerproxy-controller /out/rentnerproxy-controller; \
    rm -rf target

FROM mirror.gcr.io/library/golang:1.27.4-alpine AS caddy-go-toolchain

# The builder supplies CADDY_VERSION so image updates also update the compiled binary.
# Apply the reviewed reload-lifecycle backport to a verified upstream copy.
# Their optional AppSec and Layer 4 modules remain unconfigured.
FROM mirror.gcr.io/library/caddy:2.11.9-builder-alpine AS caddy-build

ARG TARGETOS
ARG TARGETARCH
RUN rm -rf /usr/local/go
COPY --from=caddy-go-toolchain /usr/local/go/ /usr/local/go/
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
ARG CADDY_CROWDSEC_BOUNCER_VERSION=v0.14.2-0.20261030164527-4a6ce1d3094d
ARG CADDY_LAYER4_VERSION=v0.1.3-0.20261029145729-f607ccea1b7d
COPY docker/tooling/buildinfo/verify.go /tmp/verify-buildinfo.go
COPY docker/caddy/tooling/build.sh /tmp/build-caddy.sh
COPY docker/caddy/tooling/prepare-source.sh /tmp/prepare-caddy-source.sh
COPY docker/caddy/patches/ /opt/rentnerproxy-caddy-patches/
COPY core/caddy-modules/ /opt/rentnerproxy-caddy-modules/
WORKDIR /tmp/rentnerproxy-caddy
RUN test "$(go env GOOS)/$(go env GOARCH)" = "$TARGETOS/$TARGETARCH" \
    && /bin/sh /tmp/build-caddy.sh

FROM caddy-build AS caddy-reload-tests
RUN apk add --no-cache build-base
ENV CGO_ENABLED=1
WORKDIR /opt/rentnerproxy-caddy-modules
RUN go test -mod=readonly -race -short -timeout=120s -p=1 \
    github.com/caddyserver/caddy/v2 \
    github.com/caddyserver/caddy/v2/modules/caddyhttp \
    github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy \
    github.com/caddyserver/caddy/v2/modules/caddytls

FROM mirror.gcr.io/library/alpine:3.24.4

COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
COPY docker/licenses/Caddy-LICENSE /usr/share/licenses/caddy/LICENSE
COPY docker/licenses/Caddy-LICENSE /usr/share/licenses/caddy-crowdsec-bouncer/LICENSE
COPY docker/licenses/CaddyCrowdSecBouncer-NOTICE /usr/share/licenses/caddy-crowdsec-bouncer/NOTICE

COPY --from=controller-build /out/rentnerproxy-controller /usr/local/bin/rentnerproxy-controller
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates curl openssl procps-ng \
    && apk add --no-cache --virtual .image-setup libcap-utils \
    && update-ca-certificates \
    && /usr/bin/caddy list-modules | grep -Fx crowdsec \
    && /usr/bin/caddy list-modules | grep -Fx http.handlers.crowdsec \
    && /usr/bin/caddy list-modules | grep -Fx http.handlers.rentnerproxy_response_cache \
    && /usr/bin/caddy list-modules | grep -Fx http.handlers.rentnerproxy_upstream \
    && /usr/bin/caddy list-modules | grep -Fx admin.api.rentnerproxy \
    && { [ -z "$(getcap /usr/bin/caddy)" ] || setcap -r /usr/bin/caddy; } \
    && apk del .image-setup \
    && mkdir -p /var/lib/rentnerproxy/proxy \
    && chown 10001:10001 /var/lib/rentnerproxy/proxy
USER 10001:10001

ENV RENTNERPROXY_CONTROLLER_LISTEN_ADDR=0.0.0.0:8081 \
    RENTNERPROXY_CADDY_BIN=/usr/bin/caddy \
    RENTNERPROXY_PROXY_STATE_DIR=/var/lib/rentnerproxy/proxy \
    RENTNERPROXY_PROXY_HTTP_PORT=8080 \
    RENTNERPROXY_PROXY_HTTPS_PORT=8443 \
    RENTNERPROXY_SYSTEM_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

EXPOSE 8080 8081 8443/tcp 8443/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/rentnerproxy-controller"]
