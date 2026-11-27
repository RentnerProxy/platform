# syntax=mirror.gcr.io/docker/dockerfile:1.24.0

FROM mirror.gcr.io/oven/bun:1.4.5-alpine AS web-dependencies

WORKDIR /app
COPY package.json bun.lock ./
COPY patches/picomatch@4.0.7.patch ./patches/
RUN bun install --frozen-lockfile

FROM web-dependencies AS web-build

COPY . .
ARG RENTNERPROXY_BUILD_VERSION
RUN RENTNERPROXY_BUILD_VERSION="$RENTNERPROXY_BUILD_VERSION" bun run build:web \
    && bun build web/src/db/migrate.ts --target=bun --outfile=/build/migrate.js \
    && bun build docker/production/backups/agent.ts --target=bun --outfile=/build/backup-agent.js \
    && bun build docker/production/backups/export.ts --target=bun --outfile=/build/backup-export.js \
    && bun build docker/production/backups/maintenance.ts --target=bun --outfile=/build/backup-maintenance.js \
    && bun build docker/production/backups/build-identity.ts --target=bun --outfile=/build/backup-build-identity.js \
    && bun docker/web/package-migrations.ts ./web/drizzle /build/migrations

FROM mirror.gcr.io/oven/bun:1.4.5-alpine AS web-runtime

WORKDIR /app
COPY package.json bun.lock ./
COPY patches/picomatch@4.0.7.patch ./patches/
COPY docker/web/prune-build-tools.sh /tmp/prune-build-tools.sh
RUN bun install --frozen-lockfile --production \
    && /bin/sh /tmp/prune-build-tools.sh \
    && rm /tmp/prune-build-tools.sh
COPY --from=web-build /app/web/dist ./web/dist
COPY --from=web-build /build/migrations ./web/drizzle
COPY --from=web-build /build/migrate.js ./migrate.js
COPY --from=web-build /build/backup-agent.js ./backup-agent.js
COPY --from=web-build /build/backup-export.js ./backup-export.js
COPY --from=web-build /build/backup-maintenance.js ./backup-maintenance.js
COPY --from=web-build /app/docker/web/bootstrap-secrets.ts ./docker/web/bootstrap-secrets.ts
COPY --from=web-build /app/docker/web/validate-backup.ts ./docker/web/validate-backup.ts
COPY --from=web-build /app/web/src/config/compatibility.config.ts ./web/src/config/compatibility.config.ts
COPY --from=web-build /app/web/src/lib/ApplicationVersion/backupCompatibility.ts ./web/src/lib/ApplicationVersion/backupCompatibility.ts
COPY --from=web-build /app/web/src/lib/Environment/deployment-environment.ts ./web/src/lib/Environment/deployment-environment.ts
COPY --from=web-build /app/docker/web/request-context.ts ./docker/web/request-context.ts
COPY --from=web-build /app/docker/web/static-assets.ts ./docker/web/static-assets.ts
COPY --from=web-build /app/docker/web/serve.ts ./docker/web/serve.ts
COPY --from=web-build /app/docker/web/healthcheck.ts ./docker/web/healthcheck.ts

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
# Only the binary leaves this step. The dependency target lives solely in the manifest-keyed stage
# above, which CI caches in the registry instead of the size-limited Actions cache. Keep both
# stages identical in docker/proxy-runtime/Dockerfile so one builder compiles the controller once.
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
COPY core/caddy-modules/responsecache/ /opt/rentnerproxy-responsecache/
WORKDIR /tmp/rentnerproxy-caddy
RUN test "$(go env GOOS)/$(go env GOARCH)" = "$TARGETOS/$TARGETARCH" \
    && /bin/sh /tmp/build-caddy.sh

FROM mirror.gcr.io/oven/bun:1.4.5-alpine AS geoip-assets
COPY scripts/assets/download-geoip.ts /tmp/download-geoip.ts
RUN bun --no-env-file /tmp/download-geoip.ts

# Build pristine upstream CrowdSec with the managed SQLite backend and pinned
# security dependencies; exclude its unused legacy PostgreSQL backend.
FROM mirror.gcr.io/library/golang:1.27.4-alpine AS crowdsec-build
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache build-base ca-certificates coreutils curl linux-headers pkgconf
COPY docker/crowdsec/tooling/engine-build/ /opt/crowdsec-build/
COPY docker/tooling/buildinfo/verify.go /opt/verify-buildinfo.go
RUN test "$(go env GOOS)/$(go env GOARCH)" = "$TARGETOS/$TARGETARCH" \
    && /bin/sh /opt/crowdsec-build/build.sh /out

FROM mirror.gcr.io/library/golang:1.27.4-alpine AS gosu-build
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache coreutils curl
COPY docker/gosu/tooling/ /opt/gosu-build/
RUN test "$(go env GOOS)/$(go env GOARCH)" = "$TARGETOS/$TARGETARCH" \
    && /bin/sh /opt/gosu-build/build.sh /out

FROM ghcr.io/crowdsecurity/crowdsec:v1.8.2 AS crowdsec-assets

COPY docker/crowdsec/hub/data.sha256 /tmp/rentnerproxy-crowdsec-hub-data.sha256
# The pinned Hub scenario fetches a moving upstream list. Use the revision selected by the manifest.
ADD --checksum=sha256:be1fad9b6d99346c07fd5f7f6110d497397383c14fdfa6fe59236fa6e52c3a13 \
    https://raw.githubusercontent.com/crowdsecurity/sec-lists/f9df076079c31e50bf3fcd8abd0b25d4a1e1c904/web/sensitive_data.txt \
    /tmp/rentnerproxy-crowdsec-sensitive-data.txt
RUN set -eux; \
    mkdir -p /etc/crowdsec /var/lib/crowdsec /opt/rentnerproxy/crowdsec-config; \
    cp -a /staging/etc/crowdsec/. /etc/crowdsec/; \
    cp -a /staging/var/lib/crowdsec/. /var/lib/crowdsec/; \
    sed -i '/^cscli:/a\  hub_branch: 22393a8bd820a3f6033b114adbefacca9cd120a2' /etc/crowdsec/config.yaml; \
    sed -i '/^cscli:/a\  __hub_url_template__: https://raw.githubusercontent.com/crowdsecurity/hub/%s/%s' /etc/crowdsec/config.yaml; \
    cscli -c /etc/crowdsec/config.yaml hub update --error; \
    cscli -c /etc/crowdsec/config.yaml collections remove crowdsecurity/linux --force >/dev/null; \
    rm -rf /var/lib/crowdsec/data/*; \
    cscli -c /etc/crowdsec/config.yaml parsers install \
        crowdsecurity/syslog-logs crowdsecurity/whitelists --force --error >/dev/null; \
    cscli -c /etc/crowdsec/config.yaml collections install crowdsecurity/caddy --force --error >/dev/null; \
    cd /var/lib/crowdsec/data; \
    install -m 0644 /tmp/rentnerproxy-crowdsec-sensitive-data.txt sensitive_data.txt; \
    sha256sum -c /tmp/rentnerproxy-crowdsec-hub-data.sha256; \
    rm -f /etc/crowdsec/local_api_credentials.yaml \
        /etc/crowdsec/online_api_credentials.yaml; \
    cp -aL /etc/crowdsec/. /opt/rentnerproxy/crowdsec-config/

FROM mirror.gcr.io/valkey/valkey:9.2.1-alpine AS valkey-runtime

# Already published app executables use the v1 GNU/Linux ABI. Keep its narrowly
# scoped libraries and loader paths while the appliance services move to musl.
FROM mirror.gcr.io/library/debian:13.8-slim AS published-app-glibc
ARG TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libc6 libgcc-s1 libstdc++6; \
    case "$TARGETARCH" in \
        amd64) triplet=x86_64-linux-gnu; loader=ld-linux-x86-64.so.2; loader_directory=/lib64 ;; \
        arm64) triplet=aarch64-linux-gnu; loader=ld-linux-aarch64.so.1; loader_directory=/lib ;; \
        *) exit 1 ;; \
    esac; \
    mkdir -p "/out/usr/lib/$triplet" "/out$loader_directory" /out/lib; \
    for library in "$loader" libc.so.6 libdl.so.2 libm.so.6 libpthread.so.0 libresolv.so.2 librt.so.1 libgcc_s.so.1 libstdc++.so.6; do \
        install -m 0755 "/usr/lib/$triplet/$library" "/out/usr/lib/$triplet/$library"; \
    done; \
    ln -s "/usr/lib/$triplet/$loader" "/out$loader_directory/$loader"; \
    ln -s "/usr/lib/$triplet" "/out/lib/$triplet"; \
    for package in libc6 libgcc-s1 libstdc++6; do \
        install -D -m 0644 "/usr/share/doc/$package/copyright" "/out/usr/share/licenses/rentnerproxy/app-abi/$package"; \
    done

FROM mirror.gcr.io/library/postgres:18.7-alpine3.24 AS postgres-runtime
# RentnerProxy owns the entrypoint and bundles its own gosu build.
RUN rm -f /usr/local/bin/gosu /usr/local/bin/docker-entrypoint.sh \
    /usr/local/bin/docker-ensure-initdb.sh /usr/local/bin/docker-enforce-initdb.sh

FROM scratch AS runtime
COPY --from=postgres-runtime / /

ARG TARGETOS
ARG TARGETARCH
LABEL org.opencontainers.image.source="https://github.com/RentnerProxy/platform" \
    org.opencontainers.image.description="Modern self-hosted reverse proxy manager powered by Caddy."

ENV APP_DIR=/opt/rentnerproxy/web \
    NODE_ENV=production \
    LANG=C.UTF-8 \
    PGDATA=/var/lib/rentnerproxy/postgres-data \
    RENTNERPROXY_CADDY_BIN=/usr/bin/caddy \
    RENTNERPROXY_PROXY_HTTP_PORT=8080 \
    RENTNERPROXY_PROXY_HTTPS_PORT=8443 \
    RENTNERPROXY_PROXY_STATE_DIR=/var/lib/rentnerproxy/proxy \
    RENTNERPROXY_SYSTEM_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN apk upgrade --no-cache \
    && apk add --no-cache bash binutils ca-certificates coreutils curl findutils flock grep openssl procps-ng setpriv tar tini \
    && apk add --no-cache --virtual .image-setup libcap-utils shadow \
    && test "$(getent group 999 | cut -d: -f1)" = ping \
    && groupdel ping \
    && groupmod --gid 999 postgres \
    && usermod --uid 999 --gid postgres postgres \
    && test "$(id -u postgres):$(id -g postgres)" = 999:999 \
    && install -d -m 0755 /usr/lib/postgresql/18/bin \
    && for binary in postgres initdb pg_ctl pg_isready pg_dump pg_restore psql; do \
        ln -s "/usr/local/bin/$binary" "/usr/lib/postgresql/18/bin/$binary"; \
    done \
    && groupadd --gid 10001 rentnerproxy \
    && useradd --uid 10001 --gid rentnerproxy --no-create-home --shell /sbin/nologin rentnerproxy \
    && groupadd --gid 10002 rentnerproxy-web \
    && useradd --uid 10002 --gid rentnerproxy-web --no-create-home --shell /sbin/nologin rentnerproxy-web \
    && groupadd --gid 10003 crowdsec \
    && useradd --uid 10003 --gid crowdsec --no-create-home --shell /sbin/nologin crowdsec \
    && install -d -m 0711 -o root -g root /var/lib/rentnerproxy \
    && install -d -m 0700 -o postgres -g postgres /var/lib/rentnerproxy/postgres-data \
    && install -d -m 0710 -o rentnerproxy -g crowdsec /var/lib/rentnerproxy/proxy \
    && install -d -m 2750 -o rentnerproxy -g crowdsec /var/lib/rentnerproxy/proxy/logs \
    && install -d -m 0711 -o root -g root /var/lib/rentnerproxy/crowdsec \
    && install -d -m 0700 -o crowdsec -g crowdsec /var/lib/rentnerproxy/crowdsec/credentials \
    && install -d -m 0700 -o crowdsec -g crowdsec /var/lib/rentnerproxy/crowdsec/data \
    && install -d -m 0710 -o root -g rentnerproxy /var/lib/rentnerproxy/crowdsec/bouncer \
    && install -d -m 0700 -o root -g root /var/lib/rentnerproxy/bootstrap \
    && install -d -m 0700 -o postgres -g postgres /var/run/postgresql \
    && chmod 00700 /var/run/postgresql \
    && install -d -m 0755 /opt/rentnerproxy/valkey/bin

COPY --from=published-app-glibc /out/ /
COPY --from=web-runtime /usr/local/bin/bun /usr/local/bin/bun
COPY --from=web-runtime /app /opt/rentnerproxy/web
COPY --from=controller-build /out/rentnerproxy-controller /usr/local/bin/rentnerproxy-controller
# Retain the exact locked controller graph for recurring RustSec assessments.
COPY core/Cargo.lock /usr/share/rentnerproxy/security/Cargo.lock
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
COPY --from=crowdsec-build /out/bin/crowdsec /usr/local/bin/crowdsec
COPY --from=crowdsec-build /out/bin/cscli /usr/local/bin/cscli
COPY --from=gosu-build /out/gosu /usr/local/bin/gosu
COPY --from=gosu-build /out/LICENSE /usr/share/licenses/gosu/LICENSE
COPY --from=crowdsec-assets /opt/rentnerproxy/crowdsec-config /usr/share/rentnerproxy/crowdsec/config
COPY --from=crowdsec-assets /var/lib/crowdsec/data /usr/share/rentnerproxy/crowdsec/data
COPY --from=geoip-assets /tmp/user-country.mmdb /usr/share/rentnerproxy/geoip/user-country.mmdb
COPY docker/crowdsec/runtime/config.yaml /usr/share/rentnerproxy/crowdsec/config.yaml
COPY docker/crowdsec/runtime/config-online.yaml /usr/share/rentnerproxy/crowdsec/config-online.yaml
COPY docker/crowdsec/runtime/acquis.yaml /usr/share/rentnerproxy/crowdsec/acquis.yaml
COPY docker/licenses/Caddy-LICENSE /usr/share/licenses/caddy/LICENSE
COPY docker/licenses/Caddy-LICENSE /usr/share/licenses/caddy-crowdsec-bouncer/LICENSE
COPY docker/licenses/CaddyCrowdSecBouncer-NOTICE /usr/share/licenses/caddy-crowdsec-bouncer/NOTICE
COPY docker/licenses/CrowdSec-LICENSE /usr/share/licenses/crowdsec/LICENSE
COPY docker/licenses/CrowdSec-NOTICE /usr/share/licenses/crowdsec/NOTICE
COPY docker/licenses/GeoIP-NOTICE /usr/share/licenses/rentnerproxy-geoip/NOTICE
COPY docker/licenses/Valkey-LICENSE /usr/share/licenses/valkey/LICENSE
COPY docker/licenses/Valkey-NOTICE /usr/share/licenses/valkey/NOTICE
COPY --from=valkey-runtime /usr/local/bin/valkey-server /usr/local/bin/valkey-cli /opt/rentnerproxy/valkey/bin/
COPY docker/production/entrypoint.sh /usr/local/bin/rentnerproxy-production
COPY docker/production/apps/provision.sh /usr/local/bin/rentnerproxy-provision-app
COPY docker/production/apps/pg_hba.conf docker/production/apps/pg_ident.conf /usr/local/etc/rentnerproxy/
COPY docker/production/apps/catalog/ /usr/share/rentnerproxy/app-catalog/
COPY docker/production/verify-platform.sh /tmp/verify-platform.sh
COPY docker/production/backups/supervisor.sh /usr/local/lib/rentnerproxy-backups.sh
COPY docker/production/fault-supervisor.sh /usr/local/lib/rentnerproxy-fault-supervisor.sh
COPY --from=web-build /build/backup-build-identity.js /tmp/backup-build-identity.js
COPY docker/crowdsec/runtime/supervisor.sh /usr/local/bin/rentnerproxy-crowdsec-supervisor

ARG RENTNERPROXY_BUILD_VERSION=development
ARG RENTNERPROXY_BUILD_REVISION
RUN install -d -m 0755 /usr/share/rentnerproxy \
    && RENTNERPROXY_BUILD_VERSION="$RENTNERPROXY_BUILD_VERSION" RENTNERPROXY_BUILD_REVISION="$RENTNERPROXY_BUILD_REVISION" bun --no-env-file /tmp/backup-build-identity.js \
    && rm /tmp/backup-build-identity.js \
    && chmod 0444 /usr/local/lib/rentnerproxy-backups.sh /usr/local/lib/rentnerproxy-fault-supervisor.sh

RUN chmod 0555 /usr/local/bin/rentnerproxy-production \
    && chmod 0555 /usr/local/bin/rentnerproxy-provision-app \
    && chmod 0555 /usr/local/bin/rentnerproxy-crowdsec-supervisor \
    && chmod 0555 /usr/local/bin/rentnerproxy-controller \
    && chmod 0555 /usr/local/bin/crowdsec /usr/local/bin/cscli \
    && chmod 0555 /usr/local/bin/bun \
    && chmod 0555 /opt/rentnerproxy/valkey/bin/valkey-server /opt/rentnerproxy/valkey/bin/valkey-cli \
    && /opt/rentnerproxy/valkey/bin/valkey-server --version | grep -F 'v=9.2.0 ' \
    && /opt/rentnerproxy/valkey/bin/valkey-cli --version | grep -Fx 'valkey-cli 9.2.0' \
    && postgres --version | grep -E '^postgres \(PostgreSQL\) 18\.' \
    && install -d -m 0555 -o root -g root /usr/share/rentnerproxy/crowdsec/plugins \
    && find /usr/share/rentnerproxy/crowdsec -type d -exec chmod 0555 {} + \
    && find /usr/share/rentnerproxy/crowdsec -type f -exec chmod 0444 {} + \
    && ! find /usr/share/rentnerproxy/crowdsec -type l -print -quit | grep -q . \
    && gosu crowdsec cscli -c /usr/share/rentnerproxy/crowdsec/config.yaml collections list -o json | grep -F 'crowdsecurity/caddy' \
    && /usr/bin/caddy list-modules | grep -Fx crowdsec \
    && /usr/bin/caddy list-modules | grep -Fx http.handlers.crowdsec \
    && /usr/bin/caddy list-modules | grep -Fx http.handlers.rentnerproxy_response_cache \
    && /usr/bin/caddy list-modules | grep -Fx http.handlers.rentnerproxy_upstream \
    && /usr/bin/caddy list-modules | grep -Fx admin.api.rentnerproxy \
    && /usr/local/bin/crowdsec -version | grep -F 'version: v1.8.2-3d369d64eb3e9ba770ed39aedc83ffd3170aef4c' \
    && { [ -z "$(getcap /usr/bin/caddy)" ] || setcap -r /usr/bin/caddy; } \
    && test -z "$(getcap /usr/bin/caddy)" \
    && /bin/sh /tmp/verify-platform.sh "$TARGETOS" "$TARGETARCH" \
        /usr/local/bin/bun /usr/local/bin/rentnerproxy-controller /usr/bin/caddy \
        /usr/local/bin/crowdsec /usr/local/bin/cscli /usr/local/bin/gosu \
        /opt/rentnerproxy/valkey/bin/valkey-server /opt/rentnerproxy/valkey/bin/valkey-cli \
        /usr/lib/postgresql/18/bin/postgres /usr/lib/postgresql/18/bin/initdb \
        /usr/lib/postgresql/18/bin/pg_ctl /usr/lib/postgresql/18/bin/pg_isready \
        /usr/lib/postgresql/18/bin/pg_dump /usr/lib/postgresql/18/bin/pg_restore \
        /usr/lib/postgresql/18/bin/psql "$(command -v tini)" /usr/bin/curl /usr/bin/openssl \
    && rm /tmp/verify-platform.sh \
    && apk del .image-setup \
    && cd /opt/rentnerproxy/web \
    && gosu rentnerproxy-web bun --no-env-file -e "const result = Bun.spawnSync([process.execPath, '--no-env-file', 'fmt', '--no-script', '--no-config', '--no-editorconfig', '--stdin-filepath=default-site.html', '--tab-width=4', '--print-width=100', '--html-whitespace-sensitivity=strict', '--threads=1'], { stdin: Buffer.from('<style>h1{color:red}</style>'), stdout: 'pipe', stderr: 'pipe', timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 262144 }); if (result.exitCode !== 0 || !result.stdout.toString().includes('color: red;')) throw new Error('Runtime HTML formatter failed')"

EXPOSE 3000 8080 8443/tcp 8443/udp
VOLUME ["/var/lib/rentnerproxy"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=12 CMD ["bun", "/opt/rentnerproxy/web/docker/web/healthcheck.ts"]
ENTRYPOINT ["tini", "--", "/usr/local/bin/rentnerproxy-production"]
