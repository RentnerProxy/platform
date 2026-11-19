FROM mirror.gcr.io/oven/bun:1.4.5@sha256:3aa040e5445efa09d75bb428a64ba50db13e2b3ac9b6b0c7f145615f62b2ee18

USER root
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        apt-utils ca-certificates cpio createrepo-c curl dpkg-dev git gnupg gpgv \
        iproute2 podman rpm rpm2cpio shellcheck skopeo systemd systemd-container \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENTRYPOINT ["bun", "--no-env-file"]
