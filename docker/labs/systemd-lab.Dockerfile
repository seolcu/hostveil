# syntax=docker/dockerfile:1.7

ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ARG DISTRO_FAMILY=apt
ARG LAB_LABEL=Linux lab

ENV container=docker \
    CARGO_HOME=/cargo \
    RUSTUP_HOME=/rustup \
    PATH=/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN case "${DISTRO_FAMILY}" in \
      apt) \
        apt-get update \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          bash \
          build-essential \
          ca-certificates \
          curl \
          git \
          gnupg \
          iproute2 \
          less \
          pkg-config \
          procps \
          sudo \
          systemd \
          systemd-sysv \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/* \
        ;; \
      dnf) \
        dnf install -y \
          bash \
          ca-certificates \
          curl-minimal \
          findutils \
          gcc \
          gcc-c++ \
          git \
          gnupg2 \
          hostname \
          iproute \
          less \
          make \
          pkgconf-pkg-config \
          procps-ng \
          sudo \
          systemd \
          which \
        && dnf clean all \
        ;; \
      *) \
        printf 'unsupported lab distro family: %s\n' "${DISTRO_FAMILY}" >&2 \
        && exit 1 \
        ;; \
    esac

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --profile minimal --component clippy,rustfmt

RUN mkdir -p /cargo /rustup /workspace /etc/hostveil-lab \
    && printf '%s\n' "${LAB_LABEL}" > /etc/hostveil-lab/name \
    && printf '%s\n' "${DISTRO_FAMILY}" > /etc/hostveil-lab/family

RUN systemctl mask \
      dev-hugepages.mount \
      sys-fs-fuse-connections.mount \
      systemd-remount-fs.service \
      getty.target \
      console-getty.service \
      systemd-logind.service \
      systemd-vconsole-setup.service || true

VOLUME ["/sys/fs/cgroup", "/run", "/tmp"]
STOPSIGNAL SIGRTMIN+3
