# syntax=docker/dockerfile:1.7

FROM rockylinux:9

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN dnf install -y \
      bash \
      ca-certificates \
      curl-minimal \
      findutils \
      gcc \
      gcc-c++ \
      git \
      gzip \
      make \
      pkgconf-pkg-config \
      tar \
      which \
    && dnf clean all

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --profile minimal \
    && cargo install --locked cargo-generate-rpm \
    && rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
    && chmod -R a+rwX /usr/local/cargo /usr/local/rustup

WORKDIR /workspace
