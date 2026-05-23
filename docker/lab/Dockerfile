FROM golang:1.24-trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    sudo \
    procps \
    less \
    vim-tiny \
    lynis \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64) TRIVY_ARCH="64bit"; DOCKLE_ARCH="64bit"; GITLEAKS_ARCH="x64";   DOCKER_ARCH="x86_64";; \
      arm64) TRIVY_ARCH="ARM64"; DOCKLE_ARCH="ARM64"; GITLEAKS_ARCH="arm64"; DOCKER_ARCH="aarch64";; \
      *)     echo "unsupported arch: $ARCH"; exit 1;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-${TRIVY_ARCH}.deb" \
      -o /tmp/trivy.deb && dpkg -i /tmp/trivy.deb && rm /tmp/trivy.deb; \
    curl -fsSL "https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_Linux-${DOCKLE_ARCH}.tar.gz" \
      -o /tmp/dockle.tar.gz && tar -xzf /tmp/dockle.tar.gz -C /usr/local/bin dockle && rm /tmp/dockle.tar.gz; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/gitleaks_8.24.0_linux_${GITLEAKS_ARCH}.tar.gz" \
      -o /tmp/gitleaks.tar.gz && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tar.gz; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-28.0.4.tgz" \
      -o /tmp/docker.tgz && tar -xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1 docker/docker && rm /tmp/docker.tgz

WORKDIR /workspace
CMD ["sleep", "infinity"]
