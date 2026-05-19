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

RUN curl -fsSL https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 \
    -o /usr/local/bin/ttyd && chmod +x /usr/local/bin/ttyd

RUN curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-64bit.deb \
    -o /tmp/trivy.deb && dpkg -i /tmp/trivy.deb && rm /tmp/trivy.deb

RUN curl -fsSL https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_Linux-64bit.tar.gz \
    -o /tmp/dockle.tar.gz && tar -xzf /tmp/dockle.tar.gz -C /usr/local/bin dockle && rm /tmp/dockle.tar.gz

RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/gitleaks_8.24.0_linux_x64.tar.gz \
    -o /tmp/gitleaks.tar.gz && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tar.gz

RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-28.0.4.tgz \
    -o /tmp/docker.tgz && tar -xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1 docker/docker && rm /tmp/docker.tgz

WORKDIR /workspace
CMD ["sleep", "infinity"]
