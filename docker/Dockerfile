# Test environment for hostveil — a deliberately vulnerable self-hosting host
# Includes: Docker daemon, (optional) Trivy, test Compose projects, weak SSH
FROM docker:28-dind

# ── Alpine packages ──
RUN apk add --no-cache \
    openssh \
    bash \
    curl \
    shadow \
    procps

# ── Go (required to build hostveil) ──
RUN curl -fsSL https://go.dev/dl/go1.26.3.linux-amd64.tar.gz \
    | tar xz -C /usr/local \
    && ln -s /usr/local/go/bin/go /usr/bin/go \
    && ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

# ── Trivy (optional; enables hostveil's image CVE scanning) ──
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/bin \
    && trivy image --download-db-only 2>/dev/null || true

# ── Vulnerable SSH configuration (hostveil: ssh.rootlogin, ssh.passwordauth) ──
RUN ssh-keygen -A
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# ── Test Compose projects (compose audit + image CVEs) ──
COPY compose/ /opt/compose/

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
