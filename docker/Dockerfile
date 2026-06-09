# Test environment for hostveil — vulnerable self-hosting host
# Includes: Docker daemon, Lynis, Trivy, test Compose projects, weak configs
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

# ── Lynis (install from GitHub with full directory structure) ──
# Lynis resolves include/ relative to its own path. Use a cd-based wrapper.
RUN LYNIS_VERSION=3.1.6 \
    && curl -fsSL https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_VERSION}.tar.gz \
    | tar xz -C /usr/local \
    && printf '#!/bin/sh\ncd /usr/local/lynis-'${LYNIS_VERSION}' && exec ./lynis "$@"\n' > /usr/bin/lynis \
    && chmod +x /usr/bin/lynis /usr/local/lynis-${LYNIS_VERSION}/lynis

# ── Trivy (latest via official script) ──
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/bin \
    && trivy image --download-db-only 2>/dev/null || true

# ── Vulnerable SSH configuration (lynis.AUTH-9286, lynis.AUTH-9308) ──
RUN ssh-keygen -A
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# ── Weak file permissions (lynis.FILE-6310) ──
RUN chmod 777 /etc/shadow 2>/dev/null || true

# ── Kernel hardening gaps (lynis.KRNL-5780, KRNL-5830, KRNL-5840, KRNL-5880) ──
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.accept_source_route=1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.send_redirects=1" >> /etc/sysctl.conf && \
    echo "net.ipv4.icmp_echo_ignore_broadcasts=0" >> /etc/sysctl.conf

# ── Test Compose projects (trivy vulnerabilities) ──
COPY compose/ /opt/compose/

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
