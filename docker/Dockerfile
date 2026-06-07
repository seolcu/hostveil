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
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "ChallengeResponseAuthentication yes" >> /etc/ssh/sshd_config

# ── Weak file permissions (lynis.FILE-6310, lynis.FILE-6312, lynis.FILE-6405) ──
RUN chmod 777 /etc/shadow 2>/dev/null || true
RUN touch /tmp/world-writable && chmod 777 /tmp/world-writable

# ── Missing legal banners (lynis.BANN-7126, lynis.BANN-7130) ──
RUN echo "Welcome to Test Server" > /etc/issue && \
    echo "Welcome to Test Server" > /etc/motd

# ── Password aging issue (lynis.ACCT-9626) ──
RUN adduser -D testuser && echo "testuser:testpass" | chpasswd

# ── Password policy issues (lynis.AUTH-9222, lynis.AUTH-9223) ──
RUN echo "PASS_MIN_DAYS 0" >> /etc/login.defs && \
    echo "PASS_MAX_DAYS 99999" >> /etc/login.defs

# ── Disable firewall (lynis.FIRE-4512) — just ensure no custom rules, keep iptables installed
# iptables is required by Docker-in-Docker, so we cannot remove it

# ── Remove time sync (lynis.TIME-3106) ──
RUN apk del chrony 2>/dev/null; rm -f /etc/chrony.conf 2>/dev/null; true

# ── Remove logging (lynis.LOGG-2130) ──
RUN rm -f /etc/rsyslog.conf 2>/dev/null; true

# ── System logging daemon not running (lynis.LOGG-2100) ──
RUN apk del rsyslog 2>/dev/null; true

# ── Enable IP forwarding (lynis.KRNL-5780) ──
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# ── Accept ICMP redirects (lynis.KRNL-5820) ──
RUN echo "net.ipv4.conf.all.accept_redirects=1" >> /etc/sysctl.conf

# ── Additional kernel hardening gaps (lynis.KRNL-5830 through KRNL-5930) ──
RUN echo "net.ipv4.conf.all.accept_source_route=1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.send_redirects=1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf && \
    echo "net.ipv4.icmp_echo_ignore_broadcasts=0" >> /etc/sysctl.conf && \
    echo "net.ipv4.icmp_ignore_bogus_error_responses=0" >> /etc/sysctl.conf && \
    echo "net.ipv4.tcp_timestamps=1" >> /etc/sysctl.conf && \
    echo "net.ipv4.tcp_syncookies=0" >> /etc/sysctl.conf

# ── Test Compose projects (trivy vulnerabilities) ──
COPY compose/ /opt/compose/

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
