# Containerized test host for the hostveil integration tests.
# The image is intentionally pre-seeded with one finding per
# in-scope rule, so the integration test can assert a stable
# "1 finding per rule" report shape.
#
# Build:  docker build -t hostveil-test-host -f test/hostimage/Dockerfile .
# Run:    docker run --rm -it hostveil-test-host
# Test:   ./dist/hostveil scan  (against the running container)

FROM debian:stable-slim

# Install the tools hostveil's hardening sub-checks look for.
# apt / unattended-upgrades / fail2ban / nginx / sshd. We
# deliberately leave the firewall tooling off so the test can
# assert the "no firewall tooling" skip path.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server \
      nginx \
      fail2ban \
      unattended-upgrades \
      ca-certificates \
      dumb-init \
    && rm -rf /var/lib/apt/lists/*

# Pre-seed an insecure sshd_config so the SSH scanner finds
# PermitRootLogin yes.
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?Protocol.*/Protocol 2,1/' /etc/ssh/sshd_config

# Pre-seed an insecure nginx config with server_tokens on and
# a missing security header.
RUN sed -i 's/# server_tokens off;/server_tokens on;/' /etc/nginx/nginx.conf || true

# Pre-seed a Docker-style finding by writing a docker-compose.yml
# with the :latest tag.
RUN mkdir -p /opt/hostveil-test && \
    printf 'services:\n  web:\n    image: nginx:latest\n    ports: ["80:80"]\n' \
      > /opt/hostveil-test/docker-compose.yml

# Disable unattended-upgrades so the hardening sub-check finds
# the "unattended-upgrades disabled" finding.
RUN systemctl disable unattended-upgrades 2>/dev/null || true \
    && rm -f /etc/apt/apt.conf.d/20auto-upgrades

# Skip known sysctl baseline values so the test triggers findings.
RUN printf 'net.ipv4.conf.all.rp_filter = 0\n'             >  /etc/sysctl.d/99-hostveil-test.conf \
    && printf 'net.ipv4.conf.default.rp_filter = 2\n'      >> /etc/sysctl.d/99-hostveil-test.conf \
    && printf 'net.ipv4.conf.all.log_martians = 0\n'        >> /etc/sysctl.d/99-hostveil-test.conf \
    && printf 'net.ipv4.conf.default.log_martians = 0\n'    >> /etc/sysctl.d/99-hostveil-test.conf

# Copy the seed script in.
COPY seed.sh /seed.sh
RUN chmod +x /seed.sh

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/seed.sh"]
