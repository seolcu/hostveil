FROM rust:1.95-bookworm

ENV RUSTUP_TOOLCHAIN=1.95.0

ARG USER_ID=1000
ARG GROUP_ID=1000
ARG USER_NAME=hostveil

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

# Install ttyd (web terminal)
RUN curl -fsSL https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 -o /usr/local/bin/ttyd \
    && chmod +x /usr/local/bin/ttyd

# Install Trivy
RUN curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-64bit.deb -o /tmp/trivy.deb \
    && dpkg -i /tmp/trivy.deb \
    && rm /tmp/trivy.deb

# Install Dockle
RUN curl -fsSL https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_Linux-64bit.tar.gz -o /tmp/dockle.tar.gz \
    && tar -xzf /tmp/dockle.tar.gz -C /usr/local/bin dockle \
    && rm /tmp/dockle.tar.gz

# Install Docker CLI
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-28.0.4.tgz -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1 docker/docker \
    && rm /tmp/docker.tgz

# Create user with sudo access
RUN groupadd --gid "${GROUP_ID}" "${USER_NAME}" \
    && useradd --uid "${USER_ID}" --gid "${GROUP_ID}" --create-home --shell /bin/bash "${USER_NAME}" \
    && printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${USER_NAME}" > "/etc/sudoers.d/${USER_NAME}" \
    && chmod 0440 "/etc/sudoers.d/${USER_NAME}"

# Ensure cargo stays on PATH for login shells
RUN printf 'export PATH="/usr/local/cargo/bin:$PATH"\n' > /etc/profile.d/rust.sh

# Set up workspace
WORKDIR /workspace
RUN mkdir -p /workspace/target && chown -R ${USER_NAME}:${USER_NAME} /workspace

USER ${USER_NAME}

EXPOSE 7681

CMD ["ttyd", "bash", "-lc", "cd /workspace && printf '\\nHostveil self-hosting lab (Go v1.0.0)\\n\\nUseful commands:\\n  go install github.com/seolcu/hostveil/cmd/hostveil@latest\\n  hostveil --user-mode --compose docker/lab/self-hosting-stack.yml\\n  hostveil --user-mode --output json --compose docker/lab/self-hosting-stack.yml\\n  hostveil --user-mode --serve --compose docker/lab/self-hosting-stack.yml --port 8080\\n\\n' && exec bash"]
