FROM rust:1-bookworm

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

CMD ["ttyd", "bash", "-lc", "cd /workspace && printf '\\nHostveil self-hosting lab\\n\\nUseful commands:\\n  cargo run -- --user-mode --compose docker/lab/self-hosting-stack.yml\\n  cargo run -- --user-mode --json --compose docker/lab/self-hosting-stack.yml --adapters none\\n  cargo run -- --json --compose docker/lab/self-hosting-stack.yml --host-root / --adapters trivy,dockle,lynis\\n  cargo run -- --user-mode --fix docker/lab/self-hosting-stack.yml --preview-changes\\n\\n' && exec bash"]
