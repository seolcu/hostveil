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
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install ttyd (web terminal)
RUN curl -fsSL https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 -o /usr/local/bin/ttyd \
    && chmod +x /usr/local/bin/ttyd

# Create user with sudo access
RUN groupadd --gid "${GROUP_ID}" "${USER_NAME}" \
    && useradd --uid "${USER_ID}" --gid "${GROUP_ID}" --create-home --shell /bin/bash "${USER_NAME}" \
    && printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${USER_NAME}" > "/etc/sudoers.d/${USER_NAME}" \
    && chmod 0440 "/etc/sudoers.d/${USER_NAME}"

# Set up workspace
WORKDIR /workspace
RUN chown -R ${USER_NAME}:${USER_NAME} /workspace

USER ${USER_NAME}

# Expose ttyd port
EXPOSE 7681

CMD ["ttyd", "bash"]
