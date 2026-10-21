FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV ANSIBLE_HOST_KEY_CHECKING=false
ENV ANSIBLE_STDOUT_CALLBACK=yaml
ENV ANSIBLE_CALLBACKS_ENABLED=profile_tasks

ARG VERSION

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir ansible infisicalsdk "certifi>=2026.10.19"

RUN ansible-galaxy collection install infisical.vault==${VERSION}

WORKDIR /ansible

RUN mkdir -p /root/.ansible

# Set default command
CMD ["/bin/bash"]