# One image for every airlock component: control plane, launcher, investigator
# node, egress proxy, and the executor inside worker containers.
#
# Images that need more build FROM this one, for example:
#   investigator with the Claude engine:  RUN pip install --no-cache-dir 'airlock[claude]'  (plus the Claude Code CLI if your SDK version does not bundle it)
#   worker for k8s-ops:                   add kubectl, nothing else
#   worker for aws-ops:                   add the AWS CLI, nothing else
# A worker image should hold the tools its allowlist names and no others.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

COPY pyproject.toml /src/
COPY airlock /src/airlock
RUN pip install --no-cache-dir /src && rm -rf /src \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin airlock

USER 10001
WORKDIR /work
CMD ["python", "-m", "airlock.control", "--config", "/etc/airlock/config.yaml", "--host", "0.0.0.0"]
