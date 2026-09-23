# Working on airlock

airlock separates looking from changing: investigators are read-only, workers
run only an approved plan, and everything is recorded. Changes to this code
must keep that true. Before you touch anything, know which side you are on.

## Rules

- **The skeleton is fixed.** signal → one investigator → plan → one approval →
  launcher → workers → record. Configuration may add sources, routes and
  profiles; it may not add a path around the approval. A feature that needs
  one is the wrong feature.
- **The launcher trusts nothing it can check itself.** Any change to what the
  control plane sends must keep the launcher re-checking hash, expiry, single
  use and its own worker profiles. Never make the launcher accept a plan the
  control plane has "already validated".
- **An approval binds to a version and a hash.** Anything that changes a plan
  after approval — normalising, reordering, filling defaults — changes the
  hash. Compute the hash over `plan.model_dump(mode="json")` and nothing else.
- **Records live outside what they record.** The executor streams; the
  launcher keeps. Do not add a path where a worker container writes the
  authoritative record of its own run.
- **The core does not depend on what surrounds it.** `airlock/extras/` (the
  watcher, the chat adapter, the self-check, the mirrors) talks to the core only
  through its doors: intake, outlet, adapter endpoints, health. No core module
  imports it (`tests/test_extras.py`). A feature that needs the core to know an
  extra exists is a change to a door, made for every caller.
- **A workspace stays the worker's after it exits.** The launcher reads a
  worker's workspace as plain files and never runs git (or anything) in it:
  its `.git/config` can name programs, and the launcher sits next to the
  Docker socket. What changed is computed against the mirror, which is trusted.
- **Tests never touch the outside.** No network beyond loopback, no Docker, no
  model, no credentials, nothing outside pytest's tmp directory. A command a
  test expects to be refused must be harmless if a bug let it run.
- **Say what was not run.** Docker and `deploy/` have run for real
  (`AIRLOCK_DOCKER_TESTS=1 pytest tests/test_docker.py`,
  `python scripts/compose_smoke.py`), and `deploy/compose.yml` runs on one Linux
  server with the Claude engine in its investigator container, the MCP gateway
  in front of a real server (`scripts/mcpgate_check.py` for the protocol), and
  one worker holding a real credential: the forced-command SSH key of
  `deploy/host/`. A task-mode worker has run a real model in its container
  and changed a repository (`scripts/compose_smoke.py --code`, on DeepSeek).
  The extras have run together in compose with a real model on a made-up chat
  (`scripts/extras_smoke.py`); a real Feishu application, a real chat platform
  and a real Jira have not. Cloud identities (AWS, K8s) have not run. A change
  there is not verified until it has run for real, and a PR says which.
- **A real model reads nothing it should not send.** Outside a container a real
  engine runs confined, in a working directory outside every repository, with
  a curated environment. What a tool reads is sent to the model provider.

## Before a commit

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

Read the result; a red line is not a formality.
