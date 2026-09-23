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
- **Tests never touch the outside.** No network beyond loopback, no Docker, no
  model, no credentials, nothing outside pytest's tmp directory. A command a
  test expects to be refused must be harmless if a bug let it run.
- **Say what was not run.** The Docker runtime and `deploy/` are tested only as
  far as their wiring; the Claude engine has run for real only confined on a
  host (`scripts/demo.py --engine claude`). A change there is not verified until
  it has run for real, and a PR says which.
- **A real model reads nothing it should not send.** Outside a container a real
  engine runs confined, in a working directory outside every repository, with
  a curated environment. What a tool reads is sent to the model provider.

## Before a commit

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

Read the result; a red line is not a formality.
