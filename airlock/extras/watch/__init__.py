"""The watcher: reads your chat and tickets on a schedule and posts what needs you. A source, outside the core.

    python -m airlock.extras.watch --config watch.yaml          # every round on schedule
    python -m airlock.extras.watch --config watch.yaml --once   # one round now

A round has three parts, and only the middle one uses a model:

1. **Scan** (``scan.py``): deterministic. It looks at every conversation since
   the last cursor, drops what is only noise (your own messages, bots,
   one-character fragments), holds high-volume conversations until a batch is
   due, and reads the ticket tracker's changes. Nothing new means no round:
   no model and no bill. A source that cannot be reached is itself something
   to report, because an unreachable source is not a quiet one.
2. **Judge** (``judge.py``): the model reads the brief and what the scan
   found. It answers with one ``signals`` block. It has no built-in tools,
   only the chat's read tools through the MCP gateway, so it cannot read a
   file, run a command, or see this process's secrets.
3. **Deliver** (``deliver.py``): this process checks every signal against
   what the scan offered and drops any that names a conversation it was not
   given. It then signs and posts each task to airlock's intake, where it
   becomes a work item, and each note to the notice door, where it becomes a
   chat card. The agent never holds a signing key.

Every round is written to a chained record (``rounds.jsonl``), and
``status.json`` says when the last tick and the last round happened, for
whatever watches the watcher (``airlock.extras.selfcheck``).
"""
