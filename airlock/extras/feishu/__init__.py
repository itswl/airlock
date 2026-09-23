"""The Feishu / Lark adapter: airlock's notifications as cards, and your replies back as messages. A subscriber.

    python -m airlock.extras.feishu --config feishu.yaml

**Out.** It subscribes to airlock's outlet. Every notification arrives signed,
and a delivery is kept once however often it is retried. It becomes a card in
the plans chat: a plan to approve, a report, a run's result with its diff
summary. Later cards about the same work item go into that item's thread. The
watcher's notes arrive at ``/notice`` (signed with their own secret) and
become cards in the notices chat. Cards are sent as the application through
the open platform's message API. A custom bot's webhook works too, but a
custom bot can only send: no replies come back, and nothing is threaded.

**In.** It holds the application's one long connection (Lark allows one per
application) and reads each message that @-mentions it. What happens depends
on where the message is:
- a reply under a work item's card becomes your message on that item, and the
  investigator revises its plan;
- a reply under a note, or a new topic that mentions the bot, becomes a new
  work item through the adapter's own intake source.

Only people you listed may do either; anyone else is ignored and logged.

**Approval stays on the web console.** A card links to the plan and says how
to approve, but it has no approve button. A button would make the chat
account a second key to the one decision airlock exists to protect.

Everything here is outside the core: it uses the outlet, the adapter endpoints
(``/v1/adapters/<name>/message``) and an intake door, and nothing else.
"""
