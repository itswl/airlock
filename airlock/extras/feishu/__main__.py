"""python -m airlock.extras.feishu --config feishu.yaml [--host 0.0.0.0] [--port 9100]

Serves the two doors (``/airlock`` for the outlet, ``/notice`` for the
watcher). With an application configured, it also holds the long connection
for replies, in a background thread. A custom bot's webhook needs no
connection and gets none.
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from pathlib import Path

from airlock.extras.feishu.app import Cards, create_app
from airlock.extras.feishu.config import load_feishu
from airlock.extras.feishu.lark import Lark, Webhook
from airlock.extras.settings import SettingsError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m airlock.extras.feishu", description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        config = load_feishu(args.config)
    except (SettingsError, OSError) as exc:
        print(f"feishu: {exc}", file=sys.stderr)
        return 2
    config.state.parent.mkdir(parents=True, exist_ok=True)
    sender = (
        Lark(config.app_id, config.app_secret, brand=config.brand)
        if config.app_id
        else Webhook(config.webhook_url, config.webhook_secret)
    )
    cards = Cards(config, sender)
    if config.app_id and config.people:
        from airlock.extras.feishu.inbound import listen

        threading.Thread(target=listen, args=(config, cards), daemon=True, name="lark-events").start()
    import uvicorn

    uvicorn.run(create_app(config, cards), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
