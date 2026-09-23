"""python -m airlock.control --config config.yaml"""

from __future__ import annotations

import argparse
import logging

import uvicorn

from airlock.config import load_control
from airlock.control.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="airlock control plane")
    parser.add_argument("--config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    uvicorn.run(create_app(load_control(args.config)), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
