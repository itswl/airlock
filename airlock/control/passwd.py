"""Print the scrypt hash for the operator password: python -m airlock.control.passwd

The hash goes into AIRLOCK_OPERATOR_PASSWORD_HASH (or whatever the config names).
The password itself is read without echo and never written anywhere.
"""

from __future__ import annotations

import getpass
import sys

from airlock.control.auth import hash_password


def main() -> int:
    first = getpass.getpass("operator password: ")
    if len(first) < 12:
        print("use at least 12 characters", file=sys.stderr)
        return 1
    if getpass.getpass("again: ") != first:
        print("the two entries differ", file=sys.stderr)
        return 1
    print(hash_password(first))
    return 0


if __name__ == "__main__":
    sys.exit(main())
