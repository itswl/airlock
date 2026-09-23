from __future__ import annotations

import hashlib
import hmac

import pytest

from airlock.crypto import (
    SignatureError,
    canonical_json,
    sign,
    verify,
    verify_bearer,
    verify_hub_signature,
)


def test_sign_and_verify_round_trip() -> None:
    headers = sign("s3cret", b'{"a":1}', now=1000)
    verify("s3cret", b'{"a":1}', headers, now=1001)


@pytest.mark.parametrize(
    ("secret", "body", "now", "message"),
    [
        ("other", b'{"a":1}', 1001, "does not match"),
        ("s3cret", b'{"a":2}', 1001, "does not match"),
        ("s3cret", b'{"a":1}', 1000 + 301, "outside the allowed window"),
        ("", b'{"a":1}', 1001, "no secret"),
    ],
)
def test_verify_refuses(secret: str, body: bytes, now: int, message: str) -> None:
    headers = sign("s3cret", b'{"a":1}', now=1000)
    with pytest.raises(SignatureError, match=message):
        verify(secret, body, headers, now=now)


def test_verify_needs_headers_and_is_case_insensitive() -> None:
    with pytest.raises(SignatureError, match="missing"):
        verify("s", b"{}", {}, now=0)
    headers = {k.lower(): v for k, v in sign("s", b"{}", now=5).items()}
    verify("s", b"{}", headers, now=5)


def test_sign_refuses_an_empty_secret() -> None:
    with pytest.raises(ValueError):
        sign("", b"{}")


def test_hub_signature() -> None:
    body = b'{"zen":"x"}'
    good = "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()
    verify_hub_signature("k", body, good)
    for bad in ("", "sha1=abc", "sha256=" + "0" * 64):
        with pytest.raises(SignatureError):
            verify_hub_signature("k", body, bad)
    with pytest.raises(SignatureError):
        verify_hub_signature("", body, good)


def test_bearer() -> None:
    verify_bearer("tok", "Bearer tok")
    for bad in ("", "Bearer", "Basic tok", "Bearer nope"):
        with pytest.raises(SignatureError):
            verify_bearer("tok", bad)
    with pytest.raises(SignatureError):
        verify_bearer("", "Bearer ")


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": "é"}) == canonical_json({"a": "é", "b": 1}) == '{"a":"é","b":1}'.encode()
