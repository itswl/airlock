"""The egress proxy on loopback: refused destinations never get a connection, listed ones get a tunnel."""

from __future__ import annotations

import socket
import socketserver
import threading
from collections.abc import Iterator

import pytest

from airlock.egress import proxy


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        data = self.request.recv(1024)
        self.request.sendall(b"echo:" + data)


@pytest.fixture
def servers(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[int, int]]:
    upstream = socketserver.TCPServer(("127.0.0.1", 0), Echo)
    gateway = proxy.Server(("127.0.0.1", 0), proxy.Handler)
    monkeypatch.setattr(proxy, "ALLOW", ("127.0.0.1", ".example.internal"))
    monkeypatch.setattr(proxy, "PORTS", frozenset({upstream.server_address[1]}))
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, gateway)]
    for thread in threads:
        thread.start()
    yield gateway.server_address[1], upstream.server_address[1]
    for server in (upstream, gateway):
        server.shutdown()
        server.server_close()


def ask(port: int, head: bytes) -> tuple[bytes, socket.socket]:
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.sendall(head)
    return client.recv(1024), client


def test_rules() -> None:
    rules = ("api.anthropic.com", ".amazonaws.com")
    original = proxy.ALLOW
    try:
        proxy.ALLOW = rules
        assert (
            proxy.permitted("API.anthropic.com.")
            and proxy.permitted("sts.amazonaws.com")
            and proxy.permitted("amazonaws.com")
        )
        assert not proxy.permitted("anthropic.com") and not proxy.permitted("amazonaws.com.attacker.invalid")
        proxy.ALLOW = ()
        assert not proxy.permitted("api.anthropic.com")
    finally:
        proxy.ALLOW = original


def test_an_unlisted_host_is_refused_before_any_connection(servers: tuple[int, int]) -> None:
    gateway, upstream = servers
    answer, client = ask(gateway, f"CONNECT attacker.invalid:{upstream} HTTP/1.1\r\n\r\n".encode())
    client.close()
    assert answer.startswith(b"HTTP/1.1 403") and b"not on the egress allowlist" in answer


def test_an_unlisted_port_is_refused(servers: tuple[int, int]) -> None:
    gateway, _ = servers
    answer, client = ask(gateway, b"CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n")
    client.close()
    assert answer.startswith(b"HTTP/1.1 403") and b"port 22" in answer


def test_a_listed_destination_gets_a_tunnel(servers: tuple[int, int]) -> None:
    gateway, upstream = servers
    answer, client = ask(gateway, f"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert answer.startswith(b"HTTP/1.1 200")
    client.sendall(b"hello")
    assert client.recv(1024) == b"echo:hello"
    client.close()


def test_plain_http_is_checked_against_the_same_list(servers: tuple[int, int]) -> None:
    gateway, upstream = servers
    answer, client = ask(gateway, f"GET http://attacker.invalid:{upstream}/x HTTP/1.1\r\n\r\n".encode())
    client.close()
    assert answer.startswith(b"HTTP/1.1 403")


def test_bytes_sent_right_behind_the_connect_are_not_lost(servers: tuple[int, int]) -> None:
    # Some clients start TLS without waiting for "200 Connection established":
    # whatever arrived with the request head must be passed on, not left in a buffer.
    gateway, upstream = servers
    client = socket.create_connection(("127.0.0.1", gateway), timeout=5)
    client.sendall(f"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\nHost: x\r\n\r\n".encode() + b"early")
    received = b""
    while b"echo:" not in received:
        chunk = client.recv(1024)
        if not chunk:
            break
        received += chunk
    client.close()
    assert received.startswith(b"HTTP/1.1 200") and received.endswith(b"echo:early"), received
