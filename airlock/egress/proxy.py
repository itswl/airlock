"""The one way out, and a list of where out is allowed to be. python -m airlock.egress.proxy

A container boundary stops somebody breaking into the host. It does nothing
about an agent reading a credential it is entitled to and posting it somewhere
it is not. So investigator containers (and any worker that needs the network)
sit on an internal network whose only route out is this forward proxy, on an
allowlist of hostnames. Everything legitimate is a name somebody wrote down;
everything else is refused and logged — a refused connection is the signal.

Stdlib only and small enough to read in one sitting: it sits in the path of
every call, including the model call, and a dependency there that nobody can
audit would be a worse trade than the hole it closes.

What this is not: a defence against an adversary with code execution and
patience. The allowlist is on hostnames, and a listed name that accepts
attacker-controlled content is a way out (a model gateway takes POST bodies).
It bounds the accident and the opportunist, makes the attempt visible, and
turns "anywhere" into "somewhere somebody chose".

    EGRESS_ALLOW   comma-separated; "api.anthropic.com" exactly, ".amazonaws.com" any subdomain
    EGRESS_PORT    listen port (default 8888)
    EGRESS_PORTS   destination ports it will open (default 80,443)
"""

from __future__ import annotations

import logging
import os
import select
import socket
import socketserver
import sys
import threading

logger = logging.getLogger("egress")

# Comma-separated. A bare name matches exactly; a leading dot matches any
# subdomain (".amazonaws.com" admits "ec2.ap-southeast-1.amazonaws.com").
# Empty means allow NOTHING, which is the safe direction for a variable that
# failed to interpolate — an empty allowlist is loud within seconds, where an
# empty list meaning "allow all" would be silent forever.
ALLOW = tuple(h.strip().lower() for h in os.environ.get("EGRESS_ALLOW", "").split(",") if h.strip())
PORT = int(os.environ.get("EGRESS_PORT", "8888"))
# Ports a client may CONNECT to. Everything the family speaks is HTTP or HTTPS;
# a proxy that will open 22 or 5432 for you is a tunnel, not a boundary.
PORTS = frozenset(int(p) for p in os.environ.get("EGRESS_PORTS", "80,443").split(",") if p.strip())
IDLE_SECONDS = 300


def permitted(host: str) -> bool:
    host = host.lower().strip(".")
    for rule in ALLOW:
        if rule.startswith("."):
            if host == rule[1:] or host.endswith(rule):
                return True
        elif host == rule:
            return True
    return False


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Move bytes both ways until either end stops. No inspection: this is a
    boundary about WHERE, not about what — reading the traffic would put the
    agent's tool output through one more thing that could log it."""
    sockets = [a, b]
    try:
        while True:
            ready, _, bad = select.select(sockets, [], sockets, IDLE_SECONDS)
            if bad or not ready:
                return
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (b if source is a else a).sendall(data)
    except OSError:
        return


class Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self) -> None:
        try:
            line = self.rfile.readline(65536).decode("latin-1").strip()
        except OSError:
            return
        parts = line.split()
        if len(parts) < 3:
            self._refuse(400, "not a request line", line[:40])
            return
        if parts[0].upper() != "CONNECT":
            # Absolute-URI HTTP, for plain-http peers a container on an internal
            # network cannot reach directly. Checked against the same list: this
            # proxy connects to the host out of the URI it just checked, so there
            # is no Host-header-versus-destination disagreement to exploit.
            self._plain(parts)
            return
        target = parts[1]
        host, _, port_text = target.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            self._refuse(400, "no port in the CONNECT target", target[:80])
            return
        host = host.strip("[]")
        if port not in PORTS:
            self._refuse(403, f"port {port} is not one this proxy opens", target[:80])
            return
        if not permitted(host):
            self._refuse(403, "not on the egress allowlist", target[:80])
            return
        try:
            upstream = socket.create_connection((host, port), timeout=20)
        except OSError as exc:
            self._refuse(502, f"upstream refused: {exc}", target[:80], level=logging.WARNING)
            return
        # Drain the rest of the request head before splicing.
        while True:
            more = self.rfile.readline(65536)
            if more in (b"", b"\r\n", b"\n"):
                break
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        logger.info("allowed %s", target[:80])
        with upstream:
            _pump(self.connection, upstream)

    def _plain(self, parts: list[str]) -> None:
        """One absolute-URI HTTP request, forwarded if its host is listed."""
        method, uri = parts[0], parts[1]
        if not uri.lower().startswith("http://"):
            self._refuse(400, "expected an absolute http:// URI or CONNECT", uri[:80])
            return
        rest = uri[7:]
        authority, slash, path = rest.partition("/")
        host, _, port_text = authority.rpartition(":")
        if not host:
            host, port = authority, 80
        else:
            try:
                port = int(port_text)
            except ValueError:
                self._refuse(400, "unreadable port", authority[:80])
                return
        if port not in PORTS or not permitted(host):
            self._refuse(403, "not on the egress allowlist", f"{host}:{port}")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=20)
        except OSError as exc:
            self._refuse(502, f"upstream refused: {exc}", f"{host}:{port}")
            return
        # Origin-form on the way out, which is what a server expects, plus the
        # head as the client sent it. Connection: close on both sides — this
        # forwards one request per connection rather than tracking keep-alive
        # state, which is the difference between a boundary and a web server.
        head = [f"{method} /{path if slash else ''} {parts[2]}".encode(), b"Connection: close"]
        while True:
            raw = self.rfile.readline(65536)
            if raw in (b"", b"\r\n", b"\n"):
                break
            if raw.lower().startswith((b"connection:", b"proxy-connection:")):
                continue
            head.append(raw.rstrip(b"\r\n"))
        logger.info("allowed %s %s:%s", method, host, port)
        with upstream:
            upstream.sendall(b"\r\n".join(head) + b"\r\n\r\n")
            _pump(self.connection, upstream)

    def _refuse(self, code: int, why: str, target: str, level: int = logging.WARNING) -> None:
        # WARNING, not INFO: a refusal is the whole product of this container.
        # Something behind it tried to reach an address nobody wrote down, and
        # that is worth an eye whether it was a mistake, an undeclared
        # dependency, or worse.
        logger.log(level, "REFUSED %s — %s", target, why)
        body = f"{why}\n".encode()
        try:
            self.wfile.write(f"HTTP/1.1 {code} Forbidden\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
            self.wfile.flush()
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s egress %(message)s")
    if not ALLOW:
        logger.warning("EGRESS_ALLOW is empty — every destination will be refused")
    logger.info("egress proxy on :%s, %s host rule(s), ports %s", PORT, len(ALLOW), sorted(PORTS))
    for rule in ALLOW:
        logger.info("  allow %s", rule)
    with Server(("0.0.0.0", PORT), Handler) as server:  # noqa: S104 — internal network only
        threading.current_thread().name = "egress"
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
