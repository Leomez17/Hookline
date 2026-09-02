"""TLS certificate check for a URL's host.

This is the one enrichment check that connects directly to a user-supplied
— and possibly hostile — destination, rather than to a trusted third
party, so it carries its own SSRF guard: every address the host resolves
to is checked against private/loopback/link-local/reserved ranges before
a socket is opened, and if none of them are safe to reach the connection
is refused rather than attempted. The socket then connects to that
specific validated IP (not a fresh DNS lookup at connect time), which
also closes the DNS-rebinding window between the check and the connect.

Certificate validation itself is deliberately turned off (CERT_NONE) —
we *want* to see the certificate even if it's self-signed, expired, or
for the wrong hostname, because those are exactly the anomalies worth
surfacing, not reasons to fail closed before we've looked.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

TLS_PORT = 443
RECENT_CERT_DAYS = 7
RECENT_CERT_POINTS = 8
HANDSHAKE_FAILED_POINTS = 15
EXPIRED_CERT_POINTS = 20


def _is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


class TlsClient:
    def __init__(self, enabled: bool = True, timeout: float = 4.0):
        self._enabled = enabled
        self._timeout = timeout

    def inspect(self, url: str) -> List[dict]:
        if not self._enabled:
            return [{
                "signal": "enrich:tls:unavailable",
                "detail": "Live TLS certificate checks are disabled (set ENABLE_LIVE_ENRICHMENT=true)",
                "points": 0,
            }]

        host = urlparse(url if "://" in url else f"https://{url}").hostname
        if not host:
            return []

        try:
            infos = socket.getaddrinfo(host, TLS_PORT, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return [{"signal": "enrich:tls:unavailable", "detail": f"Could not resolve {host}: {exc}", "points": 0}]

        safe_addrs = [info for info in infos if _is_safe_ip(info[4][0])]
        if not safe_addrs:
            return [{
                "signal": "enrich:tls:refused-private-address",
                "detail": f"{host} resolves only to a private/internal address — refusing to connect to it directly",
                "points": 0,
            }]

        ip = safe_addrs[0][4][0]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((ip, TLS_PORT), timeout=self._timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    der_cert = tls_sock.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError) as exc:
            return [{
                "signal": "enrich:tls:handshake-failed",
                "detail": f"Could not establish a TLS connection to {host}: {exc}",
                "points": HANDSHAKE_FAILED_POINTS,
            }]

        if not der_cert:
            return [{"signal": "enrich:tls:no-certificate", "detail": f"{host} presented no certificate", "points": HANDSHAKE_FAILED_POINTS}]

        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        issued_at = cert.not_valid_before_utc
        expires_at = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)

        findings: List[dict] = []
        if now > expires_at:
            findings.append({
                "signal": "enrich:tls:expired-certificate",
                "detail": f"Certificate for {host} expired on {expires_at.date()}",
                "points": EXPIRED_CERT_POINTS,
            })

        age_days = (now - issued_at).days
        if now <= expires_at and age_days < RECENT_CERT_DAYS:
            findings.append({
                "signal": "enrich:tls:recently-issued-certificate",
                "detail": f"Certificate for {host} was issued {age_days} day(s) ago ({issued_at.date()}) — "
                          f"weak on its own (free automated certs are routine), but notable alongside other findings",
                "points": RECENT_CERT_POINTS,
            })

        if not findings:
            findings.append({
                "signal": "enrich:tls:established-certificate",
                "detail": f"Certificate for {host} issued {age_days} days ago, valid until {expires_at.date()}",
                "points": 0,
            })
        return findings
