from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .versions import assess, extract_version


@dataclass
class Result:
    target: str
    status: str
    http_status: int | None = None
    php_version: str | None = None
    evidence: str | None = None
    reason: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def expand_targets(entries: list[str], endpoints: list[tuple[str, int]], max_hosts: int) -> list[str]:
    targets: list[str] = []
    for entry in entries:
        if "://" in entry:
            targets.append(entry)
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            hosts = [entry]
        else:
            count = network.num_addresses if network.prefixlen in (31, 32, 127, 128) else max(network.num_addresses - 2, 0)
            if count + len(targets) > max_hosts:
                raise ValueError(f"target expansion exceeds --max-hosts={max_hosts}")
            hosts = [str(ip) for ip in network.hosts()]
        for host in hosts:
            bracketed = f"[{host}]" if ":" in host else host
            for scheme, port in endpoints:
                targets.append(f"{scheme}://{bracketed}:{port}/")
    if len(targets) > max_hosts * max(1, len(endpoints)):
        raise ValueError("target expansion exceeds safety limit")
    return targets


def scan(target: str, timeout: float, path: str, host_header: str | None, verify_tls: bool) -> Result:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return Result(target, "error", error="target must be an http(s) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    request_path = path if path.startswith("/") else f"/{path}"
    headers = {"User-Agent": "php2shell-scanner/0.1 (version-only; non-invasive)", "Accept": "*/*", "Connection": "close"}
    if host_header:
        headers["Host"] = host_header
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        conn.request("HEAD", request_path, headers=headers)
        response = conn.getresponse()
        response.read(1024)
        header_pairs = response.getheaders()
        conn.close()
        evidence_values = [value for key, value in header_pairs if key.lower() in {"server", "x-powered-by"}]
        version = extract_version(evidence_values)
        if version is None:
            return Result(target, "unknown", response.status, evidence="; ".join(evidence_values) or None,
                          reason="no exact PHP version exposed in Server or X-Powered-By headers")
        verdict = assess(version)
        return Result(target, verdict.status, response.status, version, "; ".join(evidence_values), verdict.reason)
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        return Result(target, "unreachable", error=f"{type(exc).__name__}: {exc}")

