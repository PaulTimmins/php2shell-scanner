from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import warnings
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .versions import assess, extract_version, php_header_evidence, relative_php_url_evidence


@dataclass
class Result:
    target: str
    status: str
    http_status: int | None = None
    php_version: str | None = None
    evidence: str | None = None
    reason: str | None = None
    error: str | None = None
    tls_mode: str | None = None
    probe_path: str | None = None

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


def _tls_context(verify_tls: bool, legacy: bool = False) -> ssl.SSLContext:
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    if legacy:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    return context


def _request(parsed, port: int, timeout: float, headers: dict[str, str], method: str, path: str,
             verify_tls: bool, legacy_tls: bool = False, read_limit: int = 1024):
    if parsed.scheme == "https":
        connection = http.client.HTTPSConnection(
            parsed.hostname, port, timeout=timeout, context=_tls_context(verify_tls, legacy_tls)
        )
    else:
        connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    connection.request(method, path, headers=headers)
    reply = connection.getresponse()
    body = reply.read(read_limit)
    result = reply.status, reply.getheaders(), body
    connection.close()
    return result


def scan(target: str, timeout: float, path: str, host_header: str | None, verify_tls: bool,
         fallback_index: bool = False) -> Result:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return Result(target, "error", error="target must be an http(s) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    request_path = path if path.startswith("/") else f"/{path}"
    headers = {"User-Agent": "php2shell-scanner/0.1 (version-only; non-invasive)", "Accept": "*/*", "Connection": "close"}
    if host_header:
        headers["Host"] = host_header
    try:
        tls_mode = None
        try:
            response_status, header_pairs, _ = _request(
                parsed, port, timeout, headers, "HEAD", request_path, verify_tls
            )
        except ssl.SSLError:
            if verify_tls or parsed.scheme != "https":
                raise
            response_status, header_pairs, _ = _request(
                parsed, port, timeout, headers, "HEAD", request_path, False, legacy_tls=True
            )
            tls_mode = "legacy"
        evidence_values = [value for key, value in header_pairs if key.lower() in {"server", "x-powered-by"}]
        version = extract_version(evidence_values)
        if version is None:
            php_evidence = php_header_evidence(header_pairs)
            if php_evidence:
                result = Result(target, "php_unknown", response_status, evidence="; ".join(php_evidence),
                                reason="PHP identified, but its exact version is hidden", tls_mode=tls_mode,
                                probe_path=request_path)
            else:
                result = Result(target, "unknown", response_status, evidence="; ".join(evidence_values) or None,
                                reason="no PHP version or positive PHP header evidence", tls_mode=tls_mode,
                                probe_path=request_path)
            if fallback_index and request_path != "/index.php":
                if request_path == "/":
                    try:
                        _, body_headers, body = _request(
                            parsed, port, timeout, headers, "GET", "/", verify_tls,
                            legacy_tls=tls_mode == "legacy", read_limit=65536
                        )
                        content_type = next(
                            (value for name, value in body_headers if name.lower() == "content-type"), None
                        )
                        body_evidence = relative_php_url_evidence(body, content_type)
                        if body_evidence:
                            return Result(target, "php_unknown", response_status, evidence=body_evidence,
                                          reason="HTML references a relative PHP endpoint; exact version is hidden",
                                          tls_mode=tls_mode, probe_path="/")
                    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
                        pass
                index_result = scan(target, timeout, "/index.php", host_header, verify_tls, False)
                exact_statuses = {"outdated", "patched", "not_affected"}
                if index_result.status in exact_statuses:
                    return index_result
                if result.status == "unknown" and index_result.status == "php_unknown":
                    return index_result
                result.tls_mode = result.tls_mode or index_result.tls_mode
                result.reason = f"{result.reason}; also checked /index.php"
            return result
        verdict = assess(version)
        return Result(target, verdict.status, response_status, version, "; ".join(evidence_values), verdict.reason,
                      tls_mode=tls_mode, probe_path=request_path)
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        return Result(target, "unreachable", error=f"{type(exc).__name__}: {exc}")

