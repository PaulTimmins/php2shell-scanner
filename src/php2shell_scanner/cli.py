from __future__ import annotations

import argparse
from collections import Counter
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from .scanner import expand_targets, scan


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Non-invasive PHP2Shell version exposure scanner")
    p.add_argument("targets", nargs="+", help="CIDR, hostname, IP, or complete http(s) URL")
    p.add_argument("--ports", help="comma-separated ports; explicit ports are tried with each selected scheme")
    p.add_argument("--scheme", choices=("http", "https", "both"), default="both")
    p.add_argument("--path", default="/", help="request path used for fingerprinting")
    p.add_argument("--host-header", help="virtual host name to send when scanning IPs")
    p.add_argument("--workers", type=int, default=20)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--max-hosts", type=int, default=4096, help="maximum expanded IP hosts")
    p.add_argument("--verify-tls", action="store_true", help="verify TLS certificates (disabled by default for IP-range scans)")
    p.add_argument("--insecure", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--json", action="store_true", help="emit JSON Lines")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        schemes = ["http", "https"] if args.scheme == "both" else [args.scheme]
        if args.ports:
            ports = [int(value) for value in args.ports.split(",")]
            if not ports or any(port < 1 or port > 65535 for port in ports):
                raise ValueError("ports must be between 1 and 65535")
            endpoints = [(scheme, port) for scheme in schemes for port in ports]
        else:
            endpoints = [("http", 80), ("https", 443)] if args.scheme == "both" else [
                (args.scheme, 443 if args.scheme == "https" else 80)
            ]
        targets = expand_targets(args.targets, endpoints, args.max_hosts)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 100))) as pool:
        verify_tls = args.verify_tls and not args.insecure
        futures = {pool.submit(scan, target, args.timeout, args.path, args.host_header, verify_tls): target for target in targets}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if args.json:
                print(json.dumps(result.as_dict(), sort_keys=True))
            else:
                version = f" PHP/{result.php_version}" if result.php_version else ""
                detail = result.reason or result.error or ""
                print(f"{result.status.upper():11} {result.target}{version}  {detail}")
    if not args.json:
        counts = Counter(result.status for result in results)
        summary = " ".join(f"{name}={counts[name]}" for name in sorted(counts))
        print(f"\nSummary: scanned={len(results)} {summary}", file=sys.stderr)
        if counts["unknown"]:
            print("Hint: UNKNOWN hosts hid PHP versions or may not run PHP; scan known DNS names/paths for their virtual hosts.", file=sys.stderr)
    return 1 if any(result.status == "outdated" for result in results) else 0

