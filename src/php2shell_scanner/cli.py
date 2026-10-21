from __future__ import annotations

import argparse
from collections import Counter
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from .scanner import expand_targets, scan


def _print_report(results: list, limit: int) -> None:
    counts = Counter(result.status for result in results)
    summary = " ".join(f"{name}={counts[name]}" for name in sorted(counts))
    print(f"\nReport: scanned={len(results)} {summary}")

    sections = [
        ("Outdated PHP platforms", lambda result: result.status == "outdated_platform"),
        ("Outdated PHP", lambda result: result.status == "outdated"),
        ("PHP version hidden", lambda result: result.status == "php_unknown"),
        ("Patched PHP", lambda result: result.status == "patched"),
        ("Legacy TLS", lambda result: result.tls_mode == "legacy"),
        ("Unknown web responders", lambda result: result.status == "unknown"),
    ]
    for title, predicate in sections:
        matches = [result for result in results if predicate(result)]
        if not matches:
            continue
        print(f"\n{title} ({len(matches)}):")
        for result in sorted(matches, key=lambda item: item.target)[:limit]:
            version = f" PHP/{result.php_version}" if result.php_version else ""
            evidence = f" [{result.evidence}]" if result.evidence else ""
            path = f" path={result.probe_path}" if result.probe_path and result.probe_path != "/" else ""
            print(f"  {result.target}{version}{path}{evidence}")
        if len(matches) > limit:
            print(f"  ... {len(matches) - limit} more")

    application_hosts = {}
    for result in results:
        for application in result.applications or []:
            application_hosts.setdefault(application, []).append(result.target)
    if application_hosts:
        print("\nApplication fingerprints:")
        for application in sorted(application_hosts):
            targets = sorted(set(application_hosts[application]))
            shown = ", ".join(targets[:limit])
            suffix = f" (+{len(targets) - limit} more)" if len(targets) > limit else ""
            print(f"  {application} ({len(targets)}): {shown}{suffix}")

    unreachable = [result for result in results if result.status == "unreachable"]
    if unreachable:
        error_counts = Counter((result.error or "unknown error").split(":", 1)[0] for result in unreachable)
        errors = ", ".join(f"{name}={count}" for name, count in sorted(error_counts.items()))
        print(f"\nUnreachable ({len(unreachable)}): {errors}")

    if counts["php_unknown"]:
        print("\nAction: verify installed packages locally on PHP version-hidden hosts.")
    if counts["unknown"]:
        print("Action: scan known DNS names and PHP paths for unknown web responders.")
    legacy_count = sum(result.tls_mode == "legacy" for result in results)
    if legacy_count:
        print(f"Action: upgrade TLS configuration on {legacy_count} legacy-compatible host(s).")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Non-invasive PHP2Shell version exposure scanner")
    p.add_argument("targets", nargs="+", help="CIDR, hostname, IP, or complete http(s) URL")
    p.add_argument("--ports", help="comma-separated ports; explicit ports are tried with each selected scheme")
    p.add_argument("--scheme", choices=("http", "https", "both"), default="both")
    p.add_argument("--path", help="single request path; default probes / and then /index.php when needed")
    p.add_argument("--host-header", help="virtual host name to send when scanning IPs")
    p.add_argument("--workers", type=int, default=20)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--max-hosts", type=int, default=4096, help="maximum expanded IP hosts")
    p.add_argument("--verify-tls", action="store_true", help="verify TLS certificates (disabled by default for IP-range scans)")
    p.add_argument("--insecure", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--json", action="store_true", help="emit JSON Lines")
    p.add_argument("--report-limit", type=int, default=25, help="maximum hosts shown per report section (default: 25)")
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
        request_path = args.path or "/"
        futures = {
            pool.submit(scan, target, args.timeout, request_path, args.host_header, verify_tls, args.path is None): target
            for target in targets
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if args.json:
                print(json.dumps(result.as_dict(), sort_keys=True))
            else:
                version = f" PHP/{result.php_version}" if result.php_version else ""
                tls = " [legacy TLS]" if result.tls_mode == "legacy" else ""
                path = f" [path={result.probe_path}]" if result.probe_path and result.probe_path != "/" else ""
                applications = f" [apps={','.join(result.applications)}]" if result.applications else ""
                if result.application_versions:
                    rendered = ",".join(
                        f"{name}/{result.application_versions[name]}"
                        if name in result.application_versions else name
                        for name in result.applications or []
                    )
                    applications = f" [apps={rendered}]"
                detail = result.reason or result.error or ""
                if result.status == "php_unknown" and result.evidence:
                    detail = f"{detail} ({result.evidence})"
                print(f"{result.status.upper():11} {result.target}{version}{tls}{path}{applications}  {detail}")
    if not args.json:
        _print_report(results, max(1, args.report_limit))
    return 1 if any(result.status in {"outdated", "outdated_platform"} for result in results) else 0

