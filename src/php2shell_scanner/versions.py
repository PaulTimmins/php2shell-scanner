from __future__ import annotations

import re
from dataclasses import dataclass


PHP_VERSION = re.compile(r"(?i)\bPHP(?:/|\s+)(\d+\.\d+\.\d+(?:[-+._a-z0-9]*)?)")
PHP_TOKEN = re.compile(r"(?i)\bPHP\b")

# First upstream releases containing the 21 October 2026 PHP2Shell fixes.
FIXED_RELEASES = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}


@dataclass(frozen=True)
class Assessment:
    version: str
    status: str
    reason: str


def extract_version(values: list[str]) -> str | None:
    for value in values:
        match = PHP_VERSION.search(value)
        if match:
            return match.group(1)
    return None


def php_header_evidence(headers: list[tuple[str, str]]) -> list[str]:
    """Return response-header evidence that identifies PHP without guessing."""
    evidence: list[str] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered in {"server", "x-powered-by"} and PHP_TOKEN.search(value):
            evidence.append(f"{name}: {value}")
        elif lowered == "set-cookie" and re.match(r"(?i)^PHPSESSID=", value):
            evidence.append(f"{name}: PHPSESSID=<redacted>")
        elif lowered.startswith("x-php-"):
            evidence.append(f"{name}: {value}")
    return evidence


def _numeric(version: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    return tuple(map(int, match.groups())) if match else None


def assess(version: str) -> Assessment:
    parsed = _numeric(version)
    if parsed is None:
        return Assessment(version, "unknown", "version could not be parsed")
    branch = parsed[:2]
    if branch < (8, 2):
        return Assessment(version, "outdated", "branch is end-of-life and has no upstream PHP2Shell fix")
    fixed = FIXED_RELEASES.get(branch)
    if fixed is None:
        if branch > (8, 5):
            return Assessment(version, "not_affected", "release is newer than affected branches")
        return Assessment(version, "unknown", "branch is not in the upstream fix table")
    fixed_text = ".".join(map(str, fixed))
    if parsed < fixed:
        return Assessment(version, "outdated", f"upstream fix begins at PHP {fixed_text}")
    return Assessment(version, "patched", f"at or above upstream fixed release PHP {fixed_text}")

