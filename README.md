# php2shell-scanner

A non-invasive scanner for exposed, outdated PHP versions affected by PHP2Shell
(CVE-2026-109618 and CVE-2026-109619). It sends one `HEAD` request per target and
reads only the `Server` and `X-Powered-By` response headers. It sends no exploit
payload, multipart upload, large allocation, session mutation, or file write.

## What a result means

- `OUTDATED`: the server exposed an exact PHP version below its upstream fixed release.
- `PATCHED`: the exposed version is at or above the upstream fixed release.
- `UNKNOWN`: PHP may be present, but no exact version was exposed. Check the package
  locally; a remote version-only scanner cannot safely prove its patch state.
- `UNREACHABLE`: the connection or TLS handshake failed.

Fixed upstream releases published 21 October 2026:

| Branch | First fixed release |
|---|---:|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |
| 8.1 and older | No upstream release; end of life |

Linux distributions may backport fixes without changing the upstream-looking version.
For distro packages, verify the vendor security notice and installed package changelog.

## Install

Requires Python 3.10 or newer and has no runtime dependencies.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Use

Scan a private range over HTTP:

```bash
php2shell-scan 192.168.50.0/24 --scheme http --ports 80
```

Scan selected HTTPS targets and produce JSON Lines:

```bash
php2shell-scan https://app.example.test/ 10.20.0.0/24 \
  --scheme https --ports 443,8443 --json
```

For an IP behind name-based virtual hosting, supply the expected hostname:

```bash
php2shell-scan 10.20.30.40 --scheme https --ports 443 \
  --host-header intranet.example.test --insecure
```

The command exits `1` when any confirmed outdated version is found, `2` for invalid
arguments, and `0` otherwise. `UNKNOWN` does not mean safe.

Only scan address space you own or are authorized to assess. Keep concurrency modest
on production networks (`--workers 5`) and select only ports you expect to host HTTP.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Sources: [PHP security release](https://www.php.net/),
[PHP 8 changelog](https://www.php.net/ChangeLog-8.php), and
[PHP unsupported branches](https://www.php.net/eol.php).

