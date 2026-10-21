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

### Distribution packages (checked 21 October 2026)

| Distribution | Package | Fixed version/status |
|---|---|---|
| Debian 13 (trixie) | `php8.4` | `8.4.27-1~deb13u1` |
| Debian 12 (bookworm) | `php8.2` | `8.2.35-1~deb12u1` |
| Debian testing/unstable | `php8.4` | Unfixed in the Debian tracker at time checked |
| CentOS Stream / corresponding RHEL streams | `php` | Vendor lists affected; no fixed RPM or RHSA published at time checked |

Check the complete installed package release locally. Web response headers normally
show only a value such as `PHP/8.2.35`, so they cannot establish whether a downstream
backport RPM or DEB is installed.

```bash
# Debian: candidate should be at least the fixed package above for your release
dpkg-query -W -f='${Package} ${Version}\n' 'php8.*' 'libapache2-mod-php*' 2>/dev/null
apt-cache policy php8.2 php8.4

# CentOS/RHEL: inspect installed NEVRA and look for both CVEs in the vendor changelog
rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' php php-cli php-fpm
rpm -q --changelog php | grep -E 'CVE-2026-109618|CVE-2026-109619'
dnf updateinfo info --cves CVE-2026-109618,CVE-2026-109619
```

Vendor status can change quickly. Recheck the
[Debian tracker for CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618),
[Debian tracker for CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619),
and the corresponding [Red Hat CVE records](https://access.redhat.com/security/cve/cve-2026-109618)
before using package versions as a compliance gate.

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

