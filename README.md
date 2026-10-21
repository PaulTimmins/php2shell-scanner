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
| Ubuntu 26.10 | `php8.5` | `8.5.9-0ubuntu2.1` |
| Ubuntu 26.04 LTS | `php8.5` | `8.5.4-0ubuntu1.5` |
| Ubuntu 24.04 LTS | `php8.3` | `8.3.6-0ubuntu0.24.04.13` |
| Ubuntu 22.04 LTS | `php8.1` | `8.1.2-1ubuntu2.28` |
| Ubuntu 20.04 LTS (Ubuntu Pro/ESM) | `php7.4` | `7.4.3-4ubuntu2.29+esm5` |
| Ubuntu 18.04 LTS (Ubuntu Pro/ESM) | `php7.2` | `7.2.24-0ubuntu0.18.04.17+esm14` |
| Ubuntu 16.04 LTS (Ubuntu Pro/ESM) | `php7.0` | `7.0.33-0ubuntu0.16.04.16+esm22` |
| Ubuntu 14.04 LTS (Ubuntu Pro/ESM) | `php5` | `5.5.9+dfsg-1ubuntu4.29+esm18` |
| RHEL / CentOS Stream | `php` and module streams | Affected; no fixed RPM or RHSA published at time checked |
| AlmaLinux 8, 9, 10 | `php` and module streams | Patch builds in progress; no released fixed package listed at time checked |
| Rocky Linux 8, 9, 10 | `php` and module streams | No community fixed package advisory located at time checked |
| Oracle Linux | `php` and module streams | No ELSA for either CVE located at time checked |
| Amazon Linux 2 | `php` / PHP 8.2 Extra | Fix pending |
| Amazon Linux 2023 | `php8.2`–`php8.5` | Fix pending; `php8.1` says no fix planned |
| Amazon Linux 2027 Preview | `php8.5` | Fix pending |
| SUSE / openSUSE | `php` | SUSE status pending; no fixed package versions listed at time checked |
| Fedora | `php` | No Fedora advisory or stable fixed package identified at time checked |

Check the complete installed package release locally. Web response headers normally
show only a value such as `PHP/8.2.35`, so they cannot establish whether a downstream
backport RPM or DEB is installed.

```bash
# Debian: candidate should be at least the fixed package above for your release
dpkg-query -W -f='${Package} ${Version}\n' 'php8.*' 'libapache2-mod-php*' 2>/dev/null
apt-cache policy php8.2 php8.4

# Ubuntu: compare the complete revision against the row for your release
ubuntu-security-status
pro security-status 2>/dev/null || true

# CentOS/RHEL: inspect installed NEVRA and look for both CVEs in the vendor changelog
rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' php php-cli php-fpm
rpm -q --changelog php | grep -E 'CVE-2026-109618|CVE-2026-109619'
dnf updateinfo info --cves CVE-2026-109618,CVE-2026-109619

# SUSE/openSUSE
zypper lp --cve CVE-2026-109618
zypper lp --cve CVE-2026-109619
```

Vendor status can change quickly. Recheck the
[Debian tracker for CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618),
[Debian tracker for CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619),
the [Ubuntu security notice](https://ubuntu.com/security/notices/USN-8948-1),
[Red Hat CVE records](https://access.redhat.com/security/cve/cve-2026-109618),
[Amazon Linux advisory](https://explore.alas.aws.amazon.com/CVE-2026-109618.html),
and [SUSE CVE record](https://www.suse.com/security/cve/CVE-2026-109618.html)
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

With no `--scheme` or `--ports`, the scanner uses HTTP on port 80 and HTTPS
on port 443. If `--ports` is supplied, every selected scheme is tried on every
listed port so nonstandard services can still be found.

Scan selected HTTPS targets and produce JSON Lines:

```bash
php2shell-scan https://app.example.test/ 10.20.0.0/24 \
  --scheme https --ports 443,8443 --json
```

For an IP behind name-based virtual hosting, supply the expected hostname:

```bash
php2shell-scan 10.20.30.40 --scheme https --ports 443 \
  --host-header intranet.example.test
```

TLS certificate verification is disabled by default because certificates on raw IP
ranges are commonly self-signed or issued to DNS names. Use `--verify-tls` when
scanning named hosts if certificate validation should be enforced.

When an unverified HTTPS connection fails because of an obsolete signature algorithm
or OpenSSL security level, the scanner automatically retries with legacy TLS
compatibility. Successful downgraded connections are labeled `[legacy TLS]`. This
changes only the scanner's client-side TLS policy; the request remains a single
read-only `HEAD`. `--verify-tls` disables the compatibility retry.

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

