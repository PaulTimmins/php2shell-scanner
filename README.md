# php2shell-scanner

A non-invasive scanner for exposed, outdated PHP versions affected by PHP2Shell
(CVE-2026-109618 and CVE-2026-109619). It uses ordinary `HEAD` requests and, when
headers are inconclusive, a capped read of the root HTML. It sends no exploit
payload, multipart upload, large allocation, session mutation, or file write.

## What a result means

- `OUTDATED`: the server exposed an exact PHP version below its upstream fixed release.
- `OUTDATED_PLATFORM`: a passive platform signature proves the appliance branch cannot
  receive the required PHP fix. This currently applies to OPNsense releases before 25.7.
- `PATCHED`: the exposed version is at or above the upstream fixed release.
- `PHP_UNKNOWN`: PHP is positively identified by a header or `PHPSESSID` cookie, but
  its exact version is hidden. Check the installed package locally.
- `UNKNOWN`: no exact version or positive PHP header evidence was exposed. PHP may
  still be present behind the requested endpoint or virtual host.
- `UNREACHABLE`: the connection or TLS handshake failed.

## Detection signals

The scanner keeps exact-version findings separate from evidence that identifies PHP
without revealing its version.

| Signal | Result | Evidence recorded |
|---|---|---|
| `Server` or `X-Powered-By` contains `PHP/x.y.z` | Version assessment | Header value and parsed version |
| `Server` or `X-Powered-By` contains `PHP` without a version | `PHP_UNKNOWN` | Header name and value |
| Response sets the standard `PHPSESSID` cookie | `PHP_UNKNOWN` | Cookie name; its value is redacted |
| Response includes an `X-PHP-*` header | `PHP_UNKNOWN` | Header name and value |
| Root HTML has a relative `.php` `href`, `src`, or form `action` | `PHP_UNKNOWN` | First matching relative URL |
| `/index.php` returns one of the header or cookie signals above | Corresponding result | Labeled `path=/index.php` |
| OPNsense serves its retired Pick-a-Color 1.2.3 CSS asset | `OUTDATED_PLATFORM` | OPNsense web tree predates 25.7 |

### Application fingerprints

The capped root response is also checked for product-specific headers, cookies, and
HTML markers. Current fingerprints cover:

- CMS and publishing: WordPress, Drupal, Joomla, TYPO3, MediaWiki, Moodle, and Craft CMS.
- CRM and marketing: SuiteCRM, SugarCRM, CiviCRM, and Mautic.
- Commerce: WooCommerce, Magento, and PrestaShop.
- Frameworks: Laravel, Symfony, CodeIgniter, CakePHP, and Yii.
- Applications: Nextcloud, phpMyAdmin, and Roundcube.
- PHP appliances and PBX consoles: OPNsense, pfSense, OpenMediaVault, FreePBX,
  VitalPBX, Incredible PBX, Elastix, FusionPBX, Issabel, and PBXware.
- PHP monitoring consoles: Zabbix, Nagios XI, Icinga Web 2, ZoneMinder,
  LibreNMS, Cacti, Observium, and Pandora FMS.
- PHP virtualization consoles: phpVirtualBox and Virtualizor.
- Retired PHP appliance lines: m0n0wall, NAS4Free, FreeNAS 7, Elastix 2/4,
  trixbox CE, and AsteriskNOW.

Detected names appear as `[apps=...]` in streamed text results, under `applications`
and `application_evidence` in JSON, and in the final application summary. A recognized
PHP application is positive evidence of a PHP stack but does not reveal its PHP
version, so it produces `PHP_UNKNOWN` unless an exact version signal is also present.

When ordinary response HTML exposes an exact product version, the scanner checks
conservative upstream PHP 8 compatibility boundaries. These versions produce
`OUTDATED_PLATFORM`: WordPress before 5.6, Nextcloud before 21, Zabbix before 6.0,
Cacti before 1.2.20, LibreNMS before 21.1, Laravel before 6, and phpMyAdmin before 5.
The finding records the observed product version and its boundary. It means the
application release predates its project's PHP 8 compatible line; it does not claim
to have measured the installed PHP runtime.

The version must appear in product-qualified text such as a generator meta tag,
title, footer, or framework error page. Branding without an exact version remains
`PHP_UNKNOWN`. pfSense, FreePBX, PBXware, and similar login pages often hide their
release, so the scanner inventories those products without guessing from copyright
years, asset dates, or other weak proxies.

For an OPNsense root-page match, the scanner makes one additional capped `GET` for
`/ui/css/pick-a-color-1.2.3.min.css`. OPNsense 25.1 shipped this file and 25.7 removed
it while replacing the JavaScript color picker with native color inputs. The response
must contain two library-specific CSS selectors, so a generic login-page response at
that path does not match. A confirmed legacy asset produces `OUTDATED_PLATFORM` and
exit status 1. Its absence does not prove 25.7 or newer, and 25.7 or newer still needs
an exact PHP package check before it can be considered fixed. Copyright years and the
login page's timestamp-derived cache tokens are deliberately ignored.

The retired appliance names above are also one-way red flags. They identify PHP
management platforms whose original release lines have ended or moved to successor
products. A match produces `OUTDATED_PLATFORM`; current successor branding such as
XigmaNAS, Issabel, FreePBX, or pfSense remains a normal PHP fingerprint. A bare
`Elastix` string is insufficient because later Elastix products used a different
stack; the scanner requires an Elastix 2/4 version marker or its legacy theme path.

TrueNAS, Nagios Core, 3CX, Portainer, Proxmox VE, oVirt, Cockpit, VMware vSphere,
and Xen Orchestra are also fingerprinted for inventory, but they do not count as
PHP evidence. The current TrueNAS WebUI is Angular and nginx proxies its
API/UI traffic to the middleware service. Nagios Core's classic interface uses CGI,
while Nagios XI adds a PHP frontend. 3CX's web client is Angular and its server has
used .NET Core; a 3CX match does not demonstrate a PHP runtime. These matches stay
`UNKNOWN` unless an independent PHP signal is present. Products can bundle optional
apps with separate PHP runtimes, so identification does not establish the version or
patch state.

Implementation references include the official
[OPNsense core](https://github.com/opnsense/core),
[m0n0wall historical documentation](https://doc.m0n0.ch/handbook-single/),
[OPNsense's m0n0wall project history](https://docs.opnsense.org/relations/m0n0wall.html),
[XigmaNAS project history](https://www.xigmanas.com/wiki/doku.php?id=index),
[pfSense source](https://github.com/pfsense/pfsense),
[FreePBX framework](https://github.com/FreePBX/framework),
[WordPress PHP compatibility](https://make.wordpress.org/core/handbook/references/php-compatibility-and-wordpress-versions/),
[Nextcloud 21 PHP 8 release notes](https://docs.nextcloud.com/server/stable/developer_manual/release_notes/previous/upgrade_to_21.html),
[Zabbix 5.4 requirements](https://www.zabbix.com/documentation/5.4/en/manual/installation/requirements),
[Cacti PHP 8 milestone](https://github.com/Cacti/cacti/issues/4551),
[LibreNMS PHP 8 compatibility change](https://github.com/librenms/librenms/commit/39217d003ffcc730fa7186255de7e553f4ac2cdf),
[Laravel PHP 8 support](https://laravel.com/blog/laravel-php-8-support),
[AsteriskNOW succession documentation](https://docs.asterisk.org/About-the-Project/Sangoma-and-Digium-Join-Together-FAQ/),
[VitalPBX projects](https://github.com/VitalPBX),
[IssabelPBX source](https://github.com/IssabelFoundation/issabelPBX),
[FusionPBX source](https://github.com/fusionpbx/fusionpbx),
[OpenMediaVault prerequisites](https://github.com/openmediavault/openmediavault-docs/blob/master/prerequisites.rst),
[ZoneMinder Web UI documentation](https://github.com/ZoneMinder/zoneminder/blob/master/docs/web_ui_api.rst),
[LibreNMS source](https://github.com/librenms/librenms),
[Cacti source](https://github.com/Cacti/cacti),
[Zabbix frontend documentation](https://www.zabbix.com/documentation/current/en/manual/installation/frontend),
[Nagios training documentation](https://assets.nagios.com/training/selfpaced/materials/NCP_Core_Prep_Guide.pdf),
[Icinga Web documentation](https://icinga.com/docs/icinga-web/latest/),
[Observium requirements](https://docs.observium.org/software_requirements/),
[Pandora FMS requirements](https://www.pandorafms.com/manual/!current/en/documentation/pandorafms/installation/01_installing),
[PBXware release documentation](https://www.bicomsystems.com/files/public/Changelog_PBXware_8.0.0.1.pdf),
[phpVirtualBox source and requirements](https://github.com/phpvirtualbox/phpvirtualbox),
[Virtualizor installation documentation](https://www.virtualizor.com/docs/install/install-kvm/),
[Portainer source](https://github.com/portainer/portainer),
[oVirt Engine source](https://github.com/oVirt/ovirt-engine),
[Cockpit source](https://github.com/cockpit-project/cockpit),
[3CX Web Client documentation](https://www.3cx.com/blog/releases/web-based-voip-client/), and the
[TrueNAS WebUI](https://github.com/truenas/webui).

The default probe order is:

1. Send `HEAD /` and inspect headers.
2. Send `GET /`, read at most 64 KiB, and inspect product markers and HTML URL
   attributes. External URLs, fragments, JavaScript URLs, and non-HTML bodies are
   ignored for HTML fingerprinting.
3. If OPNsense is identified, check the capped legacy static asset described above.
4. If no PHP signal is present, send `HEAD /index.php` and inspect its headers.

An HTTP response from a path ending in `.php` does not by itself prove PHP is in use;
many frameworks route arbitrary paths. The fallback requires a PHP-specific header,
cookie, or a relative PHP endpoint in returned HTML.

To reproduce the signal checks independently:

```bash
# Header, version, and PHPSESSID signals
curl -kIsS https://host.example/ | sed -n '/^Server:/Ip;/^X-Powered-By:/Ip;/^X-PHP-/Ip;/^Set-Cookie: PHPSESSID=/Ip'

# Relative PHP URLs in the first 64 KiB of HTML
curl -ksS --range 0-65535 https://host.example/ \
  | grep -Eio "(href|src|action)=['\"][^'\"]+\.php([^'\"]*)?['\"]" | head

# Fallback path
curl -kIsS https://host.example/index.php

# For a server requiring obsolete TLS compatibility (OpenSSL builds)
curl -kIsS --ciphers 'DEFAULT:@SECLEVEL=0' https://host.example/
```

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

The default path check starts at `/`. If that does not expose an exact PHP
version, the scanner reads at most 64 KiB of the root HTML and looks for relative
`.php` links, script sources, or form actions. That positive application signal
produces `PHP_UNKNOWN` without probing another path. Otherwise it sends a `HEAD`
request to `/index.php`; a finding there is labeled `path=/index.php`. Supplying
`--path` disables both fallbacks and checks only the requested path.

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
changes only the scanner's client-side TLS policy; application probes remain
read-only HTTP requests. `--verify-tls` disables the compatibility retry.

The command exits `1` when any confirmed outdated version is found, `2` for invalid
arguments, and `0` otherwise. `UNKNOWN` does not mean safe.

After streaming individual results, text mode prints a report grouped into outdated
PHP, PHP with hidden versions, patched PHP, legacy TLS, unknown web responders, and
unreachable error types. Each host section is capped at 25 entries by default; change
that with `--report-limit`. JSON Lines mode emits only per-target JSON objects so it
remains safe to pipe into another program.

Only scan address space you own or are authorized to assess. Keep concurrency modest
on production networks (`--workers 5`) and select only ports you expect to host HTTP.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Sources: [PHP security release](https://www.php.net/),
[PHP 8 changelog](https://www.php.net/ChangeLog-8.php), and
[PHP unsupported branches](https://www.php.net/eol.php).

## License

BSD 3-Clause. See [LICENSE](LICENSE).

