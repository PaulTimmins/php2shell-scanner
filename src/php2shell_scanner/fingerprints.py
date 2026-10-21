from __future__ import annotations

import re


# Each expression is deliberately product-specific. Generic technology clues such as
# CSRF fields, routing styles, or a bare session cookie are excluded.
RULES = {
    "WordPress": (r"generator[^>]+wordpress", r"/wp-(?:content|includes)/"),
    "WooCommerce": (r"/wp-content/plugins/woocommerce/", r"\bwoocommerce_(?:cart_hash|items_in_cart)="),
    "Drupal": (r"generator[^>]+drupal", r"\bdrupalSettings\b", r"/sites/default/files/"),
    "Joomla": (r"generator[^>]+joomla", r"/media/system/js/", r"[?&]option=com_[a-z0-9_]+"),
    "Laravel": (r"\blaravel_session=", r"x-powered-by:\s*laravel\b", r"\blaravel(?: framework)? v[0-9]+"),
    "Symfony": (r"x-debug-token(?:-link)?:", r"/(?:_wdt|_profiler)/"),
    "CodeIgniter": (r"\bci_session=", r"x-powered-by:\s*codeigniter\b"),
    "CakePHP": (r"\bcakephp=", r"x-powered-by:\s*cakephp\b"),
    "Yii": (r"\byii_csrf_token=", r"x-powered-by:\s*yii framework\b"),
    "Magento": (r"x-magento-[a-z-]+:", r"\bmage-cache-storage\b", r"\bMagento_Ui\b"),
    "PrestaShop": (r"\bprestashop-[a-z0-9]+=", r"generator[^>]+prestashop"),
    "TYPO3": (r"generator[^>]+typo3", r"/typo3temp/", r"/typo3conf/"),
    "MediaWiki": (r"generator[^>]+mediawiki", r"\bmw\.config\.(?:set|get)\b", r"/w/load\.php"),
    "Moodle": (r"\bmoodlesession=", r"/theme/yui_combo\.php", r"\bM\.cfg\b"),
    "Nextcloud": (r"\bnc_samesitecookie(?:lax|strict)=", r"generator[^>]+nextcloud"),
    "phpMyAdmin": (r"\bphpmyadmin=", r"\bid=[\"']pma_navigation[\"']", r"\bphpmyadmin\b"),
    "Roundcube": (r"\broundcube_sessid=", r"\broundcube webmail\b"),
    "SuiteCRM": (r"\bsuitecrm\b", r"/themes/suitep/"),
    "SugarCRM": (r"\bsugar_user_theme=", r"\bsugarcrm\b"),
    "CiviCRM": (r"/civicrm/", r"\bCRM\.\$\b"),
    "Mautic": (r"generator[^>]+mautic", r"/media/js/mautic"),
    "Craft CMS": (r"\bcraft_csrf_token=", r"generator[^>]+craft cms"),
    # Firewalls, PBX systems, storage appliances, and monitoring consoles.
    "OPNsense": (r"\bopnsense\b", r"/ui/themes/[a-z0-9_-]+/"),
    "pfSense": (r"\bpfsense\b", r"/themes/pfsense/"),
    "OpenMediaVault": (r"\bopenmediavault\b", r"\bomv\.workspace\b"),
    "FreePBX": (r"\bfreepbx\b", r"/admin/assets/"),
    "VitalPBX": (r"\bvitalpbx\b", r"\bvital pbx\b"),
    "Incredible PBX": (r"\bincredible pbx\b",),
    "Elastix 2/4": (r"\belastix (?:2|4)(?:\.\d+)*\b", r"/themes/.*elastix"),
    "FusionPBX": (r"\bfusionpbx\b", r"/themes/default/.*fusionpbx"),
    "Issabel": (r"\bissabel(?:pbx)?\b", r"/themes/.*issabel"),
    "ZoneMinder": (r"\bzoneminder\b", r"[?&]view=(?:console|montage|watch)\b"),
    "LibreNMS": (r"\blibrenms\b", r"\blnms\b"),
    "Cacti": (r"\blogin to cacti\b", r"\bcacti(?:version)?\b"),
    "Zabbix": (r"\bzabbix\b", r"\bzbx_session="),
    "Nagios XI": (r"\bnagios xi\b", r"/nagiosxi/", r"\bnagiosxi="),
    "Icinga Web 2": (r"\bicinga web 2\b", r"/icingaweb2/", r"\bicingaweb2="),
    "Observium": (r"\bobservium\b", r"/observium/"),
    "Pandora FMS": (r"\bpandora fms\b", r"/pandora_console/"),
    "PBXware": (r"\bpbxware\b",),
    "phpVirtualBox": (r"\bphpvirtualbox\b", r"\bphpvirtualbox(?:version)?="),
    "Virtualizor": (r"\bvirtualizor\b", r"/virtualizor/"),
    # Retired PHP appliance identities. Seeing these brands is itself a legacy signal.
    "m0n0wall": (r"\bm0n0wall\b",),
    "NAS4Free": (r"\bnas4free\b",),
    "FreeNAS 7": (r"\bfreenas 7(?:\.\d+)*\b",),
    "trixbox CE": (r"\btrixbox ce\b", r"\btrixbox platform\b"),
    "AsteriskNOW": (r"\basterisknow\b", r"\basterisk now\b"),
    # Inventory-only products whose primary management interfaces do not prove PHP.
    "Nagios Core": (r"\bnagios core\b", r"/nagios/cgi-bin/", r"/cgi-bin/nagios[0-9]?/"),
    "3CX": (r"\b3cx (?:phone system|web client|management console)\b", r"/webclient/#/"),
    "TrueNAS": (r"\btruenas\b", r"\bixsystems\b.*\btruenas\b"),
    "Portainer": (r"\bportainer(?:\.io| community edition| business edition)?\b",),
    "Proxmox VE": (r"\bproxmox virtual environment\b", r"\bproxmox ve\b", r"\bpve-manager/"),
    "oVirt": (r"\bovirt engine\b", r"/ovirt-engine/"),
    "Cockpit": (r"\bcockpit web console\b", r"/cockpit/(?:@[^/]+/)?system/"),
    "VMware vSphere": (r"\bvmware vsphere\b", r"/ui/app/.*vsphere"),
    "Xen Orchestra": (r"\bxen orchestra\b", r"\bxoa(?: login)?\b"),
}

NON_PHP_APPLICATIONS = {
    "3CX",
    "Cockpit",
    "Nagios Core",
    "oVirt",
    "Portainer",
    "Proxmox VE",
    "TrueNAS",
    "VMware vSphere",
    "Xen Orchestra",
}

UNSUPPORTED_PHP_APPLICATIONS = {
    "AsteriskNOW",
    "Elastix 2/4",
    "FreeNAS 7",
    "NAS4Free",
    "m0n0wall",
    "trixbox CE",
}

# Conservative support or PHP 8 release floors. These rules only run when an
# exact application version is present in the response.
APPLICATION_VERSION_FLOORS = {
    "Cacti": (1, 2, 20),
    "FreePBX": (16,),
    "Icinga Web 2": (2, 9),
    "Laravel": (6,),
    "LibreNMS": (21, 1),
    "Mautic": (4, 4),
    "Nextcloud": (21,),
    "OpenMediaVault": (8,),
    "PBXware": (7,),
    "Pandora FMS": (760,),
    "VitalPBX": (4,),
    "WordPress": (5, 6),
    "Zabbix": (6,),
    "phpVirtualBox": (7, 1),
    # The 5.x line is the conservative boundary. Some late 4.x builds can be
    # made to work, but upstream did not document the whole line for PHP 8.
    "phpMyAdmin": (5,),
}

VERSION_PATTERNS = {
    "Cacti": (r"\bcacti(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
    "FreePBX": (r"\bfreepbx(?:\s+distro)?(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){0,3})\b",),
    "Icinga Web 2": (r"\bicinga web 2(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
    "Laravel": (r"\blaravel(?:\s+framework)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){0,3})\b",),
    "LibreNMS": (r"\blibrenms(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
    "Mautic": (r"\bmautic(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
    "Nextcloud": (r"generator[^>]+nextcloud(?:\s+|/)([0-9]+(?:\.[0-9]+){0,3})\b",),
    "OpenMediaVault": (r"\bopenmediavault(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){0,3})\b",),
    "PBXware": (r"\bpbxware(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){0,3})\b",),
    "Pandora FMS": (r"\bpandora fms(?:\s+(?:ng|version))?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){0,3})\b",),
    "SuiteCRM": (r"\bsuitecrm(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
    "VitalPBX": (r"\bvitalpbx(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){0,3})\b",),
    "WordPress": (r"generator[^>]+wordpress(?:\s+|/)([0-9]+(?:\.[0-9]+){0,3})\b",),
    "Zabbix": (r"\bzabbix(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
    "phpMyAdmin": (r"\bphpmyadmin(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
    "phpVirtualBox": (r"\bphpvirtualbox(?:\s+version)?\s*(?:v|version\s*)?([0-9]+(?:\.[0-9]+){1,3})\b",),
}


def is_php_application(application: str) -> bool:
    return application not in NON_PHP_APPLICATIONS


def is_unsupported_php_application(application: str) -> bool:
    return application in UNSUPPORTED_PHP_APPLICATIONS


def fingerprint_application_versions(
    applications: list[str], headers: list[tuple[str, str]], body: bytes = b"",
    content_type: str | None = None,
) -> dict[str, str]:
    """Extract exact, product-qualified versions from an ordinary response."""
    header_text = "\n".join(f"{name}: {value}" for name, value in headers)
    body_text = body.decode("utf-8", errors="replace") if content_type and "html" in content_type.lower() else ""
    searchable = f"{header_text}\n{body_text}"
    found = {}
    for application in applications:
        for pattern in VERSION_PATTERNS.get(application, ()):
            match = re.search(pattern, searchable, re.IGNORECASE)
            if match:
                found[application] = match.group(1)
                break
    return found


def legacy_application_version(application_versions: dict[str, str]) -> tuple[str, str, str] | None:
    """Return the first app version below its defensible support/runtime floor."""
    for application in sorted(application_versions):
        minimum = APPLICATION_VERSION_FLOORS.get(application)
        if not minimum:
            if application == "SuiteCRM":
                version = application_versions[application]
                parts = tuple(int(value) for value in re.findall(r"\d+", version))
                unsupported = (
                    not parts
                    or parts[0] < 7
                    or (parts[0] == 7 and parts < (7, 15))
                    or (parts[0] == 8 and parts < (8, 10))
                )
                if unsupported:
                    return application, version, "7.15 ESR or 8.10"
            continue
        version = application_versions[application]
        parts = tuple(int(value) for value in re.findall(r"\d+", version))
        width = max(len(parts), len(minimum))
        if parts + (0,) * (width - len(parts)) < minimum + (0,) * (width - len(minimum)):
            boundary = ".".join(str(value) for value in minimum)
            return application, version, boundary
    return None


def fingerprint_applications(
    headers: list[tuple[str, str]], body: bytes = b"", content_type: str | None = None
) -> dict[str, list[str]]:
    header_text = "\n".join(f"{name}: {value}" for name, value in headers)
    body_text = body.decode("utf-8", errors="replace") if content_type and "html" in content_type.lower() else ""
    searchable = f"{header_text}\n{body_text}"
    found: dict[str, list[str]] = {}
    for application, patterns in RULES.items():
        evidence = []
        for pattern in patterns:
            match = re.search(pattern, searchable, re.IGNORECASE)
            if match:
                value = match.group(0).replace("\n", " ")[:160]
                # Do not retain cookie values after the equals sign.
                if "=" in value and re.search(r"(?i)(?:session|csrf|phpmyadmin|prestashop|woocommerce)", value):
                    value = value.split("=", 1)[0] + "=<redacted>"
                evidence.append(value)
        if evidence:
            found[application] = evidence
    return found
