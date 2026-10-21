from __future__ import annotations

import re


# Each expression is deliberately product-specific. Generic technology clues such as
# CSRF fields, routing styles, or a bare session cookie are excluded.
RULES = {
    "WordPress": (r"generator[^>]+wordpress", r"/wp-(?:content|includes)/"),
    "WooCommerce": (r"/wp-content/plugins/woocommerce/", r"\bwoocommerce_(?:cart_hash|items_in_cart)="),
    "Drupal": (r"generator[^>]+drupal", r"\bdrupalSettings\b", r"/sites/default/files/"),
    "Joomla": (r"generator[^>]+joomla", r"/media/system/js/", r"[?&]option=com_[a-z0-9_]+"),
    "Laravel": (r"\blaravel_session=", r"x-powered-by:\s*laravel\b"),
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


def is_php_application(application: str) -> bool:
    return application not in NON_PHP_APPLICATIONS


def is_unsupported_php_application(application: str) -> bool:
    return application in UNSUPPORTED_PHP_APPLICATIONS


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
