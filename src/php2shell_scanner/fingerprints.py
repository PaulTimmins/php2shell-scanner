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
}


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
