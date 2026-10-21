import unittest

from php2shell_scanner.fingerprints import fingerprint_applications, is_php_application


class FingerprintTests(unittest.TestCase):
    def assert_app(self, application, html="", headers=None):
        found = fingerprint_applications(headers or [], html.encode(), "text/html")
        self.assertIn(application, found)

    def test_cms_and_app_html_markers(self):
        cases = {
            "WordPress": '<link href="/wp-content/themes/site/style.css">',
            "WooCommerce": '<script src="/wp-content/plugins/woocommerce/app.js">',
            "Drupal": "<script>window.drupalSettings = {};</script>",
            "Joomla": '<script src="/media/system/js/core.js">',
            "Magento": '<script>var section = "mage-cache-storage";</script>',
            "PrestaShop": '<meta name="generator" content="PrestaShop">',
            "TYPO3": '<meta name="generator" content="TYPO3 CMS">',
            "MediaWiki": '<meta name="generator" content="MediaWiki 1.45">',
            "Moodle": '<script src="/theme/yui_combo.php?rollup/3.17"></script>',
            "Nextcloud": '<meta name="generator" content="Nextcloud">',
            "phpMyAdmin": '<nav id="pma_navigation"></nav>',
            "Roundcube": '<title>Roundcube Webmail</title>',
            "SuiteCRM": '<link href="/themes/SuiteP/css/style.css">',
            "SugarCRM": '<title>SugarCRM</title>',
            "CiviCRM": '<a href="/civicrm/contact/view">Contact</a>',
            "Mautic": '<script src="/media/js/mautic-form.js"></script>',
            "Craft CMS": '<meta name="generator" content="Craft CMS">',
        }
        for application, html in cases.items():
            with self.subTest(application=application):
                self.assert_app(application, html)

    def test_framework_header_and_cookie_markers(self):
        cases = {
            "Laravel": [("Set-Cookie", "laravel_session=secret; HttpOnly")],
            "Symfony": [("X-Debug-Token", "abc123")],
            "CodeIgniter": [("Set-Cookie", "ci_session=secret")],
            "CakePHP": [("Set-Cookie", "CAKEPHP=secret")],
            "Yii": [("X-Powered-By", "Yii Framework")],
        }
        for application, headers in cases.items():
            with self.subTest(application=application):
                self.assert_app(application, headers=headers)

    def test_php_appliance_markers(self):
        cases = {
            "OPNsense": "<title>OPNsense</title>",
            "pfSense": '<input name="__csrf_magic" value="csrfMagicToken"> pfSense',
            "OpenMediaVault": "<title>openmediavault Workbench</title>",
            "FreePBX": "<title>FreePBX Administration</title>",
            "VitalPBX": "<title>VitalPBX Administration</title>",
            "Incredible PBX": "<title>Incredible PBX</title>",
            "Elastix": "<title>Elastix</title>",
            "FusionPBX": "<title>FusionPBX</title>",
            "Issabel": "<title>IssabelPBX</title>",
            "ZoneMinder": "<title>ZoneMinder Console</title>",
            "LibreNMS": "<title>LibreNMS</title>",
            "Cacti": "<title>Login to Cacti</title>",
            "Zabbix": "<title>Zabbix</title>",
            "Nagios XI": '<link href="/nagiosxi/includes/css/base.css">',
            "Icinga Web 2": "<title>Icinga Web 2</title>",
            "Observium": "<title>Observium</title>",
            "Pandora FMS": '<form action="/pandora_console/index.php">',
            "PBXware": "<title>PBXware by Bicom Systems</title>",
            "phpVirtualBox": "<title>phpVirtualBox</title>",
            "Virtualizor": "<title>Virtualizor Admin Panel</title>",
        }
        for application, html in cases.items():
            with self.subTest(application=application):
                self.assert_app(application, html)
                self.assertTrue(is_php_application(application))

    def test_non_php_products_are_inventory_only(self):
        cases = {
            "TrueNAS": "<title>TrueNAS</title>",
            "Nagios Core": "<title>Nagios Core</title>",
            "3CX": "<title>3CX Phone System Management Console</title>",
            "Portainer": "<title>Portainer.io</title>",
            "Proxmox VE": "<title>Proxmox Virtual Environment</title>",
            "oVirt": '<script src="/ovirt-engine/webadmin/app.js"></script>',
            "Cockpit": "<title>Cockpit Web Console</title>",
            "VMware vSphere": "<title>VMware vSphere</title>",
            "Xen Orchestra": "<title>Xen Orchestra</title>",
        }
        for application, html in cases.items():
            with self.subTest(application=application):
                self.assert_app(application, html)
                self.assertFalse(is_php_application(application))

    def test_cookie_evidence_is_redacted(self):
        found = fingerprint_applications([("Set-Cookie", "laravel_session=topsecret")])
        self.assertNotIn("topsecret", repr(found))

    def test_generic_page_does_not_match(self):
        found = fingerprint_applications(
            [("Server", "nginx"), ("Set-Cookie", "session=abc")],
            b'<form action="/login"><input name="csrf"></form>',
            "text/html",
        )
        self.assertEqual(found, {})

    def test_cacti_csrf_token_does_not_match_pfsense(self):
        found = fingerprint_applications(
            [],
            b'<title>Login to Cacti</title><input name="__csrf_magic" value="csrfMagicToken">',
            "text/html",
        )
        self.assertIn("Cacti", found)
        self.assertNotIn("pfSense", found)


if __name__ == "__main__":
    unittest.main()
