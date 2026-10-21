import unittest
import ssl

from php2shell_scanner.scanner import _tls_context, expand_targets
from php2shell_scanner.cli import parser
from php2shell_scanner.versions import assess, extract_version, php_header_evidence


class VersionTests(unittest.TestCase):
    def test_tls_verification_is_opt_in(self):
        args = parser().parse_args(["192.0.2.1"])
        self.assertFalse(args.verify_tls)

    def test_legacy_tls_context_is_unverified(self):
        context = _tls_context(False, legacy=True)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_assessment_boundaries(self):
        cases = [
            ("8.2.34", "outdated"), ("8.2.35", "patched"),
            ("8.3.35", "outdated"), ("8.3.36", "patched"),
            ("8.4.26", "outdated"), ("8.4.27", "patched"),
            ("8.5.11", "outdated"), ("8.5.12", "patched"),
            ("8.1.34", "outdated"),
        ]
        for version, status in cases:
            with self.subTest(version=version):
                self.assertEqual(assess(version).status, status)

    def test_extracts_header_version(self):
        self.assertEqual(extract_version(["nginx", "PHP/8.4.26"]), "8.4.26")

    def test_identifies_versionless_php_header(self):
        self.assertEqual(php_header_evidence([("X-Powered-By", "PHP")]), ["X-Powered-By: PHP"])

    def test_identifies_php_session_cookie_without_disclosing_value(self):
        self.assertEqual(
            php_header_evidence([("Set-Cookie", "PHPSESSID=secret; path=/; HttpOnly")]),
            ["Set-Cookie: PHPSESSID=<redacted>"],
        )

    def test_does_not_guess_php_from_generic_headers(self):
        self.assertEqual(php_header_evidence([("Server", "nginx"), ("Set-Cookie", "session=abc")]), [])

    def test_expands_cidr(self):
        self.assertEqual(expand_targets(["192.0.2.0/30"], [("http", 80)], 10), [
            "http://192.0.2.1:80/", "http://192.0.2.2:80/"
        ])

    def test_endpoint_pairs_do_not_cross_product(self):
        self.assertEqual(expand_targets(
            ["192.0.2.1"], [("http", 80), ("https", 443)], 10
        ), ["http://192.0.2.1:80/", "https://192.0.2.1:443/"])

    def test_expansion_limit(self):
        with self.assertRaises(ValueError):
            expand_targets(["10.0.0.0/8"], [("http", 80)], 256)


if __name__ == "__main__":
    unittest.main()

