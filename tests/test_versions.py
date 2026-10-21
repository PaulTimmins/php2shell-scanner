import unittest
import ssl
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from php2shell_scanner.scanner import _tls_context, expand_targets
from php2shell_scanner.scanner import Result
from php2shell_scanner.cli import _print_report, parser
from php2shell_scanner.versions import assess, extract_version, php_header_evidence, relative_php_url_evidence


class VersionTests(unittest.TestCase):
    def test_tls_verification_is_opt_in(self):
        args = parser().parse_args(["192.0.2.1"])
        self.assertFalse(args.verify_tls)
        self.assertIsNone(args.path)

    def test_report_groups_actionable_findings(self):
        output = StringIO()
        results = [
            Result("https://old.test", "outdated", php_version="8.4.26"),
            Result("https://hidden.test", "php_unknown", evidence="X-Powered-By: PHP", tls_mode="legacy"),
            Result("http://down.test", "unreachable", error="TimeoutError: timed out"),
        ]
        with redirect_stdout(output):
            _print_report(results, 25)
        report = output.getvalue()
        self.assertIn("Outdated PHP (1)", report)
        self.assertIn("PHP version hidden (1)", report)
        self.assertIn("Legacy TLS (1)", report)
        self.assertIn("TimeoutError=1", report)

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

    def test_identifies_relative_php_url_in_html(self):
        body = b'<form action="login.php"><script src="/assets/app.js"></script></form>'
        self.assertEqual(
            relative_php_url_evidence(body, "text/html; charset=utf-8"),
            "relative PHP URL in HTML: login.php",
        )

    def test_ignores_external_php_url_and_non_html(self):
        body = b'<a href="https://other.test/login.php">login</a>'
        self.assertIsNone(relative_php_url_evidence(body, "text/html"))
        self.assertIsNone(relative_php_url_evidence(b"download.php", "text/plain"))

    def test_index_php_fallback_can_identify_php(self):
        from php2shell_scanner.scanner import scan

        class Reply:
            status = 200

            def __init__(self, path):
                self.path = path

            def read(self, _size):
                return b""

            def getheaders(self):
                return [("X-Powered-By", "PHP")] if self.path == "/index.php" else [("Server", "nginx")]

        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.path = "/"

            def request(self, _method, path, headers=None):
                self.path = path

            def getresponse(self):
                return Reply(self.path)

            def close(self):
                pass

        with patch("php2shell_scanner.scanner.http.client.HTTPConnection", Connection):
            result = scan("http://192.0.2.1", 1, "/", None, False, fallback_index=True)
        self.assertEqual(result.status, "php_unknown")
        self.assertEqual(result.probe_path, "/index.php")

    def test_opnsense_legacy_asset_marks_pre_25_7_platform(self):
        from php2shell_scanner.scanner import scan

        class Reply:
            status = 200

            def __init__(self, path):
                self.path = path

            def read(self, _size):
                if self.path.endswith("pick-a-color-1.2.3.min.css"):
                    return b".pick-a-color-markup{} .hex-pound{}"
                return b"<title>Login | OPNsense</title>"

            def getheaders(self):
                content_type = "text/css" if self.path.endswith(".css") else "text/html"
                return [("Content-Type", content_type)]

        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.path = "/"

            def request(self, _method, path, headers=None):
                self.path = path

            def getresponse(self):
                return Reply(self.path)

            def close(self):
                pass

        with patch("php2shell_scanner.scanner.http.client.HTTPConnection", Connection):
            result = scan("http://192.0.2.1", 1, "/", None, False, fallback_index=True)
        self.assertEqual(result.status, "outdated_platform")
        self.assertIn("older than 25.7", result.reason)

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

