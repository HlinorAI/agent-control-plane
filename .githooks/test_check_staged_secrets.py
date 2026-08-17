#!/usr/bin/env python3

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_staged_secrets.py")
SPEC = importlib.util.spec_from_file_location("check_staged_secrets", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class StagedSecretGuardTests(unittest.TestCase):
    def test_provider_patterns_are_redacted_to_metadata(self):
        provider_prefix = "ghp_"
        provider_suffix = "123456789012345678901234567890"
        token_key = "tok" + "en:"
        findings = MODULE.scan_added_line("config.yaml", f'{token_key} "{provider_prefix}{provider_suffix}"', 4)
        self.assertTrue({item.kind for item in findings} >= {"credential_assignment", "github_token"})
        self.assertTrue(all(item.fingerprint.startswith("sha256:") for item in findings))

    def test_synthetic_markers_are_allowlisted(self):
        findings = MODULE.scan_added_line("testdata/fixture.yaml", 'token: "ghp_SYNTHETIC-NOT-REAL"', 2)
        self.assertEqual(findings, [])
        provider_prefix = "ghp_"
        provider_suffix = "123456789012345678901234567890"
        token_key = "tok" + "en:"
        findings = MODULE.scan_added_line("config.yaml", f'{token_key} "{provider_prefix}{provider_suffix}" # synthetic fixture', 2)
        self.assertTrue(findings)

    def test_url_unicode_and_split_variants_are_normalized(self):
        encoded_suffix = "%31%32%33%34%35%36%37%38%39%30%31%32%33%34%35%36%37%38%39%30"
        token_key = "tok" + "en:"
        findings = MODULE.scan_added_line("config.yaml", f'{token_key} "ghp_{encoded_suffix}"', 1)
        self.assertTrue(any(item.kind == "credential_assignment" for item in findings))

    def test_entropy_requires_sensitive_context(self):
        self.assertEqual(MODULE.scan_added_line("main.go", 'value = "v3ry-random-but-not-a-secret-value"', 1), [])
        entropy_value = "q7H2mN8pR4xT9vK3zL6cW1sY5dF8gJ2"
        token_key = "tok" + "en = "
        findings = MODULE.scan_added_line("main.go", f'{token_key}"{entropy_value}"', 1)
        self.assertTrue(any(item.kind == "high_entropy_secret_context" for item in findings))

    def test_sensitive_filename_and_example_exception(self):
        self.assertTrue(MODULE.sensitive_filename("secrets/service-account.json"))
        self.assertTrue(MODULE.sensitive_filename(".env.production"))
        self.assertFalse(MODULE.sensitive_filename(".env.example"))


if __name__ == "__main__":
    unittest.main()
