"""
High-Precision Credential Signature Catalog & Combined Secret Scanner (CWE-798).

Maintains 34 curated regular expression signatures covering cloud provider keys,
VCS personal access tokens, SaaS API tokens, asymmetric private key headers,
JWT bearer tokens, AI model provider keys, and database connection URIs.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Tuple

from vault_warden.entropy import (
     calculate_shannon_entropy,
    is_false_positive_token,
    mask_secret,
    scan_line_entropy,
)


@dataclass(frozen=True)
class SignatureRule:
    """Definition of a deterministic or entropy-assisted secret detection rule."""

    rule_id: str
    name: str
    cwe_id: str
    severity: str
    pattern: Pattern[str]
    min_entropy: float = 0.0
    secret_group: int = 0


@dataclass(frozen=True)
class SecretFinding:
    """Unified finding emitted by the signature or Shannon entropy scanner."""

    rule_id: str
    rule_name: str
    cwe_id: str
    severity: str
    file_path: str
    line_number: int
    column: int
    masked_secret: str
    entropy: float
    commit_hash: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "category": "secret",
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "masked_secret": self.masked_secret,
            "entropy": self.entropy,
            "commit_hash": self.commit_hash,
            "description": self.description or f"{self.rule_name} detected ({self.cwe_id})",
        }


def constant_time_Token_match(candidate: str, expected: str) -> bool:
    """
    Compare two sensitive strings using constant-time HMAC digest comparison
    to prevent timing side-channel leakage (CWE-208).
    """
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


# 34 High-Precision Credential Signatures (constructed cleanly without literal dummy keys)
SIGNATURE_CATALOG: Tuple[SignatureRule, ...] = (
    SignatureRule(
        rule_id="VW-SIG-001",
        name="AWS Access Key ID",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        min_entropy=3.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-002",
        name="AWS Secret Access Key",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(
            r"""(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""
        ),
        min_entropy=4.2,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-003",
        name="GitHub Classic Personal Access Token",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        min_entropy=3.8,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-004",
        name="GitHub Fine-Grained Personal Access Token",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b"),
        min_entropy=4.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-005",
        name="GitHub OAuth / App / Refresh Token",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b((?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"),
        min_entropy=3.8,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-006",
        name="GitLab Personal Access Token",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b"),
        min_entropy=3.6,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-007",
        name="Slack Bot / User Token",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
        min_entropy=3.5,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-008",
        name="Slack Incoming Webhook URL",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24})"
        ),
        min_entropy=3.5,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-009",
        name="Stripe Live Secret Key",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b"),
        min_entropy=3.8,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-010",
        name="Google Cloud (GCP) API Key",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        min_entropy=3.8,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-011",
        name="GCP Service Account Private Key ID",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r'"private_key_id"\s*:\s*"([0-9a-f]{40})"'),
        min_entropy=3.2,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-012",
        name="RSA / OpenSSH / EC / PGP Private Key Header",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(
            r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"
        ),
        min_entropy=0.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-013",
        name="JSON Web Token (JWT Bearer)",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,})\b"
        ),
        min_entropy=4.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-014",
        name="PostgreSQL Connection URI with Credentials",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(
            r"(postgres(?:ql)?://[A-Za-z0-9_.\-]+:[^\s\"']{4,}@[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_.\-]+)"
        ),
        min_entropy=3.2,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-015",
        name="MySQL / MariaDB Connection URI with Credentials",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(
            r"(mysql(?:\+pymysql)?://[A-Za-z0-9_.\-]+:[^\s\"']{4,}@[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_.\-]+)"
        ),
        min_entropy=3.2,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-016",
        name="MongoDB Connection URI with Credentials",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(
            r"(mongodb(?:\+srv)?://[A-Za-z0-9_.\-]+:[^\s\"']{4,}@[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_.\-]*)?)"
        ),
        min_entropy=3.2,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-017",
        name="Redis Connection URI with Password",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"(rediss?://:[A-Za-z0-9_\-!#$%^&*()+=]{6,}@[A-Za-z0-9.\-]+:\d+)"),
        min_entropy=3.2,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-018",
        name="OpenAI Standard API Key",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(sk-(?!proj-|admin-|ant-api03-)[A-Za-z0-9_\-]{32,120})\b"),
        min_entropy=4.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-019",
        name="SendGrid API Token",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
        min_entropy=4.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-020",
        name="Twilio API Key SID / Secret",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(SK[0-9a-f]{32})\b"),
        min_entropy=3.4,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-021",
        name="NPM Automation / Publish Access Token",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
        min_entropy=3.8,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-022",
        name="PyPI Upload API Token",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"),
        min_entropy=4.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-023",
        name="HashiCorp Vault Service Token",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(hvs\.[A-Za-z0-9_\-]{24,90})\b"),
        min_entropy=3.8,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-024",
        name="DigitalOcean Personal Access Token",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"),
        min_entropy=3.4,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-025",
        name="Discord Bot / User Token",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b([MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,39})\b"),
        min_entropy=4.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-026",
        name="Telegram Bot Token",
        cwe_id="CWE-798",
        severity="medium",
        pattern=re.compile(r"\b([0-9]{9,10}:[a-zA-Z0-9_\-]{35})\b"),
        min_entropy=0.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-027",
        name="Mailgun Private API Key",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(key-[0-9a-f]{32})\b"),
        min_entropy=3.4,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-028",
        name="Azure Storage Account Shared Key",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(r"AccountKey=([A-Za-z0-9+/]{86}==)"),
        min_entropy=4.3,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-029",
        name="Anthropic Claude API Key",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(sk-ant-api03-[A-Za-z0-9_\-]{80,110})\b"),
        min_entropy=0.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-030",
        name="OpenAI Project Key",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(sk-proj-[A-Za-z0-9_\-]{48,128})\b"),
        min_entropy=0.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-031",
        name="OpenAI Admin Key",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(sk-admin-[A-Za-z0-9_\-]{48,128})\b"),
        min_entropy=0.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-032",
        name="HuggingFace Access Token",
        cwe_id="CWE-798",
        severity="high",
        pattern=re.compile(r"\b(hf_[A-Za-z0-9]{34,40})\b"),
        min_entropy=0.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-033",
        name="Discord Webhook URL",
        cwe_id="CWE-798",
        severity="medium",
        pattern=re.compile(
            r"(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,21}/[A-Za-z0-9_\-]{60,70})"
        ),
        min_entropy=0.0,
        secret_group=1,
    ),
    SignatureRule(
        rule_id="VW-SIG-034",
        name="GCP Service Account Key",
        cwe_id="CWE-798",
        severity="critical",
        pattern=re.compile(
            r"""(?:"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"(?:[^\"]*-----[B]EGIN PRIVATE KEY-----)|"private_key"\s*:\s*"(?:[^\"]*-----[B]EGIN PRIVATE KEY-----)[\s\S]*?"type"\s*:\s*"service_account")"""
        ),
        min_entropy=0.0,
        secret_group=0,
    ),
)


def _is_signature_placeholder(raw_match: str) -> bool:
    """Filter out obvious placeholder examples in matched signatures."""
    lower = raw_match.lower()
    placeholders = (
        "example",
        "your_api_key",
        "your_secret",
        "changeme",
        "placeholder",
        "dummy",
        "00000000",
        "12345678",
        "xxxx",
        "user:password@",
        "user:pass@",
        "postgres:postgres@localhost",
        "root:root@localhost",
    )
    return any(p in lower for p in placeholders)


def scan_line_for_secrets(
    line: str,
    file_path: str = "<memory>",
    line_number: int = 1,
    commit_hash: Optional[str] = None,
    include_entropy: bool = True,
) -> List[SecretFinding]:
    """
    Scan a single line of text against all 28 deterministic signatures first,
    then fall back to character-set calibrated Shannon entropy analysis for
    unrecognized token formats.
    """
    findings: List[SecretFinding] = []
    if not line or len(line) > 8192:
        return findings

    matched_spans: List[Tuple[int, int]] = []

    for rule in SIGNATURE_CATALOG:
        for match in rule.pattern.finditer(line):
            raw_secret = match.group(rule.secret_group)
            if _is_signature_placeholder(raw_secret):
                continue

            entropy = calculate_shannon_entropy(raw_secret)
            if rule.min_entropy > 0.0 and entropy < rule.min_entropy:
                continue

            start_col = match.start(rule.secret_group) + 1
            matched_spans.append((match.start(rule.secret_group), match.end(rule.secret_group)))

            findings.append(
                SecretFinding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    cwe_id=rule.cwe_id,
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=line_number,
                    column=start_col,
                    masked_secret=mask_secret(raw_secret),
                    entropy=entropy,
                    commit_hash=commit_hash,
                    description=f"{rule.name} detected ({rule.cwe_id})",
                )
            )

    if include_entropy:
        entropy_findings = scan_line_entropy(line, line_number=line_number)
        for ef in entropy_findings:
            # Avoid duplicate alerts if already matched by a specific signature on the same column
            if any(start + 1 <= ef.column <= end + 1 for start, end in matched_spans):
                continue
            findings.append(
                SecretFinding(
                    rule_id=ef.rule_id,
                    rule_name=f"Shannon Entropy Anomaly ({ef.charset.upper()})",
                    cwe_id=ef.cwe_id,
                    severity=ef.severity,
                    file_path=file_path,
                    line_number=ef.line_number,
                    column=ef.column,
                    masked_secret=ef.masked_value,
                    entropy=ef.entropy,
                    commit_hash=commit_hash,
                    description=ef.description,
                )
            )

    return findings


def scan_text_for_secrets(
    content: str,
    file_path: str = "<memory>",
    commit_hash: Optional[str] = None,
    include_entropy: bool = True,
) -> List[SecretFinding]:
    """Scan multi-line text content for signature and Shannon entropy secrets."""
    results: List[SecretFinding] = []
    for idx, line in enumerate(content.splitlines(), start=1):
        results.extend(
            scan_line_for_secrets(
                line=line,
                file_path=file_path,
                line_number=idx,
                commit_hash=commit_hash,
                include_entropy=include_entropy,
            )
        )

    # Multi-line detection for GCP Service Account Key spanning multiple JSON lines
    if not any(f.rule_id == "VW-SIG-034" for f in results):
        gcp_rule = next((r for r in SIGNATURE_CATALOG if r.rule_id == "VW-SIG-034"), None)
        if gcp_rule is not None:
            for match in gcp_rule.pattern.finditer(content):
                matched_text = match.group(0)
                line_no = content[: match.start()].count("\n") + 1
                col = match.start() - content[: match.start()].rfind("\n")
                results.append(
                    SecretFinding(
                        rule_id=gcp_rule.rule_id,
                        rule_name=gcp_rule.name,
                        cwe_id=gcp_rule.cwe_id,
                        severity=gcp_rule.severity,
                        file_path=file_path,
                        line_number=line_no,
                        column=max(1, col),
                        masked_secret=mask_secret(matched_text),
                        entropy=calculate_shannon_entropy(matched_text),
                        commit_hash=commit_hash,
                        description=f"{gcp_rule.name} detected ({gcp_rule.cwe_id})",
                    )
                )

    return results
