"""
Shannon Entropy & Character-Set Calibrated Token Analysis (CWE-798).

Implements information-theoretic entropy calculation:
    H(X) = - sum( P(x_i) * log2(P(x_i)) )

Calibrates detection thresholds across Hexadecimal, Base58, and Base64 alphabets
while suppressing common developer false positives (UUIDv4, lockfile SRI digests,
placeholder values, and CSS/file paths).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

HEX_CHARS = frozenset("0123456789abcdefABCDEF")
BASE58_CHARS = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-."
)

# Thresholds calibrated per character set (bits per character)
HEX_ENTROPY_THRESHOLD = 3.20
BASE58_ENTROPY_THRESHOLD = 4.25
BASE64_ENTROPY_THRESHOLD = 4.50

# Regex for extracting candidate high-entropy string tokens
TOKEN_CANDIDATE_RE = re.compile(
    r"""(?x)
    (?:
        # Quoted string literals or assignment values
        (?<=["'=:\s])
        ([A-Za-z0-9+/=_\-]{20,128})
        (?=["'\s,;)\]}]|$)
    )
    """
)

# False positive suppression patterns
UUID_V4_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
LOCKFILE_INTEGRITY_RE = re.compile(r"^sha(1|256|384|512)-[A-Za-z0-9+/=]{20,}$", re.IGNORECASE)

PLACEHOLDER_SUBSTRINGS = (
    "example",
    "your_api_key",
    "your-api-key",
    "your_secret",
    "your_token",
    "changeme",
    "replace_me",
    "placeholder",
    "dummy",
    "sample",
    "todo",
    "xxxx",
    "00000000",
    "12345678",
    "abcdef",
    "deadbeef",
    "test_token",
    "mock_secret",
)


@dataclass(frozen=True)
class EntropyFinding:
    """Represents a high-entropy token candidate discovered in text."""

    rule_id: str
    cwe_id: str
    severity: str
    charset: str
    entropy: float
    masked_value: str
    line_number: int
    column: int
    description: str


def calculate_shannon_entropy(data: str) -> float:
    """
    Compute the Shannon entropy H(X) in bits per symbol for a string:
        H(X) = - sum_{i=1}^{n} P(x_i) * log2(P(x_i))
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def classify_charset(token: str) -> str:
    """Classify a candidate token into hex, base58, or base64 alphabet class."""
    if not token:
        return "unknown"
    chars = set(token)
    if chars.issubset(HEX_CHARS):
        return "hex"
    if chars.issubset(BASE58_CHARS):
        return "base58"
    if chars.issubset(BASE64_CHARS):
        return "base64"
    return "alphanumeric"


def mask_secret(raw: str, visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """
    Safely redact a secret string so logs and reports never re-leak raw credentials.
    Preserves a minimal prefix/suffix for operator triage when token length permits.
    """
    if not raw:
        return "****"
    length = len(raw)
    if length <= 8:
        return "*" * length
    if length <= 14:
        return f"{raw[:2]}{'*' * (length - 4)}{raw[-2:]}"
    prefix = raw[:visible_prefix]
    suffix = raw[-visible_suffix:]
    return f"{prefix}****...****{suffix}"


def is_false_positive_token(token: str, line_context: str = "") -> bool:
    """
    Evaluate whether a candidate string is a benign identifier, lockfile hash,
    UUID, path expression, or documentation placeholder.
    """
    if not token or len(token) < 20:
        return True

    # Ignore UUIDs
    if UUID_V4_RE.match(token):
        return True

    # Ignore lockfile integrity hashes (sha512-..., sha256-...)
    if LOCKFILE_INTEGRITY_RE.match(token):
        return True
    lower_line = line_context.lower()
    if '"integrity":' in lower_line or "sha512-" in lower_line or "sha256-" in lower_line:
        return True

    # Ignore pure alphabetical words or camelCase / snake_case identifiers without mixed digits
    if token.isalpha() or token.isdigit():
        return True
    if "_" in token and token.replace("_", "").isalpha():
        return True
    if "-" in token and token.replace("-", "").isalpha():
        return True

    # Ignore URLs, file paths, or Python/JS dotted module imports
    if "/" in token and (token.startswith("/") or "http" in lower_line or "node_modules" in lower_line):
        return True
    if "." in token and all(part.isalpha() for part in token.split(".") if part):
        return True

    # Check common dummy placeholders
    lower_token = token.lower()
    for indicator in PLACEHOLDER_SUBSTRINGS:
        if indicator in lower_token:
            return True

    # Check if character diversity is too low (e.g., repeated patterns)
    if len(set(token)) < 6:
        return True

    return False


def evaluate_token_entropy(
    token: str,
    line_context: str = "",
    line_number: int = 1,
    column: int = 1,
    hex_threshold: float = HEX_ENTROPY_THRESHOLD,
    base58_threshold: float = BASE58_ENTROPY_THRESHOLD,
    base64_threshold: float = BASE64_ENTROPY_THRESHOLD,
) -> Optional[EntropyFinding]:
    """
    Evaluate a single token against character-set calibrated Shannon entropy thresholds.
    Returns an EntropyFinding if anomalous entropy is detected, otherwise None.
    """
    if is_false_positive_token(token, line_context):
        return None

    charset = classify_charset(token)
    entropy = calculate_shannon_entropy(token)

    if charset == "hex":
        # Require at least 32 hex chars (128-bit key) to avoid short commit prefixes
        if len(token) < 32:
            return None
        # Git commit SHA-1 (40 hex chars) in git metadata lines are suppressed
        if len(token) == 40 and any(
            k in line_context.lower() for k in ("commit ", "parent ", "tree ", "author ", "rev ")
        ):
            return None
        if entropy >= hex_threshold:
            return EntropyFinding(
                rule_id="VW-ENT-001",
                cwe_id="CWE-798",
                severity="medium",
                charset="hex",
                entropy=entropy,
                masked_value=mask_secret(token),
                line_number=line_number,
                column=column,
                description=f"High-entropy hexadecimal secret candidate ({entropy:.2f} bits/char)",
            )
        return None

    if charset == "base58":
        if len(token) >= 24 and entropy >= base58_threshold:
            return EntropyFinding(
                rule_id="VW-ENT-002",
                cwe_id="CWE-798",
                severity="medium",
                charset="base58",
                entropy=entropy,
                masked_value=mask_secret(token),
                line_number=line_number,
                column=column,
                description=f"High-entropy Base58/Alphanumeric secret candidate ({entropy:.2f} bits/char)",
            )
        return None

    # Base64 or mixed alphanumeric
    if len(token) >= 24 and entropy >= base64_threshold:
        # Ensure token has a mix of upper, lower, and digits/symbols typical of real secrets
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if not (has_upper and has_lower and has_digit):
            return None

        return EntropyFinding(
            rule_id="VW-ENT-003",
            cwe_id="CWE-798",
            severity="medium",
            charset="base64",
            entropy=entropy,
            masked_value=mask_secret(token),
            line_number=line_number,
            column=column,
            description=f"High-entropy Base64 secret candidate ({entropy:.2f} bits/char)",
        )

    return None


def scan_line_entropy(
    line: str,
    line_number: int = 1,
    secret_context_only: bool = True,
) -> List[EntropyFinding]:
    """
    Scan a single line of text for high-entropy secret tokens.
    When secret_context_only is True, requires assignment/credential context keywords
    on the line or high-confidence entropy to keep false positives near zero.
    """
    findings: List[EntropyFinding] = []
    if not line or len(line) > 4096:
        return findings

    secret_keywords = (
        "key",
        "secret",
        "token",
        "password",
        "passwd",
        "pwd",
        "auth",
        "bearer",
        "credential",
        "private",
        "api_",
        "apikey",
        "access_",
        "client_",
        "webhook",
        "signing",
        "encryption",
    )
    lower_line = line.lower()
    has_keyword = any(kw in lower_line for kw in secret_keywords)

    for match in TOKEN_CANDIDATE_RE.finditer(line):
        candidate = match.group(1)
        col = match.start(1) + 1
        finding = evaluate_token_entropy(
            candidate,
            line_context=line,
            line_number=line_number,
            column=col,
        )
        if finding is not None:
            # If no secret keyword is present on the line, require higher entropy (4.75+ bits/char)
            if not secret_context_only or has_keyword or finding.entropy >= 4.75:
                findings.append(finding)

    return findings
