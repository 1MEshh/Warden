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
STANDARD_UUID_RE = re.compile(
    r"^(?:urn:uuid:|\{)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$",
    re.IGNORECASE,
)
CSS_HEX_COLOR_RE = re.compile(
    r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$"
)
REPETITIVE_HEX_RE = re.compile(
    r"^(?:0{8,}|f{8,}|(?:00){4,}|(?:ff){4,}|(?:00000000|ffffffff)+|([0-9a-fA-F]{1,4})\1{3,})$",
    re.IGNORECASE,
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
    "ffffffff",
    "12345678",
    "abcdef",
    "deadbeef",
    "test_token",
    "mock_secret",
)

ALPHABET_SIZES = {
    "hex": 16,
    "base58": 58,
    "base64": 64,
    "alphanumeric": 62,
}


def calibrate_threshold(charset: str, token_length: int = 32) -> float:
    """
    Calibrate Shannon entropy threshold dynamically based on token alphabet length
    and maximum theoretical entropy H_max = log2(|Sigma|), adjusted for finite sample length.
    """
    alpha_size = ALPHABET_SIZES.get(charset, 64)
    max_entropy = math.log2(alpha_size)
    if token_length > 1:
        length_bound = math.log2(token_length)
        achievable_max = min(max_entropy, length_bound)
    else:
        achievable_max = max_entropy

    if charset == "hex":
        ratio = 0.80
        calibrated = round(achievable_max * ratio, 2)
        return max(2.80, min(calibrated, HEX_ENTROPY_THRESHOLD))
    if charset == "base58":
        ratio = 0.725
        calibrated = round(achievable_max * ratio, 2)
        return max(3.80, min(calibrated, BASE58_ENTROPY_THRESHOLD))

    ratio = 0.75
    calibrated = round(achievable_max * ratio, 2)
    return max(4.00, min(calibrated, BASE64_ENTROPY_THRESHOLD))



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
    UUID, path expression, CSS color, repetitive hex string, or documentation placeholder.
    """
    if not token:
        return True

    # Ignore standard UUIDs (with or without brackets/URN)
    if STANDARD_UUID_RE.match(token) or UUID_V4_RE.match(token):
        return True

    # Ignore CSS hex color codes (#ffffff, #00ff66, #fff, etc.)
    if CSS_HEX_COLOR_RE.match(token):
        return True

    # Ignore repetitive hex strings (00000000, ffffffff, 0000000000000000, etc.)
    lower_token = token.lower()
    if lower_token in ("00000000", "ffffffff"):
        return True
    if REPETITIVE_HEX_RE.match(token):
        return True
    if "00000000" in lower_token or "ffffffff" in lower_token:
        return True
    if all(c == "0" for c in lower_token) or all(c == "f" for c in lower_token):
        return True

    # Check CSS hex colors in line context
    lower_line = line_context.lower()
    if any(
        css_prop in lower_line
        for css_prop in ("color:", "background:", "fill:", "stroke:", "border:")
    ):
        if token.startswith("#") or (len(token) in (6, 8) and all(c in HEX_CHARS for c in token)):
            return True

    if len(token) < 20:
        return True

    # Ignore lockfile integrity hashes (sha512-..., sha256-...)
    if LOCKFILE_INTEGRITY_RE.match(token):
        return True
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
    hex_threshold: Optional[float] = None,
    base58_threshold: Optional[float] = None,
    base64_threshold: Optional[float] = None,
) -> Optional[EntropyFinding]:
    """
    Evaluate a single token against character-set calibrated Shannon entropy thresholds.
    Returns an EntropyFinding if anomalous entropy is detected, otherwise None.
    """
    if is_false_positive_token(token, line_context):
        return None

    charset = classify_charset(token)
    entropy = calculate_shannon_entropy(token)
    token_len = len(token)

    eff_hex = hex_threshold if hex_threshold is not None else calibrate_threshold("hex", token_len)
    eff_base58 = (
        base58_threshold
        if base58_threshold is not None
        else calibrate_threshold("base58", token_len)
    )
    eff_base64 = (
        base64_threshold
        if base64_threshold is not None
        else calibrate_threshold("base64", token_len)
    )

    if charset == "hex":
        # Require at least 32 hex chars (128-bit key) to avoid short commit prefixes
        if token_len < 32:
            return None
        # Git commit SHA-1 (40 hex chars) in git metadata lines are suppressed
        if token_len == 40 and any(
            k in line_context.lower() for k in ("commit ", "parent ", "tree ", "author ", "rev ")
        ):
            return None
        if entropy >= eff_hex:
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
        if token_len >= 24 and entropy >= eff_base58:
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
    if token_len >= 24 and entropy >= eff_base64:
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
