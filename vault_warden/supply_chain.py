"""
Supply-Chain, Typosquatting & Lifecycle Script Auditor (CWE-506, CWE-829).

Parses `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`,
and `Cargo.lock` to detect:
  1. Levenshtein edit-distance + homoglyph typosquatting against top PyPI, NPM,
     and Crates.io packages (CWE-829).
  2. Unpinned wildcard dependencies or insecure `http://` / `git+http://` sources (CWE-829).
  3. Malicious `preinstall` / `install` / `postinstall` lifecycle scripts containing
     remote shell execution, encoded PowerShell, reverse shells, or exfiltration (CWE-506).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Curated registry of popular target packages across PyPI, NPM, and Crates.io
POPULAR_PACKAGES: Dict[str, Tuple[str, ...]] = {
    "pypi": (
        "requests",
        "urllib3",
        "boto3",
        "botocore",
        "cryptography",
        "paramiko",
        "pyyaml",
        "pydantic",
        "fastapi",
        "flask",
        "django",
        "sqlalchemy",
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "scikit-learn",
        "torch",
        "tensorflow",
        "pillow",
        "beautifulsoup4",
        "selenium",
        "playwright",
        "pytest",
        "black",
        "ruff",
        "mypy",
        "celery",
        "redis",
        "psycopg2",
        "pymongo",
        "httpx",
        "aiohttp",
        "click",
        "rich",
        "jinja2",
        "werkzeug",
        "markupsafe",
        "certifi",
        "charset-normalizer",
        "idna",
        "packaging",
        "setuptools",
        "wheel",
        "pip",
        "python-dotenv",
        "pyjwt",
        "bcrypt",
        "passlib",
    ),
    "npm": (
        "lodash",
        "express",
        "react",
        "react-dom",
        "next",
        "axios",
        "chalk",
        "commander",
        "dotenv",
        "cross-env",
        "webpack",
        "typescript",
        "eslint",
        "prettier",
        "moment",
        "dayjs",
        "uuid",
        "jsonwebtoken",
        "bcrypt",
        "mongoose",
        "prisma",
        "socket.io",
        "ws",
        "glob",
        "minimatch",
        "semver",
        "debug",
        "mkdirp",
        "rimraf",
        "inquirer",
        "yargs",
        "rxjs",
        "zod",
        "tailwindcss",
        "vite",
        "vitest",
        "jest",
        "playwright",
        "puppeteer",
        "nodemon",
        "ts-node",
        "esbuild",
        "rollup",
        "cheerio",
        "underscore",
        "async",
        "bluebird",
        "body-parser",
        "cors",
        "helmet",
    ),
    "cargo": (
        "serde",
        "serde_json",
        "tokio",
        "reqwest",
        "clap",
        "anyhow",
        "thiserror",
        "rand",
        "regex",
        "chrono",
        "log",
        "env_logger",
        "tracing",
        "futures",
        "hyper",
        "axum",
        "actix-web",
        "sqlx",
        "diesel",
        "rayon",
        "crossbeam",
        "bytes",
        "uuid",
        "sha2",
        "ring",
        "rustls",
        "syn",
        "quote",
        "proc-macro2",
        "once_cell",
        "lazy_static",
        "itertools",
        "base64",
        "url",
    ),
}

# Lifecycle hooks in package.json that execute automatically during install
LIFECYCLE_HOOKS: Tuple[str, ...] = (
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepublish",
    "prepare",
)

# Suspicious shell patterns in package.json lifecycle hooks (CWE-506)
MALICIOUS_SCRIPT_PATTERNS: Tuple[Tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "VW-SC-101",
        "Remote Pipe-to-Shell Execution",
        "critical",
        re.compile(r"(?i)\b(?:curl|wget)\b[^|;\n]*\|\s*(?:ba)?sh\b"),
    ),
    (
        "VW-SC-102",
        "Encoded PowerShell Payload Execution",
        "critical",
        re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\b"),
    ),
    (
        "VW-SC-103",
        "Base64 Decode Pipe to Execution",
        "critical",
        re.compile(r"(?i)\bbase64\s+(?:-d|--decode)\b[^|\n]*\|\s*(?:ba)?sh\b"),
    ),
    (
        "VW-SC-104",
        "Reverse Shell / Raw Socket Redirection",
        "critical",
        re.compile(r"(?i)(?:/dev/tcp/[0-9a-z.\-]+/\d+|\b(?:nc|ncat|netcat)\s+[^\n]*-e\s+/bin/)"),
    ),
    (
        "VW-SC-105",
        "Inline Python/Node Network Exfiltration in Install Hook",
        "high",
        re.compile(
            r"(?i)(?:python3?\s+-c\s+.*(?:urllib|requests|socket|http\.client)|node\s+-e\s+.*(?:http|https|net|child_process))"
        ),
    ),
    (
        "VW-SC-106",
        "Credential / Environment Harvesting in Lifecycle Hook",
        "high",
        re.compile(r"(?i)(?:\.ssh/id_rsa|\.aws/credentials|\.npmrc|\benv\b.*\|\s*curl)"),
    ),
)

REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(.*)$")


@dataclass(frozen=True)
class SupplyChainFinding:
    """Represents a supply-chain, typosquatting, or lifecycle hook finding."""

    rule_id: str
    rule_name: str
    cwe_id: str
    severity: str
    ecosystem: str
    package_name: str
    file_path: str
    line_number: int
    description: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "category": "supply_chain",
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
        }


def levenshtein_distance(source: str, target: str) -> int:
    """
    Compute the exact Levenshtein edit distance between two strings using
    dynamic programming with O(min(M, N)) space complexity.
    """
    if source == target:
        return 0
    if not source:
        return len(target)
    if not target:
        return len(source)

    if len(source) < len(target):
        source, target = target, source

    previous_row = list(range(len(target) + 1))
    for i, s_char in enumerate(source, start=1):
        current_row = [i]
        for j, t_char in enumerate(target, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (0 if s_char == t_char else 1)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_homoglyphs(name: str) -> str:
    """Normalize common ASCII confusables and separator variations."""
    cleaned = name.lower().strip()
    cleaned = cleaned.replace("_", "-").replace(".", "-")
    # Common digit-to-letter visual confusables
    translations = str.maketrans({"0": "o", "1": "l"})
    return cleaned.translate(translations)


def detect_typosquat(package_name: str, ecosystem: str) -> Optional[Tuple[str, int, str]]:
    """
    Compare `package_name` against the curated registry of popular packages for `ecosystem`.
    Returns `(target_popular_package, distance, reason)` if a potential typosquat is found.
    """
    candidates = POPULAR_PACKAGES.get(ecosystem, ())
    pkg_lower = package_name.lower().strip()

    # Strip NPM scope if present for comparison, unless scoped
    if ecosystem == "npm" and pkg_lower.startswith("@"):
        return None

    # Exact match with a known popular package is safe
    if pkg_lower in candidates:
        return None

    # Also check canonical PEP 503 normalized match for PyPI
    if ecosystem == "pypi" and pkg_lower.replace("_", "-") in {c.replace("_", "-") for c in candidates}:
        # If the only difference is hyphen vs underscore on a package that uses one canonically,
        # check if it's an exact canonical match:
        for canonical in candidates:
            if pkg_lower == canonical:
                return None

    for popular in candidates:
        pop_lower = popular.lower()
        if len(pop_lower) < 4:
            continue

        dist = levenshtein_distance(pkg_lower, pop_lower)

        # 1. Edit distance of 1 (single character typo, omission, addition, or substitution)
        if dist == 1:
            return (popular, dist, f"Levenshtein edit distance 1 from popular package '{popular}'")

        # 2. Adjacent character transposition (e.g., reqeusts -> requests, lodahs -> lodash, tokoi -> tokio)
        if dist == 2 and len(pkg_lower) == len(pop_lower) and sorted(pkg_lower) == sorted(pop_lower):
            return (popular, dist, f"Character transposition of popular package '{popular}'")

        # 3. Homoglyph / separator confusion (e.g., cr0ss-env vs cross-env)
        if normalize_homoglyphs(pkg_lower) == normalize_homoglyphs(pop_lower) and pkg_lower != pop_lower:
            return (popular, dist, f"Homoglyph/delimiter confusion with popular package '{popular}'")

    return None


def _find_line_number(content: str, needle: str) -> int:
    """Locate the 1-indexed line number where `needle` first appears."""
    for idx, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return idx
    return 1


def audit_package_json(content: str, file_path: str = "package.json") -> List[SupplyChainFinding]:
    """Audit an NPM `package.json` file for malicious lifecycle scripts, typosquats, and insecure specs."""
    findings: List[SupplyChainFinding] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings

    if not isinstance(data, dict):
        return findings

    # 1. Inspect lifecycle scripts (CWE-506)
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook_name, script_cmd in scripts.items():
            if not isinstance(script_cmd, str):
                continue
            line_no = _find_line_number(content, f'"{hook_name}"')
            for rule_id, rule_name, severity, pattern in MALICIOUS_SCRIPT_PATTERNS:
                if pattern.search(script_cmd):
                    findings.append(
                        SupplyChainFinding(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            cwe_id="CWE-506",
                            severity=severity,
                            ecosystem="npm",
                            package_name=f"scripts.{hook_name}",
                            file_path=file_path,
                            line_number=line_no,
                            description=(
                                f"Malicious pattern ({rule_name}) in lifecycle script '{hook_name}' (CWE-506)"
                            ),
                        )
                    )

    # 2. Inspect dependency blocks (CWE-829)
    dep_sections = ("dependencies", "devDependencies", "optionalDependencies")
    for section in dep_sections:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for pkg_name, version_spec in deps.items():
            if not isinstance(pkg_name, str) or not isinstance(version_spec, str):
                continue
            line_no = _find_line_number(content, f'"{pkg_name}"')

            # Check typosquatting
            typo = detect_typosquat(pkg_name, "npm")
            if typo is not None:
                target_pkg, dist, reason = typo
                findings.append(
                    SupplyChainFinding(
                        rule_id="VW-SC-001",
                        rule_name="Suspected NPM Typosquatting Package",
                        cwe_id="CWE-829",
                        severity="high",
                        ecosystem="npm",
                        package_name=pkg_name,
                        file_path=file_path,
                        line_number=line_no,
                        description=f"Package '{pkg_name}' flagged: {reason} (edit distance={dist}, CWE-829)",
                    )
                )

            # Check insecure HTTP / unpinned specs
            spec_clean = version_spec.strip().lower()
            if spec_clean in ("*", "latest"):
                findings.append(
                    SupplyChainFinding(
                        rule_id="VW-SC-002",
                        rule_name="Unpinned Wildcard Dependency Version",
                        cwe_id="CWE-829",
                        severity="medium",
                        ecosystem="npm",
                        package_name=pkg_name,
                        file_path=file_path,
                        line_number=line_no,
                        description=(
                            f"Dependency '{pkg_name}' uses unpinned spec '{version_spec}' (CWE-829)"
                        ),
                    )
                )
            elif spec_clean.startswith(("http://", "git+http://", "git://")):
                findings.append(
                    SupplyChainFinding(
                        rule_id="VW-SC-003",
                        rule_name="Insecure Unencrypted Dependency Transport",
                        cwe_id="CWE-829",
                        severity="high",
                        ecosystem="npm",
                        package_name=pkg_name,
                        file_path=file_path,
                        line_number=line_no,
                        description=(
                            f"Dependency '{pkg_name}' fetched over unencrypted transport '{version_spec}' (CWE-829)"
                        ),
                    )
                )

    return findings


def audit_package_lock_json(
    content: str, file_path: str = "package-lock.json"
) -> List[SupplyChainFinding]:
    """Audit `package-lock.json` for insecure resolved tarball URLs and typosquats."""
    findings: List[SupplyChainFinding] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings

    if not isinstance(data, dict):
        return findings

    packages = data.get("packages") or data.get("dependencies")
    if not isinstance(packages, dict):
        return findings

    for pkg_key, meta in packages.items():
        if not pkg_key or not isinstance(meta, dict):
            continue
        pkg_name = pkg_key.split("node_modules/")[-1] if "node_modules/" in pkg_key else pkg_key
        line_no = _find_line_number(content, f'"{pkg_key}"')

        typo = detect_typosquat(pkg_name, "npm")
        if typo is not None:
            _, dist, reason = typo
            findings.append(
                SupplyChainFinding(
                    rule_id="VW-SC-001",
                    rule_name="Suspected NPM Typosquatting Package",
                    cwe_id="CWE-829",
                    severity="high",
                    ecosystem="npm",
                    package_name=pkg_name,
                    file_path=file_path,
                    line_number=line_no,
                    description=f"Locked package '{pkg_name}' flagged: {reason} (edit distance={dist}, CWE-829)",
                )
            )

        resolved = meta.get("resolved")
        if isinstance(resolved, str) and resolved.startswith(("http://", "git+http://", "git://")):
            findings.append(
                SupplyChainFinding(
                    rule_id="VW-SC-003",
                    rule_name="Insecure Unencrypted Dependency Transport",
                    cwe_id="CWE-829",
                    severity="high",
                    ecosystem="npm",
                    package_name=pkg_name,
                    file_path=file_path,
                    line_number=line_no,
                    description=f"Locked package '{pkg_name}' resolves over insecure URI '{resolved}' (CWE-829)",
                )
            )

    return findings


def audit_requirements_txt(
    content: str, file_path: str = "requirements.txt"
) -> List[SupplyChainFinding]:
    """Audit Python `requirements.txt` for PyPI typosquatting, insecure index URLs, and unpinned specs."""
    findings: List[SupplyChainFinding] = []

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        # Check for insecure --index-url / --extra-index-url / --trusted-host
        if line.startswith(("--index-url", "--extra-index-url", "-i ")):
            if "http://" in line:
                findings.append(
                    SupplyChainFinding(
                        rule_id="VW-SC-003",
                        rule_name="Insecure HTTP PyPI Package Index",
                        cwe_id="CWE-829",
                        severity="high",
                        ecosystem="pypi",
                        package_name="pip-index",
                        file_path=file_path,
                        line_number=idx,
                        description=f"Insecure HTTP package index configured: '{line}' (CWE-829)",
                    )
                )
            continue

        if "git+http://" in line or line.startswith("http://"):
            findings.append(
                SupplyChainFinding(
                    rule_id="VW-SC-003",
                    rule_name="Insecure Unencrypted Dependency Transport",
                    cwe_id="CWE-829",
                    severity="high",
                    ecosystem="pypi",
                    package_name=line.split("/")[0],
                    file_path=file_path,
                    line_number=idx,
                    description=f"Requirement uses unencrypted HTTP transport: '{line}' (CWE-829)",
                )
            )
            continue

        match = REQ_LINE_RE.match(line)
        if not match:
            continue
        pkg_name = match.group(1)
        version_spec = match.group(2).strip()

        typo = detect_typosquat(pkg_name, "pypi")
        if typo is not None:
            _, dist, reason = typo
            findings.append(
                SupplyChainFinding(
                    rule_id="VW-SC-001",
                    rule_name="Suspected PyPI Typosquatting Package",
                    cwe_id="CWE-829",
                    severity="high",
                    ecosystem="pypi",
                    package_name=pkg_name,
                    file_path=file_path,
                    line_number=idx,
                    description=f"Package '{pkg_name}' flagged: {reason} (edit distance={dist}, CWE-829)",
                )
            )

        if not version_spec:
            findings.append(
                SupplyChainFinding(
                    rule_id="VW-SC-002",
                    rule_name="Unpinned PyPI Dependency Specification",
                    cwe_id="CWE-829",
                    severity="low",
                    ecosystem="pypi",
                    package_name=pkg_name,
                    file_path=file_path,
                    line_number=idx,
                    description=f"PyPI dependency '{pkg_name}' is unpinned in {file_path} (CWE-829)",
                )
            )

    return findings


def audit_pyproject_toml(content: str, file_path: str = "pyproject.toml") -> List[SupplyChainFinding]:
    """Audit `pyproject.toml` dependency declarations for typosquatting and insecure URLs."""
    findings: List[SupplyChainFinding] = []
    dep_string_re = re.compile(r'^\s*"([A-Za-z0-9_.\-]+)([^"]*)"\s*,?\s*$')

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        match = dep_string_re.match(line)
        if not match:
            continue
        pkg_name = match.group(1)
        spec_rest = match.group(2)

        typo = detect_typosquat(pkg_name, "pypi")
        if typo is not None:
            _, dist, reason = typo
            findings.append(
                SupplyChainFinding(
                    rule_id="VW-SC-001",
                    rule_name="Suspected PyPI Typosquatting Package",
                    cwe_id="CWE-829",
                    severity="high",
                    ecosystem="pypi",
                    package_name=pkg_name,
                    file_path=file_path,
                    line_number=idx,
                    description=f"Package '{pkg_name}' flagged: {reason} (edit distance={dist}, CWE-829)",
                )
            )

        if "http://" in spec_rest:
            findings.append(
                SupplyChainFinding(
                    rule_id="VW-SC-003",
                    rule_name="Insecure Unencrypted Dependency Transport",
                    cwe_id="CWE-829",
                    severity="high",
                    ecosystem="pypi",
                    package_name=pkg_name,
                    file_path=file_path,
                    line_number=idx,
                    description=f"Dependency '{pkg_name}' uses unencrypted HTTP URL (CWE-829)",
                )
            )

    return findings


def audit_cargo_lock(content: str, file_path: str = "Cargo.lock") -> List[SupplyChainFinding]:
    """Audit Rust `Cargo.lock` for Crates.io typosquatting and insecure git sources."""
    findings: List[SupplyChainFinding] = []
    name_re = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
    source_re = re.compile(r'^\s*source\s*=\s*"([^"]+)"')

    current_name: Optional[str] = None
    current_line: int = 1

    for idx, line in enumerate(content.splitlines(), start=1):
        name_match = name_re.match(line)
        if name_match:
            current_name = name_match.group(1)
            current_line = idx
            typo = detect_typosquat(current_name, "cargo")
            if typo is not None:
                _, dist, reason = typo
                findings.append(
                    SupplyChainFinding(
                        rule_id="VW-SC-001",
                        rule_name="Suspected Crates.io Typosquatting Package",
                        cwe_id="CWE-829",
                        severity="high",
                        ecosystem="cargo",
                        package_name=current_name,
                        file_path=file_path,
                        line_number=current_line,
                        description=f"Crate '{current_name}' flagged: {reason} (edit distance={dist}, CWE-829)",
                    )
                )
            continue

        source_match = source_re.match(line)
        if source_match and current_name:
            src = source_match.group(1)
            if src.startswith(("git+http://", "http://")):
                findings.append(
                    SupplyChainFinding(
                        rule_id="VW-SC-003",
                        rule_name="Insecure Unencrypted Dependency Transport",
                        cwe_id="CWE-829",
                        severity="high",
                        ecosystem="cargo",
                        package_name=current_name,
                        file_path=file_path,
                        line_number=idx,
                        description=f"Crate '{current_name}' uses unencrypted source '{src}' (CWE-829)",
                    )
                )

    return findings


def scan_supply_chain(root_path: Path, exclude_tests: bool = False) -> List[SupplyChainFinding]:
    """Discover and audit all dependency manifests under `root_path`."""
    findings: List[SupplyChainFinding] = []
    base = root_path.resolve()

    manifest_names = {
        "package.json": audit_package_json,
        "package-lock.json": audit_package_lock_json,
        "requirements.txt": audit_requirements_txt,
        "pyproject.toml": audit_pyproject_toml,
        "Cargo.lock": audit_cargo_lock,
    }

    if base.is_file():
        auditor = manifest_names.get(base.name)
        if auditor is not None:
            content = base.read_text(encoding="utf-8", errors="replace")
            findings.extend(auditor(content, file_path=base.name))
        return findings

    for file_path in sorted(base.rglob("*")):
        if not file_path.is_file():
            continue
        if any(part in (".git", "node_modules", ".venv", "venv", "__pycache__") for part in file_path.parts):
            continue
        if exclude_tests and any(part in ("tests", "test") for part in file_path.parts):
            continue
        auditor = manifest_names.get(file_path.name)
        if auditor is None:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            rel_path = file_path.resolve().relative_to(base).as_posix()
        except OSError:
            continue
        findings.extend(auditor(content, file_path=rel_path))

    return findings
