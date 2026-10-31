# Warden — Cryptographic Secret Sprawl, Git Forensics & Supply-Chain Integrity Scanner

**Blue Team DevSecOps & Incident-Response Toolkit for Secret Detection, Git Object Forensics, Supply-Chain Auditing, and Static AST Analysis**

`vault-warden-ir` is a zero-dependency, cross-platform security engineering and incident-response scanner written in pure Python 3.10+. It combines character-set calibrated Shannon entropy analysis, 34 deterministic credential signatures, deep Git commit-graph history forensics, Levenshtein edit-distance typosquatting detection across PyPI/NPM/Cargo manifests, lifecycle script auditing, and Python/JavaScript static AST vulnerability scanning with native OASIS SARIF v2.1.0 output.

---

## Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Mathematical Foundations](#2-mathematical-foundations)
   - [2.1 Character-Set Calibrated Shannon Entropy](#21-character-set-calibrated-shannon-entropy)
   - [2.2 Dynamic Programming Levenshtein Edit Distance](#22-dynamic-programming-levenshtein-edit-distance)
3. [Detection Capabilities & CWE Taxonomy Mapping](#3-detection-capabilities--cwe-taxonomy-mapping)
   - [3.1 Credential Signatures & Entropy Rules (`CWE-798`)](#31-credential-signatures--entropy-rules-cwe-798)
   - [3.2 Supply-Chain & Lifecycle Hook Auditing (`CWE-506`, `CWE-829`)](#32-supply-chain--lifecycle-hook-auditing-cwe-506-cwe-829)
   - [3.3 Python & JavaScript Static AST Sinks (`CWE-94`, `CWE-78`, `CWE-502`, `CWE-295`, `CWE-328`)](#33-python--javascript-static-ast-sinks-cwe-94-cwe-78-cwe-502-cwe-295-cwe-328)
4. [Deep Git Commit-Graph Forensics](#4-deep-git-commit-graph-forensics)
5. [Cross-Platform Installation & Usage (Linux & Windows)](#5-cross-platform-installation--usage-linux--windows)
6. [CLI Reference](#6-cli-reference)
7. [SARIF v2.1.0 & CI/CD Integration](#7-sarif-v210--cicd-integration)
8. [Verification & Security Audit Gate](#8-verification--security-audit-gate)

---

## 1. Architectural Overview

`vault-warden-ir` is engineered to execute in restricted incident-response environments, ephemeral CI/CD runners, and developer workstations without requiring third-party C extensions or network access.

```
vault-warden-ir/
├── pyproject.toml
├── vault_warden/
│   ├── __init__.py          # Package metadata and version export
│   ├── __main__.py          # Module execution entry point (python -m vault_warden)
│   ├── cli.py               # Subcommands: scan, audit-deps, install-hook
│   ├── entropy.py           # Calibrated Shannon entropy & secret redaction engine
│   ├── signatures.py        # 34 credential regex rules & constant-time HMAC matching
│   ├── ignore.py            # .wardenignore pattern parser and token whitelisting gate
│   ├── git_forensics.py     # Working-tree walker & git log -p unified diff parser
│   ├── supply_chain.py      # Levenshtein typosquatting & package.json hook auditor
│   ├── ast_auditor.py       # Python ast.NodeVisitor & JS static sink analyzer
│   └── sarif.py             # OASIS SARIF v2.1.0 report builder
├── samples/                 # Synthetic compromised manifests & vulnerable code fixtures
├── scripts/
│   └── security-audit.sh    # Automated zero-leak and self-audit verification gate
└── tests/
    └── test_vault_warden.py # 15 unit & integration tests with dynamic token synthesis
```

---

## 2. Mathematical Foundations

### 2.1 Character-Set Calibrated Shannon Entropy

Unstructured secret strings (API keys, cryptographic signing secrets, bearer tokens) exhibit significantly higher randomness than natural-language identifiers, file paths, or source code keywords. `vault_warden/entropy.py` computes the discrete Shannon entropy $H(X)$ in bits per character for a candidate string $X$ of length $N$ over alphabet $\Sigma$:

$$H(X) = -\sum_{x_i \in \Sigma} P(x_i) \log_2 P(x_i), \quad \text{where } P(x_i) = \frac{\text{count}(x_i)}{N}$$

The theoretical maximum entropy $H_{\max} = \log_2 |\Sigma|$ depends on the underlying encoding alphabet. Applying a single uncalibrated threshold across all strings produces either high false negatives on hexadecimal keys or high false positives on Base64 strings. `vault-warden-ir` classifies each candidate token into its narrowest character set prior to threshold evaluation:

| Alphabet Class | Character Set $\Sigma$ | Cardinality $\|\Sigma\|$ | Theoretical $H_{\max}$ (bits/char) | Calibrated Threshold (bits/char) | Minimum Token Length |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Hexadecimal** | `[0-9a-fA-F]` | $16$ | $4.0000$ | $3.20$ | $32$ chars ($128$ bits) |
| **Base58** | `[1-9A-HJ-NP-Za-km-z]` | $58$ | $5.8580$ | $4.25$ | $24$ chars |
| **Base64 / URL-Safe** | `[A-Za-z0-9+/=_-]` | $65$ | $6.0224$ | $4.50$ | $24$ chars |

#### False-Positive Suppression Filters
Before emitting an entropy finding (`VW-ENT-001` through `VW-ENT-003`), the engine suppresses known benign high-entropy constructs:
- **RFC 4122 UUIDv4 Identifiers**: Matches `^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`.
- **Subresource Integrity (SRI) Lockfile Digests**: Ignores `sha256-`, `sha384-`, and `sha512-` Base64 digests inside `package-lock.json` and web manifests.
- **Git Object Metadata**: Suppresses 40-character hexadecimal commit and tree SHA-1 hashes on diff header lines (`commit `, `parent `, `tree `).
- **Documentation Placeholders**: Filters tokens containing `EXAMPLE`, `YOUR_API_KEY`, `changeme`, `placeholder`, `dummy`, or low character diversity ($|\{x_i\}| < 6$).

#### Redaction Safety
Every secret detected by `vault-warden-ir` is immediately masked via `mask_secret()` (`ghp_****...****x9z0`) before being stored in memory structures or serialized to stdout/SARIF, guaranteeing that security scan logs never become a secondary credential leak vector.

### 2.2 Dynamic Programming Levenshtein Edit Distance

To detect software supply-chain typosquatting attacks (e.g., `reqeusts` targeting `requests`, `lodahs` targeting `lodash`, or `tokoi` targeting `tokio`), `vault_warden/supply_chain.py` computes the Levenshtein distance $D(i, j)$ between a declared package name $A$ ($|A| = m$) and a curated registry of popular packages $B$ ($|B| = n$):

$$D(i, j) = \begin{cases} \max(i, j) & \text{if } \min(i, j) = 0, \\ \min \begin{cases} D(i-1, j) + 1 & \text{(deletion)} \\ D(i, j-1) + 1 & \text{(insertion)} \\ D(i-1, j-1) + \mathbb{I}(A_i \neq B_j) & \text{(substitution)} \end{cases} & \text{otherwise.} \end{cases}$$

The implementation uses a two-row rolling buffer achieving $\mathcal{O}(m \cdot n)$ time complexity and $\mathcal{O}(\min(m, n))$ auxiliary space. A package is flagged under `VW-SC-001` (`CWE-829`) when:
1. $D(A, B) = 1$ (single-character insertion, deletion, or substitution),
2. $D(A, B) = 2$ with identical character multisets ($\text{sorted}(A) = \text{sorted}(B)$, capturing adjacent character transpositions such as `reqeusts` $\leftrightarrow$ `requests`), or
3. Homoglyph/delimiter normalization (`0` $\to$ `o`, `1` $\to$ `l`, `_` $\leftrightarrow$ `-`) yields an exact collision with a canonical package name.

---

## 3. Detection Capabilities & CWE Taxonomy Mapping

| CWE ID | CWE Name | Module | Rule ID Range | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **CWE-798** | Use of Hard-coded Credentials | `signatures.py`, `entropy.py`, `git_forensics.py` | `VW-SIG-001` .. `VW-SIG-034`, `VW-ENT-001` .. `VW-ENT-003` | Medium - Critical |
| **CWE-506** | Embedded Malicious Code (Install Hooks) | `supply_chain.py` | `VW-SC-101` .. `VW-SC-106` | High - Critical |
| **CWE-829** | Inclusion of Functionality from Untrusted Control Sphere | `supply_chain.py` | `VW-SC-001` .. `VW-SC-003` | Low - High |
| **CWE-94** | Improper Control of Generation of Code (`eval`/`exec`) | `ast_auditor.py` | `VW-AST-001`, `VW-AST-101` | Critical |
| **CWE-502** | Deserialization of Untrusted Data (`pickle`/`yaml`) | `ast_auditor.py` | `VW-AST-002`, `VW-AST-003` | High - Critical |
| **CWE-78** | OS Command Injection (`shell=True`, `os.system`) | `ast_auditor.py` | `VW-AST-004`, `VW-AST-005`, `VW-AST-103` | High |
| **CWE-295** | Improper Certificate Validation (`verify=False`) | `ast_auditor.py` | `VW-AST-007`, `VW-AST-104` | High |
| **CWE-328** | Use of Weak Hash (`hashlib.md5`, `hashlib.sha1`) | `ast_auditor.py` | `VW-AST-006` | Medium |
| **CWE-79** | Cross-Site Scripting DOM Sink (`innerHTML`) | `ast_auditor.py` | `VW-AST-102` | High |

### 3.1 Credential Signatures & Entropy Rules (`CWE-798`)

`vault_warden/signatures.py` enforces 34 deterministic signatures coupled with minimum Shannon entropy verification:
- **Cloud Provider Credentials**: AWS Access Key IDs (`AKIA`, `ASIA`, `ABIA`, `ACCA`), AWS 40-char Secret Access Keys, Google Cloud API Keys (`AIza...`), GCP Service Account Private Key JSON blocks, Azure Storage Shared Keys, DigitalOcean PATs (`dop_v1_...`).
- **Modern AI & LLM Tokens**: Anthropic Claude API Keys (`sk-ant-api03-...`), OpenAI Project Keys (`sk-proj-...`), OpenAI Admin Keys (`sk-admin-...`), OpenAI Standard Keys (`sk-...`), HuggingFace Access Tokens (`hf_...`).
- **Source Control & CI/CD Tokens**: GitHub Classic PATs (`ghp_...`), GitHub Fine-Grained PATs (`github_pat_...`), GitHub OAuth/App/Refresh tokens (`gho_`, `ghu_`, `ghs_`, `ghr_`), GitLab PATs (`glpat-...`), NPM Publish Tokens (`npm_...`), PyPI Upload Tokens (`pypi-AgEIcHlwaS5vcmc...`), HashiCorp Vault Service Tokens (`hvs....`).
- **SaaS, Messaging & Webhook Keys**: Stripe Live Secret/Restricted Keys (`sk_live_...`, `rk_live_...`), Slack Bot/User Tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`), Slack Incoming Webhooks, Discord Webhooks & Bot Tokens, Telegram Bot Tokens, SendGrid Tokens (`SG....`), Twilio Keys (`SK...`), Mailgun Keys.
- **Cryptographic Material & Database URIs**: RSA/OpenSSH/EC/PGP Private Key PEM headers, JWT Bearer Tokens (`eyJ...`), and PostgreSQL, MySQL, MongoDB (`mongodb+srv://`), and Redis connection URIs with embedded passwords.

### 3.2 Supply-Chain & Lifecycle Hook Auditing (`CWE-506`, `CWE-829`)

`vault_warden/supply_chain.py` parses `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, and `Cargo.lock`:
- **`VW-SC-001` (Typosquatting)**: Flags near-miss package names across PyPI, NPM, and Crates.io.
- **`VW-SC-002` (Unpinned Dependencies)**: Detects wildcard (`*`, `latest`) or unpinned requirements that expose builds to upstream takeover.
- **`VW-SC-003` (Insecure Transport)**: Flags `http://`, `git+http://`, and `git://` dependency URLs and untrusted HTTP PyPI package indexes.
- **`VW-SC-101` .. `VW-SC-106` (Malicious Lifecycle Scripts)**: Inspects `preinstall`, `install`, `postinstall`, and `prepare` hooks in `package.json` for `curl ... | sh`, encoded PowerShell (`powershell -enc`), Base64 decode pipes (`base64 -d | sh`), `/dev/tcp/` reverse shells, inline `python -c` / `node -e` network exfiltration, and `.ssh/id_rsa` or `.aws/credentials` harvesting.

### 3.3 Python & JavaScript Static AST Sinks (`CWE-94`, `CWE-78`, `CWE-502`, `CWE-295`, `CWE-328`)

`vault_warden/ast_auditor.py` parses Python source trees using `ast.NodeVisitor`, tracking import aliases (`import subprocess as sp`, `from pickle import loads as l`) to accurately identify dangerous calls:
- **`VW-AST-001` (`CWE-94`)**: `eval()` and `exec()` dynamic code execution.
- **`VW-AST-002` (`CWE-502`)**: `pickle.load()`, `pickle.loads()`, `cPickle.loads()`, `marshal.loads()`, and `shelve.open()`.
- **`VW-AST-003` (`CWE-502`)**: `yaml.load()`, `yaml.unsafe_load()`, and `yaml.full_load()` unless `Loader=yaml.SafeLoader` (or `CSafeLoader`) is explicitly passed.
- **`VW-AST-004` / `VW-AST-005` (`CWE-78`)**: `os.system()`, `os.popen()`, and `subprocess.Popen` / `run` / `call` / `check_output` with `shell=True`.
- **`VW-AST-006` (`CWE-328`)**: `hashlib.md5()`, `hashlib.sha1()`, and `hashlib.new('md5'|'sha1')`.
- **`VW-AST-007` (`CWE-295`)**: HTTP client calls with `verify=False` or `ssl._create_unverified_context()`.

---

## 4. Deep Git Commit-Graph Forensics

Adversaries and incident responders frequently inspect git history because developers who accidentally commit a credential often remove it in a subsequent commit (`git rm` or line deletion) without rewriting the commit graph or rotating the key. The secret remains recoverable inside `.git/objects/pack/`.

When `--git-history <MAX_COMMITS>` is passed to `vault-warden scan`, `vault_warden/git_forensics.py` invokes `git log -p --no-color -n <MAX_COMMITS>` with `shell=False` (preventing argument injection across POSIX and Windows), parses unified diff headers (`commit <sha1>`, `+++ b/<path>`, `@@ -a,b +c,d @@`), tracks exact line numbers in the target revision, and scans every added diff line (`+`) for credentials.

---

## 5. Cross-Platform Installation & Usage (Linux & Windows)

`vault-warden-ir` uses only the Python 3.10+ standard library and runs identically on Linux, macOS, and Windows without compiling native dependencies.

### Linux / macOS (Bash / Zsh)

```bash
# Clone and install in editable mode (or run directly via python3 -m vault_warden)
pip install -e .

# 1. Scan a directory (working tree + last 50 Git commits)
python3 -m vault_warden scan --path . --git-history 50 --format table --fail-on high

# 2. Audit dependency manifests only
python3 -m vault_warden audit-deps --path ./samples --format table

# 3. Export SARIF v2.1.0 report for GitHub Advanced Security
python3 -m vault_warden scan --path ./samples --format sarif > results.sarif

# 4. Install cross-platform pre-commit hook
python3 -m vault_warden install-hook --repo .
```

### Windows (PowerShell / Command Prompt)

```powershell
# Run directly with the Windows Python launcher or python.exe
python -m vault_warden scan --path .\samples --format table

# Scan repository including last 25 Git commits and fail CI on high/critical findings
python -m vault_warden scan --path . --git-history 25 --format json --fail-on high

# Audit dependency manifests in a target project
python -m vault_warden audit-deps --path .\samples

# Install pre-commit security gate inside .git\hooks\pre-commit
python -m vault_warden install-hook --repo .
```

---

## 6. CLI Reference

| Subcommand | Flag | Values / Default | Description |
| :--- | :--- | :--- | :--- |
| `scan` | `--path` | `<DIR_OR_FILE>` (Required) | Target directory or file path to audit. |
| `scan` | `--git-history` | `<INT>` (Default: `0`) | Number of historical Git commits (`git log -p -n N`) to inspect for deleted secrets. |
| `scan` | `--format` | `table` \| `json` \| `sarif` (Default: `table`) | Output serialization format. |
| `scan` | `--fail-on` | `low` \| `medium` \| `high` \| `critical` | Return non-zero exit code (`1`) if any finding meets or exceeds severity. |
| `scan` | `--exclude-tests` | Boolean flag | Skip `tests/` directories and `test_*.py` files during scanning. |
| `scan` | `--no-entropy` | Boolean flag | Disable generic Shannon entropy heuristics and run deterministic signatures only. |
| `audit-deps` | `--path` | `<DIR_OR_FILE>` (Required) | Target directory or manifest file (`package.json`, `requirements.txt`, `Cargo.lock`, `pyproject.toml`). |
| `audit-deps` | `--format` | `table` \| `json` \| `sarif` (Default: `table`) | Output serialization format. |
| `audit-deps` | `--fail-on` | `low` \| `medium` \| `high` \| `critical` | Return exit code `1` if any supply-chain finding meets or exceeds severity. |
| `install-hook` | `--repo` | `<GIT_REPO_DIR>` (Required) | Generates an executable security gate inside the repository. |
| `install-hook` | `--hook-type` | `pre-commit` \| `pre-push` (Default: `pre-push`) | Type of git hook to install. |

---

## 7. SARIF v2.1.0 & CI/CD Integration

Running `python3 -m vault_warden scan --path <DIR> --format sarif` emits a schema-validated SARIF v2.1.0 document compatible with GitHub Code Scanning (`github/codeql-action/upload-sarif`), DefectDojo, and SIEM ingestion pipelines. Each rule entry includes:
- `properties.security-severity` mapped to CVSS-aligned numeric scores (`9.5` for `critical`, `7.8` for `high`, `5.5` for `medium`, `3.0` for `low`).
- `properties.tags` populated with `external/cwe/cwe-798`, `external/cwe/cwe-506`, `external/cwe/cwe-829`, `external/cwe/cwe-94`, etc.
- Redacted credential previews (`properties.masked_secret`) and Git commit hashes (`properties.commit_hash`) for forensic triage.

---

## 8. Verification & Security Audit Gate

Run the full unit test suite (19 tests covering Shannon entropy math, dynamic token synthesis, redaction safety, Levenshtein typosquatting, malicious `postinstall` hooks, Python AST analysis, Git commit history scanning, AI tokens, entropy calibration, `.wardenignore`, and SARIF output) and the repository zero-leak gate:

```bash
# Run unit test suite
python3 -m unittest discover -s tests -v

# Run automated zero-leak & self-scan security gate
bash ./scripts/security-audit.sh
```
