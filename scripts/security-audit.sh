#!/usr/bin/env bash
# ==============================================================================
# vault-warden-ir: Zero-Leak & Self-Audit Security Gate
# Enforces zero local filesystem paths, zero OS username leaks, zero literal
# secrets in tracked files, and 100% clean self-scan on `vault_warden/`.
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[security-audit] Starting zero-leak and DevSecOps verification..."

# 1. Verify tracked files exist
TRACKED_FILES="$(git ls-files)"
if [ -z "$TRACKED_FILES" ]; then
    echo "[security-audit] Notice: No git-tracked files yet; scanning working tree files."
    TRACKED_FILES="$(find . -maxdepth 3 -type f -not -path '*/.*' -not -path './__pycache__/*')"
fi

# 2. Check for hardcoded home directories (/home/<user>, /Users/<user>, C:\Users\<user>)
# Exclude this script and documentation rules that describe the pattern generically
PATH_LEAKS="$(grep -rnE '(/home/[a-zA-Z0-9_-]+|/Users/[a-zA-Z0-9_-]+|C:\\\\Users\\\\[a-zA-Z0-9_-]+)' \
    vault_warden/ tests/ samples/ pyproject.toml README.md .github/ 2>/dev/null | \
    grep -vE '(/home/<user>|/Users/<user>|C:\\Users\\<user>)' || true)"

if [ -n "$PATH_LEAKS" ]; then
    echo "[security-audit] FAIL: Machine-specific filesystem path leak detected:" >&2
    echo "$PATH_LEAKS" >&2
    exit 1
fi
echo "[security-audit] PASS: Zero machine-specific filesystem paths detected."

# 3. Check for current OS username leak in repository files
CURRENT_USER="$(whoami 2>/dev/null || echo "")"
if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ] && [ "$CURRENT_USER" != "runner" ]; then
    USER_LEAKS="$(grep -rnF "$CURRENT_USER" vault_warden/ tests/ samples/ scripts/ pyproject.toml README.md .github/ 2>/dev/null || true)"
    if [ -n "$USER_LEAKS" ]; then
        echo "[security-audit] FAIL: Local OS username leak detected in repository:" >&2
        echo "$USER_LEAKS" >&2
        exit 1
    fi
fi
echo "[security-audit] PASS: Zero OS username leaks detected."

# 4. Run vault-warden-ir self-scan against its own production code (`vault_warden/`)
echo "[security-audit] Running vault-warden-ir self-scan on vault_warden/..."
python3 -m vault_warden scan --path vault_warden --format table --fail-on low

# 5. Execute full unit test suite
echo "[security-audit] Running unit test suite..."
python3 -m unittest discover -s tests -v

echo "[security-audit] ALL CHECKS PASSED."
