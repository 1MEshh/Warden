"""
Deep Git Commit-Graph & Working Tree Forensics (CWE-798).

Scans working tree files and walks historical Git commit patches (`git log -p -n <N>`)
across Linux and Windows to detect secrets that were committed and subsequently
deleted in later revisions.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

from vault_warden.signatures import SecretFinding, scan_line_for_secrets, scan_text_for_secrets

IGNORED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".eggs",
}

BINARY_EXTENSIONS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".whl",
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".mov",
    ".sqlite",
    ".db",
}

DIFF_HEADER_FILE_RE = re.compile(r"^\+\+\+\s+b/(.+)$")
DIFF_HUNK_RE = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")
COMMIT_HEADER_RE = re.compile(r"^commit\s+([0-9a-f]{40})\b")


def is_binary_file(file_path: Path) -> bool:
    """Detect whether a file is binary by extension or NUL byte inspection."""
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with file_path.open("rb") as fh:
            chunk = fh.read(2048)
            if b"\x00" in chunk:
                return True
    except OSError:
        return True
    return False


def iter_scannable_files(
    root_path: Path,
    exclude_tests: bool = False,
    warden_ignore: Optional[Any] = None,
) -> Iterable[Path]:
    """Yield text files under root_path safely across Windows and Linux."""
    base = root_path.resolve()
    if root_path.is_file():
        if warden_ignore and warden_ignore.is_path_ignored(root_path.name):
            return
        if not is_binary_file(root_path):
            yield root_path
        return

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune ignored directories in-place
        dirnames[:] = [
            d
            for d in dirnames
            if d not in IGNORED_DIRS
            and not d.endswith(".egg-info")
            and not (exclude_tests and d in ("tests", "test"))
            and not (
                warden_ignore
                and warden_ignore.is_path_ignored(
                    (Path(dirpath) / d).resolve().relative_to(base).as_posix() + "/"
                )
            )
        ]
        for filename in sorted(filenames):
            if exclude_tests and (filename.startswith("test_") or filename.endswith("_test.py")):
                continue
            full_path = Path(dirpath) / filename
            if warden_ignore:
                try:
                    rel_p = full_path.resolve().relative_to(base).as_posix()
                except ValueError:
                    rel_p = filename
                if warden_ignore.is_path_ignored(rel_p):
                    continue
            if is_binary_file(full_path):
                continue
            try:
                if full_path.stat().st_size > 2 * 1024 * 1024:  # Skip files > 2MB
                    continue
            except OSError:
                continue
            yield full_path


def scan_working_tree(
    root_path: Path,
    exclude_tests: bool = False,
    include_entropy: bool = True,
    warden_ignore: Optional[Any] = None,
) -> List[SecretFinding]:
    """Scan all eligible files in the working directory for secrets."""
    findings: List[SecretFinding] = []
    base = root_path.resolve()
    if warden_ignore is None:
        from vault_warden.ignore import WardenIgnore

        warden_ignore = WardenIgnore.load(search_dir=base if base.is_dir() else base.parent)

    for file_path in iter_scannable_files(
        base, exclude_tests=exclude_tests, warden_ignore=warden_ignore
    ):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            rel_path = file_path.resolve().relative_to(base).as_posix()
        except ValueError:
            rel_path = file_path.name

        file_findings = scan_text_for_secrets(
            content=content,
            file_path=rel_path,
            commit_hash=None,
            include_entropy=include_entropy,
        )
        findings.extend(file_findings)

    return warden_ignore.filter_findings(findings)


def parse_git_log_patch(
    patch_output: str,
    include_entropy: bool = True,
) -> List[SecretFinding]:
    """
    Parse raw `git log -p` unified diff output and scan added lines (`+`)
    for leaked credentials across historical commits.
    """
    findings: List[SecretFinding] = []
    current_commit: Optional[str] = None
    current_file: str = "<git-history>"
    current_line_num: int = 1
    seen_keys: Set[Tuple[str, str, int, str]] = set()

    for raw_line in patch_output.splitlines():
        commit_match = COMMIT_HEADER_RE.match(raw_line)
        if commit_match:
            current_commit = commit_match.group(1)
            continue

        file_match = DIFF_HEADER_FILE_RE.match(raw_line)
        if file_match:
            current_file = file_match.group(1).strip()
            continue

        hunk_match = DIFF_HUNK_RE.match(raw_line)
        if hunk_match:
            current_line_num = int(hunk_match.group(1))
            continue

        # Only inspect added lines in commits (excluding `+++` header lines)
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added_content = raw_line[1:]
            line_findings = scan_line_for_secrets(
                line=added_content,
                file_path=current_file,
                line_number=current_line_num,
                commit_hash=current_commit,
                include_entropy=include_entropy,
            )
            for item in line_findings:
                dedup_key = (item.rule_id, item.file_path, item.line_number, item.masked_secret)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    findings.append(item)
            current_line_num += 1
        elif not raw_line.startswith("-") and not raw_line.startswith("\\"):
            # Context line in unified diff advances the target file line counter
            if current_commit is not None and current_file != "<git-history>":
                current_line_num += 1

    return findings


def scan_git_history(
    repo_path: Path,
    max_commits: int = 50,
    include_entropy: bool = True,
    warden_ignore: Optional[Any] = None,
) -> List[SecretFinding]:
    """
    Execute `git log -p -n <max_commits>` safely without a shell (`shell=False`)
    and inspect commit diffs for historical credential exposure.
    """
    if max_commits <= 0:
        return []

    target_dir = repo_path if repo_path.is_dir() else repo_path.parent
    if warden_ignore is None:
        from vault_warden.ignore import WardenIgnore

        warden_ignore = WardenIgnore.load(search_dir=target_dir)

    cmd = [
        "git",
        "-C",
        str(target_dir),
        "log",
        "-p",
        "--no-color",
        "-n",
        str(int(max_commits)),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if proc.returncode != 0 or not proc.stdout:
        return []

    findings = parse_git_log_patch(proc.stdout, include_entropy=include_entropy)
    return warden_ignore.filter_findings(findings)
