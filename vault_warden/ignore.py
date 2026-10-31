"""
.wardenignore Configuration & Whitelist Gate.

Provides path exclusion and secret token whitelisting to eliminate false positives
in test fixtures, documentation, or mock credentials.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Union


@dataclass
class WardenIgnore:
    """Manages whitelisted file paths, glob patterns, and mock token strings."""

    path_patterns: List[str] = field(default_factory=list)
    token_patterns: List[str] = field(default_factory=list)
    source_file: Optional[Path] = None

    @classmethod
    def load(
        cls,
        ignore_path: Optional[Union[str, Path]] = None,
        search_dir: Optional[Path] = None,
    ) -> "WardenIgnore":
        """
        Load .wardenignore from specified path, or search upwards from search_dir / cwd.
        """
        target: Optional[Path] = None
        if ignore_path is not None:
            p = Path(ignore_path)
            if p.is_file():
                target = p
        elif search_dir is not None:
            candidate = search_dir / ".wardenignore"
            if candidate.is_file():
                target = candidate

        if target is None:
            candidate = Path.cwd() / ".wardenignore"
            if candidate.is_file():
                target = candidate

        if target is None or not target.is_file():
            return cls()

        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return cls()

        return cls.parse(content, source_file=target)

    @classmethod
    def parse(cls, content: str, source_file: Optional[Path] = None) -> "WardenIgnore":
        """Parse .wardenignore content lines into path patterns and token whitelists."""
        paths: List[str] = []
        tokens: List[str] = []

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("token:"):
                tokens.append(line[6:].strip())
            elif line.startswith("path:"):
                paths.append(line[5:].strip())
            elif (
                any(line.startswith(prefix) for prefix in ("sk-", "ghp_", "hf_", "xox", "AIza"))
                or (len(line) >= 30 and "/" not in line and "\\" not in line)
            ):
                tokens.append(line)
            else:
                paths.append(line)

        return cls(path_patterns=paths, token_patterns=tokens, source_file=source_file)

    def is_path_ignored(self, file_path: Union[str, Path]) -> bool:
        """Check if a relative or absolute file path matches any path pattern."""
        if not self.path_patterns:
            return False

        path_str = str(file_path).replace("\\", "/").lstrip("./")
        filename = Path(path_str).name

        for pattern in self.path_patterns:
            pat = pattern.replace("\\", "/").strip().lstrip("./")
            if not pat:
                continue

            # Directory pattern (e.g., fixtures/ or /fixtures/)
            if pat.endswith("/"):
                pat_dir = pat.rstrip("/")
                if (
                    path_str == pat_dir
                    or path_str.startswith(f"{pat_dir}/")
                    or f"/{pat_dir}/" in f"/{path_str}"
                ):
                    return True
            # Direct glob match against full path or basename
            if fnmatch.fnmatch(path_str, pat) or fnmatch.fnmatch(filename, pat):
                return True
            # Glob match against subpaths (e.g. fixtures/* matching a/fixtures/test.py)
            if fnmatch.fnmatch(path_str, f"*/{pat}"):
                return True

        return False

    def is_token_ignored(self, token: str) -> bool:
        """Check if a raw or masked secret token matches any whitelisted token entry."""
        if not self.token_patterns or not token:
            return False

        for pat in self.token_patterns:
            if not pat:
                continue
            if pat in token or token in pat:
                return True
        return False

    def is_finding_ignored(self, finding: Any) -> bool:
        """Determine if a finding object or dictionary should be ignored."""
        if isinstance(finding, dict):
            file_path = str(finding.get("file_path", ""))
            masked = str(finding.get("masked_secret", ""))
            desc = str(finding.get("description", ""))
        else:
            file_path = getattr(finding, "file_path", "")
            masked = getattr(finding, "masked_secret", "")
            desc = getattr(finding, "description", "")

        if file_path and self.is_path_ignored(file_path):
            return True

        if masked and self.is_token_ignored(masked):
            return True

        for tok in self.token_patterns:
            if tok in desc:
                return True

        return False

    def filter_findings(self, findings: Iterable[Any]) -> List[Any]:
        """Filter out findings that match ignored paths or token whitelists."""
        return [f for f in findings if not self.is_finding_ignored(f)]
