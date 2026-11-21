"""
Git Security Sentinel - Path Exclusions and .sentinelignore Filter.
Pure Python standard library implementation of gitignore-style glob matching.
"""

from pathlib import Path
import re
from typing import List, Optional, Pattern, Tuple


class PathFilter:
    """
    Gitignore-style path filter using Python standard library regex.
    Supports glob patterns (*, **, ?), root anchoring (/), bare directory matching,
    negation (!), and comment stripping. Rules are evaluated sequentially.
    """

    def __init__(self, patterns: Optional[List[str]] = None):
        self.patterns: List[str] = patterns or []
        self._rules: List[Tuple[bool, Pattern]] = []
        self._regexes: List[Pattern] = []
        for pat in self.patterns:
            rule = self._parse_rule(pat)
            if rule is not None:
                self._rules.append(rule)
                self._regexes.append(rule[1])

    @classmethod
    def _parse_rule(cls, pattern: str) -> Optional[Tuple[bool, Pattern]]:
        """
        Parses a pattern into an (is_negative, compiled_regex) tuple.
        Returns None for comments and empty lines.
        """
        p = pattern.strip().replace("\\", "/")
        if not p or p.startswith("#"):
            return None

        is_negative = False
        if p.startswith("!"):
            is_negative = True
            p = p[1:].strip()
            if not p:
                return None
        elif p.startswith(r"\!"):
            p = p[1:]

        rx = cls._pattern_to_regex(p)
        if rx is None:
            return None
        return (is_negative, rx)

    @staticmethod
    def _pattern_to_regex(pattern: str) -> Optional[Pattern]:
        """
        Converts a gitignore-style pattern into a compiled regex.
        Supports bare directories, trailing slashes, globs (*, **, ?), and root anchoring.
        Returns None for comments and empty lines.
        """
        p = pattern.strip().replace("\\", "/")
        if not p or p.startswith("#"):
            return None

        if p.startswith("!"):
            p = p[1:].strip()
            if not p:
                return None
        elif p.startswith(r"\!"):
            p = p[1:]

        anchored = p.startswith("/")
        if anchored:
            p = p[1:]

        is_dir_pattern = False
        if p.endswith("/"):
            is_dir_pattern = True
            p = p[:-1]
        elif "*" not in p and "?" not in p:
            last_segment = p.split("/")[-1]
            if "." not in last_segment:
                is_dir_pattern = True

        i = 0
        n = len(p)
        res = []
        while i < n:
            c = p[i]
            if c == "*":
                if i + 1 < n and p[i + 1] == "*":
                    i += 2
                    if i < n and p[i] == "/":
                        i += 1
                        res.append("(?:.*/)?")
                    else:
                        res.append(".*")
                else:
                    i += 1
                    res.append("[^/]*")
            elif c == "?":
                i += 1
                res.append("[^/]")
            elif c in r"\.+^$()[]{}|":
                i += 1
                res.append("\\" + c)
            else:
                i += 1
                res.append(c)

        regex_str = "".join(res)
        suffix = "(?:/.*)?$" if is_dir_pattern else "$"
        if anchored:
            return re.compile(f"^{regex_str}{suffix}")
        return re.compile(f"(?:^|/){regex_str}{suffix}")

    def is_ignored(self, path: str) -> bool:
        """
        Checks whether the given path matches any ignore pattern,
        evaluating rules sequentially in order of appearance.
        A pattern starting with '!' un-ignores matching paths.
        """
        norm_path = path.replace("\\", "/").strip().lstrip("/")
        if norm_path.startswith("./"):
            norm_path = norm_path[2:]

        ignored = False
        for is_negative, rx in self._rules:
            if rx.search(norm_path) is not None:
                ignored = not is_negative
        return ignored

    def should_ignore(self, path: str) -> bool:
        """Alias for is_ignored."""
        return self.is_ignored(path)


def load_sentinelignore(repo_root: Path) -> List[str]:
    """
    Loads ignore patterns from .sentinelignore at the repository root if present.
    """
    root = Path(repo_root)
    ignore_file = root / ".sentinelignore"
    if not ignore_file.is_file():
        return []

    try:
        content = ignore_file.read_text(encoding="utf-8", errors="replace")
        patterns = []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
        return patterns
    except Exception:
        return []
