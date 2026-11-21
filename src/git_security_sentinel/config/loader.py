"""
Git Security Sentinel - Zero-Dependency Configuration Loader.
Parses .sentinel.yaml and .sentinel.toml strictly using the Python standard library.
Zero third-party dependencies (no PyYAML).
"""

from pathlib import Path
import re
import sys
import textwrap
from typing import Any, Dict, List, Optional, Tuple


def _strip_inline_comment(line: str) -> str:
    """Strips comments from line while preserving hash characters inside quotes."""
    in_single = False
    in_double = False
    for i, c in enumerate(line):
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1].isspace():
                return line[:i].rstrip()
    return line


def parse_scalar(val: str) -> Any:
    """Parses a raw YAML scalar string into a Python typed value."""
    v = val.strip()
    if not v:
        return None

    lower = v.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    if lower in ("null", "none", "~"):
        return None

    # Quoted string
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]

    # Inline list: [a, b, c]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        tokens = [t.strip() for t in inner.split(",") if t.strip()]
        return [parse_scalar(t) for t in tokens]

    # Numbers
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass

    return v


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """
    Pure Python standard library YAML parser supporting key-value pairs,
    nested dictionaries (2-space indents), lists (- item), inline lists,
    booleans, numbers, quoted strings, nulls, and comments.
    """
    if not text or not text.strip():
        return {}

    dedented = textwrap.dedent(text)
    raw_lines = dedented.splitlines()

    active_lines: List[Tuple[int, str]] = []
    for raw in raw_lines:
        stripped_comment = _strip_inline_comment(raw)
        if not stripped_comment.strip():
            continue
        indent = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        content = stripped_comment.strip()
        active_lines.append((indent, content))

    if not active_lines:
        return {}

    def _parse_mapping(lines: List[Tuple[int, str]], start_idx: int, cur_indent: int) -> Tuple[Dict[str, Any], int]:
        result: Dict[str, Any] = {}
        i = start_idx
        while i < len(lines):
            indent, text = lines[i]
            if indent < cur_indent:
                break
            if indent > cur_indent:
                # Belonged to previous block; break out
                break

            if ":" not in text:
                i += 1
                continue

            key_part, _, val_part = text.partition(":")
            key = key_part.strip()
            # Unquote key if quoted
            if (key.startswith('"') and key.endswith('"')) or (key.startswith("'") and key.endswith("'")):
                key = key[1:-1]
            val = val_part.strip()
            i += 1

            if val:
                result[key] = parse_scalar(val)
            else:
                # Check next line for nested block
                if i < len(lines) and lines[i][0] > cur_indent:
                    child_indent = lines[i][0]
                    if lines[i][1].startswith("- "):
                        child_list, i = _parse_sequence(lines, i, child_indent)
                        result[key] = child_list
                    else:
                        child_dict, i = _parse_mapping(lines, i, child_indent)
                        result[key] = child_dict
                else:
                    result[key] = None

        return result, i

    def _parse_sequence(lines: List[Tuple[int, str]], start_idx: int, cur_indent: int) -> Tuple[List[Any], int]:
        result: List[Any] = []
        i = start_idx
        while i < len(lines):
            indent, text = lines[i]
            if indent < cur_indent:
                break
            if indent > cur_indent:
                break

            if not text.startswith("- "):
                break

            item_text = text[2:].strip()
            i += 1

            if not item_text:
                if i < len(lines) and lines[i][0] > cur_indent:
                    child_indent = lines[i][0]
                    if lines[i][1].startswith("- "):
                        child_list, i = _parse_sequence(lines, i, child_indent)
                        result.append(child_list)
                    else:
                        child_dict, i = _parse_mapping(lines, i, child_indent)
                        result.append(child_dict)
                else:
                    result.append(None)
            else:
                if ":" in item_text and not (item_text.startswith('"') or item_text.startswith("'")):
                    k, _, v = item_text.partition(":")
                    k = k.strip()
                    v = v.strip()
                    sub_map: Dict[str, Any] = {k: parse_scalar(v) if v else None}
                    if i < len(lines) and lines[i][0] > cur_indent and not lines[i][1].startswith("- "):
                        extra_map, i = _parse_mapping(lines, i, lines[i][0])
                        sub_map.update(extra_map)
                    result.append(sub_map)
                else:
                    result.append(parse_scalar(item_text))

        return result, i

    # Top-level parsing
    if active_lines[0][1].startswith("- "):
        parsed_res, _ = _parse_sequence(active_lines, 0, active_lines[0][0])
        return {"items": parsed_res}
    else:
        parsed_map, _ = _parse_mapping(active_lines, 0, active_lines[0][0])
        return parsed_map


def _parse_simple_toml(text: str) -> Dict[str, Any]:
    """Lightweight fallback TOML parser for simple key-value and tables."""
    root: Dict[str, Any] = {}
    current_section: Dict[str, Any] = root

    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            sec_name = line[1:-1].strip()
            parts = [p.strip() for p in sec_name.split(".")]
            curr = root
            for p in parts:
                if p not in curr or not isinstance(curr[p], dict):
                    curr[p] = {}
                curr = curr[p]
            current_section = curr
        elif "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            current_section[key] = parse_scalar(val)

    return root


def load_config(repo_root: Path, config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Finds and parses project configuration (.sentinel.yaml, .sentinel.yml, or .sentinel.toml).
    Uses stdlib only.
    """
    root = Path(repo_root)

    if config_path:
        target = Path(config_path)
        if not target.is_absolute():
            target = root / target
        if not target.is_file():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
    else:
        candidates = [
            root / ".sentinel.yaml",
            root / ".sentinel.yml",
            root / ".sentinel.toml",
        ]
        target = next((c for c in candidates if c.is_file()), None)

    if not target:
        return {}

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        raise RuntimeError(f"Failed to read configuration file '{target}': {e}")

    if target.suffix == ".toml":
        if sys.version_info >= (3, 11):
            import tomllib
            return tomllib.loads(content)
        return _parse_simple_toml(content)

    return parse_simple_yaml(content)
