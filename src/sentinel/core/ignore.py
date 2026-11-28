"""Gitignore-style ignore rule parsing and path matching for Sentinel."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterable, List, Optional, Pattern, Tuple


@dataclass(frozen=True)
class IgnoreRule:
    """Single compiled rule parsed from a `.sentinelignore` file."""

    raw_pattern: str
    pattern: str
    negated: bool
    dir_only: bool
    anchored: bool
    regex: Pattern[str]


def _normalize_rel_path(rel_path: str) -> str:
    """Normalize a relative path to forward slashes without leading/trailing slashes."""
    norm = rel_path.replace("\\", "/").strip("/")
    while norm.startswith("./"):
        norm = norm[2:].lstrip("/")
    if not norm or norm == ".":
        return ""
    parts = [part for part in norm.split("/") if part and part != "."]
    return "/".join(parts)


def _strip_trailing_unescaped_spaces(line: str) -> str:
    """Strip unescaped trailing ASCII spaces while preserving escaped trailing spaces."""
    end = len(line)
    while end > 0 and line[end - 1] == " ":
        backslashes = 0
        idx = end - 2
        while idx >= 0 and line[idx] == "\\":
            backslashes += 1
            idx -= 1
        if backslashes % 2 == 1:
            break
        end -= 1
    return line[:end]


def _translate_char_class(pattern: str, start: int) -> Tuple[str, int]:
    """Translate a glob `[...]` character class without allowing `/` matches."""
    length = len(pattern)
    idx = start + 1
    if idx >= length:
        return re.escape("["), start + 1

    negated = False
    if pattern[idx] in ("!", "^"):
        negated = True
        idx += 1

    body: List[str] = []
    if idx < length and pattern[idx] == "]":
        body.append(r"\]")
        idx += 1

    closed = False
    while idx < length:
        ch = pattern[idx]
        if ch == "]":
            closed = True
            idx += 1
            break
        if ch == "\\" and idx + 1 < length:
            body.append(re.escape(pattern[idx + 1]))
            idx += 2
            continue
        if ch in ("\\", "[", "&", "~", "|"):
            body.append("\\" + ch)
        elif ch == "-" and not body:
            body.append("\\-")
        else:
            body.append(ch)
        idx += 1

    if not closed or not body:
        return re.escape("["), start + 1

    prefix = "^" if negated else ""
    cls_expr = f"[{prefix}{''.join(body)}]"
    try:
        re.compile(cls_expr)
    except re.error:
        return re.escape("["), start + 1
    return f"(?!/){cls_expr}", idx


def _segment_glob_to_regex(segment: str) -> str:
    """Convert a single path-segment glob pattern into a regex (never matching `/`)."""
    out: List[str] = []
    idx = 0
    length = len(segment)
    while idx < length:
        ch = segment[idx]
        if ch == "\\" and idx + 1 < length:
            out.append(re.escape(segment[idx + 1]))
            idx += 2
        elif ch == "*":
            while idx + 1 < length and segment[idx + 1] == "*":
                idx += 1
            out.append("[^/]*")
            idx += 1
        elif ch == "?":
            out.append("[^/]")
            idx += 1
        elif ch == "[":
            cls_regex, idx = _translate_char_class(segment, idx)
            out.append(cls_regex)
        else:
            out.append(re.escape(ch))
            idx += 1
    return "".join(out)


def _collapse_double_stars(segments: List[str]) -> List[str]:
    """Collapse consecutive `**` segments into a single `**`."""
    collapsed: List[str] = []
    for seg in segments:
        if seg == "**" and collapsed and collapsed[-1] == "**":
            continue
        collapsed.append(seg)
    return collapsed


def _compile_pattern_regex(
    pattern: str,
    anchored: bool,
    case_insensitive: bool,
) -> Pattern[str]:
    """Compile a normalized ignore pattern into a full-string regex."""
    flags = re.IGNORECASE if case_insensitive else 0
    raw_segments = [seg for seg in pattern.split("/") if seg]
    segments = _collapse_double_stars(raw_segments)

    if not segments:
        return re.compile(r"^$", flags)

    if segments == ["**"]:
        return re.compile(r"^.+$", flags)

    if not anchored and len(segments) == 1:
        seg_regex = _segment_glob_to_regex(segments[0])
        return re.compile(rf"^(?:[^/]+/)*{seg_regex}$", flags)

    parts: List[str] = ["^"]
    for idx, seg in enumerate(segments):
        if seg == "**":
            if idx == 0 or idx < len(segments) - 1:
                if idx > 0:
                    parts.append("/")
                parts.append("(?:[^/]+/)*")
            else:
                parts.append("/.+")
        else:
            if idx > 0 and segments[idx - 1] != "**":
                parts.append("/")
            parts.append(_segment_glob_to_regex(seg))
    parts.append("$")
    return re.compile("".join(parts), flags)


def _parse_rule(raw_line: str, case_insensitive: bool) -> Optional[IgnoreRule]:
    """Parse one line from `.sentinelignore` into an IgnoreRule, or None if ignored."""
    line = raw_line.rstrip("\r\n")
    if line.startswith("#"):
        return None

    trimmed = _strip_trailing_unescaped_spaces(line)
    if not trimmed.strip():
        return None

    work = trimmed
    negated = False
    if work.startswith("!"):
        negated = True
        work = work[1:]

    if not work:
        return None

    dir_only = False
    if work.endswith("/"):
        dir_only = True
        work = work.rstrip("/")

    if not work:
        return None

    if work.startswith("/"):
        anchored = True
        work = work.lstrip("/")
    else:
        anchored = "/" in work

    if not work:
        return None

    regex = _compile_pattern_regex(work, anchored=anchored, case_insensitive=case_insensitive)
    return IgnoreRule(
        raw_pattern=line,
        pattern=work,
        negated=negated,
        dir_only=dir_only,
        anchored=anchored,
        regex=regex,
    )


def _rule_matches_direct(rule: IgnoreRule, rel_path: str, is_dir: bool) -> bool:
    """Return True if *rule* matches *rel_path* directly (respecting dir_only)."""
    if rule.dir_only and not is_dir:
        return False
    return rule.regex.match(rel_path) is not None


def _rule_could_match_inside(
    rule: IgnoreRule,
    rel_dir: str,
    case_insensitive: bool,
) -> bool:
    """Return True if *rule* could match a descendant strictly inside *rel_dir*."""
    if not rule.anchored:
        return True

    dir_parts = rel_dir.split("/")
    pat_parts = _collapse_double_stars([seg for seg in rule.pattern.split("/") if seg])
    if not pat_parts:
        return False

    flags = re.IGNORECASE if case_insensitive else 0
    seg_patterns = [
        None if seg == "**" else re.compile(f"^{_segment_glob_to_regex(seg)}$", flags)
        for seg in pat_parts
    ]

    num_dir = len(dir_parts)
    num_pat = len(pat_parts)
    memo: dict[Tuple[int, int], bool] = {}

    def _can_reach(dir_idx: int, pat_idx: int) -> bool:
        key = (dir_idx, pat_idx)
        if key in memo:
            return memo[key]

        if dir_idx == num_dir:
            result = pat_idx < num_pat
            memo[key] = result
            return result

        if pat_idx == num_pat:
            memo[key] = False
            return False

        seg_re = seg_patterns[pat_idx]
        if seg_re is None:
            result = _can_reach(dir_idx, pat_idx + 1) or _can_reach(dir_idx + 1, pat_idx)
        else:
            result = bool(
                seg_re.match(dir_parts[dir_idx])
                and _can_reach(dir_idx + 1, pat_idx + 1)
            )
        memo[key] = result
        return result

    return _can_reach(0, 0)


class IgnoreMatcher:
    """Evaluates gitignore-style rules against relative filesystem paths."""

    def __init__(
        self,
        rules: Iterable[IgnoreRule] = (),
        case_insensitive: Optional[bool] = None,
    ) -> None:
        """Initialize a matcher from compiled rules and case-sensitivity setting."""
        self.rules: Tuple[IgnoreRule, ...] = tuple(rules)
        if case_insensitive is None:
            case_insensitive = os.name == "nt"
        self.case_insensitive: bool = bool(case_insensitive)

    @classmethod
    def from_lines(
        cls,
        lines: Iterable[str],
        case_insensitive: Optional[bool] = None,
    ) -> IgnoreMatcher:
        """Build an IgnoreMatcher by parsing an iterable of pattern lines.

        Args:
            lines: Sequence or iterable of raw pattern lines.
            case_insensitive: Whether path matching ignores case; defaults to Windows behavior.

        Returns:
            Compiled IgnoreMatcher instance.
        """
        resolved_ci = (os.name == "nt") if case_insensitive is None else bool(case_insensitive)
        parsed: List[IgnoreRule] = []
        for idx, raw_line in enumerate(lines):
            if idx == 0 and raw_line.startswith("\ufeff"):
                raw_line = raw_line[1:]
            rule = _parse_rule(raw_line, case_insensitive=resolved_ci)
            if rule is not None:
                parsed.append(rule)
        return cls(parsed, case_insensitive=resolved_ci)

    @classmethod
    def from_file(
        cls,
        ignore_file: Path,
        case_insensitive: Optional[bool] = None,
    ) -> IgnoreMatcher:
        """Load ignore rules from *ignore_file* using UTF-8 (stripping optional BOM).

        Args:
            ignore_file: Path to the `.sentinelignore` file.
            case_insensitive: Whether path matching ignores case; defaults to Windows behavior.

        Returns:
            Compiled IgnoreMatcher instance.

        Raises:
            OSError: If *ignore_file* cannot be opened or read.
            UnicodeDecodeError: If *ignore_file* contains invalid UTF-8 bytes.
        """
        content = ignore_file.read_text(encoding="utf-8-sig")
        return cls.from_lines(content.splitlines(), case_insensitive=case_insensitive)

    def _evaluate(self, norm_path: str, is_dir: bool) -> Tuple[bool, int]:
        """Return `(is_ignored, last_deciding_rule_index)` for a normalized path."""
        if not norm_path or not self.rules:
            return False, -1

        segments = norm_path.split("/")
        prefixes: List[Tuple[int, str, bool]] = []
        for idx in range(len(segments)):
            prefix = "/".join(segments[: idx + 1])
            prefix_is_dir = True if idx < len(segments) - 1 else is_dir
            prefixes.append((idx + 1, prefix, prefix_is_dir))

        ignored = False
        active_depth = 0
        last_deciding_idx = -1

        for rule_idx, rule in enumerate(self.rules):
            for depth, prefix, prefix_is_dir in prefixes:
                if not _rule_matches_direct(rule, prefix, prefix_is_dir):
                    continue
                if not rule.negated:
                    active_depth = max(active_depth, depth) if ignored else depth
                    ignored = True
                    last_deciding_idx = rule_idx
                elif not ignored or depth >= active_depth:
                    ignored = False
                    active_depth = depth
                    last_deciding_idx = rule_idx

        return ignored, last_deciding_idx

    def is_ignored(self, rel_path: str, is_dir: bool = False) -> bool:
        """Return True if *rel_path* is ignored by the configured rules.

        Args:
            rel_path: Path relative to the monitored root directory.
            is_dir: True if *rel_path* refers to a directory.

        Returns:
            True when the last applicable rule ignores *rel_path*; otherwise False.
        """
        norm_path = _normalize_rel_path(rel_path)
        if not norm_path:
            return False
        ignored, _ = self._evaluate(norm_path, is_dir=is_dir)
        return ignored

    def can_prune_directory(self, rel_dir: str) -> bool:
        """Return True when an ignored directory has no subsequent negation rule
        that could re-include files inside it.

        Args:
            rel_dir: Directory path relative to the monitored root.

        Returns:
            True if the scanner can safely skip traversing *rel_dir*.
        """
        norm_dir = _normalize_rel_path(rel_dir)
        if not norm_dir or not self.rules:
            return False

        ignored, last_deciding_idx = self._evaluate(norm_dir, is_dir=True)
        if not ignored:
            return False

        for rule in self.rules[last_deciding_idx + 1 :]:
            if rule.negated and _rule_could_match_inside(
                rule, norm_dir, case_insensitive=self.case_insensitive
            ):
                return False
        return True


def load_ignore_matcher(
    root: Path,
    ignore_file: Optional[Path] = None,
    case_insensitive: Optional[bool] = None,
) -> IgnoreMatcher:
    """Load an IgnoreMatcher for *root* or an explicit *ignore_file*.

    Args:
        root: Monitored root directory.
        ignore_file: Optional explicit path to an ignore file. When None, loads
            ``root / ".sentinelignore"`` if it exists and is a regular file.
        case_insensitive: Optional override for case-insensitive matching.

    Returns:
        An initialized IgnoreMatcher (empty if no default `.sentinelignore` exists).

    Raises:
        OSError: If an explicit *ignore_file* or an existing `.sentinelignore` cannot be read.
        UnicodeDecodeError: If the loaded ignore file is not valid UTF-8.
    """
    if ignore_file is not None:
        return IgnoreMatcher.from_file(ignore_file, case_insensitive=case_insensitive)

    default_file = Path(root) / ".sentinelignore"
    if default_file.exists() and default_file.is_file():
        return IgnoreMatcher.from_file(default_file, case_insensitive=case_insensitive)

    return IgnoreMatcher(case_insensitive=case_insensitive)
