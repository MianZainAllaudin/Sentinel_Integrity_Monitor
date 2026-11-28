"""Unit tests for sentinel.core.ignore."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from sentinel.core.ignore import IgnoreMatcher, load_ignore_matcher


class TestIgnoreParsingAndFormatting(unittest.TestCase):
    """Tests for comment, blank-line, escape, whitespace, BOM, and CRLF handling."""

    def test_blank_lines_and_comments_are_ignored(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                "",
                "   ",
                "\t",
                "# comment line",
                "# another comment with *.log",
                "*.tmp",
            ],
            case_insensitive=False,
        )

        self.assertEqual(len(matcher.rules), 1)
        self.assertFalse(matcher.is_ignored("# comment line"))
        self.assertFalse(matcher.is_ignored("   "))
        self.assertTrue(matcher.is_ignored("cache.tmp"))
        self.assertFalse(matcher.is_ignored("app.log"))

    def test_escaped_hash_and_bang_match_literally(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                r"\#notes.txt",
                r"\!important.txt",
            ],
            case_insensitive=False,
        )

        self.assertTrue(matcher.is_ignored("#notes.txt"))
        self.assertTrue(matcher.is_ignored("sub/#notes.txt"))
        self.assertFalse(matcher.is_ignored("notes.txt"))

        self.assertTrue(matcher.is_ignored("!important.txt"))
        self.assertTrue(matcher.is_ignored("docs/!important.txt"))
        self.assertFalse(matcher.is_ignored("important.txt"))
        self.assertFalse(matcher.rules[1].negated)

    def test_trailing_unescaped_spaces_trimmed_vs_escaped_trailing_space(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                "trimmed.txt   ",
                r"space_end.txt\ ",
                r"single_space.txt\   ",
                r"double_backslash_space.txt\\ ",
            ],
            case_insensitive=False,
        )

        self.assertTrue(matcher.is_ignored("trimmed.txt"))
        self.assertFalse(matcher.is_ignored("trimmed.txt   "))

        self.assertTrue(matcher.is_ignored("space_end.txt "))
        self.assertFalse(matcher.is_ignored("space_end.txt"))

        self.assertTrue(matcher.is_ignored("single_space.txt "))
        self.assertFalse(matcher.is_ignored("single_space.txt   "))
        self.assertFalse(matcher.is_ignored("single_space.txt"))

        # Even number of backslashes before a trailing space leaves the space unescaped,
        # so the trailing space is stripped during rule parsing.
        self.assertEqual(matcher.rules[3].pattern, r"double_backslash_space.txt\\")
        self.assertFalse(matcher.is_ignored("double_backslash_space.txt "))

    def test_utf8_bom_and_crlf_handling(self) -> None:
        matcher_from_lines = IgnoreMatcher.from_lines(
            [
                "\ufeff# leading BOM comment\r\n",
                "\r\n",
                "*.log\r\n",
                "build/\r\n",
            ],
            case_insensitive=False,
        )
        self.assertTrue(matcher_from_lines.is_ignored("app.log"))
        self.assertTrue(matcher_from_lines.is_ignored("build/output.bin"))

        matcher_bom_rule = IgnoreMatcher.from_lines(["\ufeff*.pyc\r\n"], case_insensitive=False)
        self.assertTrue(matcher_bom_rule.is_ignored("mod.pyc"))

        with tempfile.TemporaryDirectory() as tmp_dir:
            ignore_path = Path(tmp_dir) / ".sentinelignore"
            ignore_path.write_bytes(b"\xef\xbb\xbf# BOM header\r\n*.log\r\ndist/\r\n")
            matcher_from_file = IgnoreMatcher.from_file(ignore_path, case_insensitive=False)

        self.assertTrue(matcher_from_file.is_ignored("server.log"))
        self.assertTrue(matcher_from_file.is_ignored("dist/bundle.js"))
        self.assertFalse(matcher_from_file.is_ignored("src/main.py"))


class TestIgnorePatternMatching(unittest.TestCase):
    """Tests for directory rules, globs, anchoring, **, char classes, negations, and casing."""

    def test_directory_rules_match_dirs_and_descendants_but_not_regular_files(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                "node_modules/",
                "__pycache__/",
                "dist/",
            ],
            case_insensitive=False,
        )

        self.assertTrue(matcher.is_ignored("node_modules", is_dir=True))
        self.assertTrue(matcher.is_ignored("frontend/node_modules", is_dir=True))
        self.assertTrue(matcher.is_ignored("node_modules/pkg/index.js", is_dir=False))
        self.assertFalse(matcher.is_ignored("node_modules", is_dir=False))
        self.assertFalse(matcher.is_ignored("frontend/node_modules", is_dir=False))

        self.assertTrue(matcher.is_ignored("__pycache__", is_dir=True))
        self.assertTrue(matcher.is_ignored("src/__pycache__/x.pyc", is_dir=False))
        self.assertFalse(matcher.is_ignored("__pycache__", is_dir=False))

        self.assertTrue(matcher.is_ignored("dist", is_dir=True))
        self.assertTrue(matcher.is_ignored("dist/app.js", is_dir=False))
        self.assertFalse(matcher.is_ignored("dist", is_dir=False))

    def test_unanchored_basename_globs(self) -> None:
        matcher = IgnoreMatcher.from_lines(["*.pyc", ".env"], case_insensitive=False)

        self.assertTrue(matcher.is_ignored("root.pyc"))
        self.assertTrue(matcher.is_ignored("a/b/c/nested.pyc"))
        self.assertFalse(matcher.is_ignored("foo.pyc2"))
        self.assertFalse(matcher.is_ignored("pyc"))
        self.assertFalse(matcher.is_ignored("foo.pyc_dir/bar.py"))

        self.assertTrue(matcher.is_ignored(".env"))
        self.assertTrue(matcher.is_ignored("deploy/prod/.env"))
        self.assertFalse(matcher.is_ignored(".env.local"))
        self.assertFalse(matcher.is_ignored("local.env"))

    def test_anchored_patterns_and_wildcards_never_cross_slash(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                "/build/",
                "src/*.log",
                "src/a?c.txt",
            ],
            case_insensitive=False,
        )

        self.assertTrue(matcher.is_ignored("build", is_dir=True))
        self.assertTrue(matcher.is_ignored("build/artifact.o", is_dir=False))
        self.assertFalse(matcher.is_ignored("build", is_dir=False))
        self.assertFalse(matcher.is_ignored("sub/build", is_dir=True))
        self.assertFalse(matcher.is_ignored("sub/build/artifact.o", is_dir=False))

        self.assertTrue(matcher.is_ignored("src/app.log"))
        self.assertTrue(matcher.is_ignored("src/.log"))
        self.assertFalse(matcher.is_ignored("src/nested/app.log"))
        self.assertFalse(matcher.is_ignored("other/src/app.log"))

        self.assertTrue(matcher.is_ignored("src/abc.txt"))
        self.assertFalse(matcher.is_ignored("src/a/c.txt"))
        self.assertFalse(matcher.is_ignored("src/ac.txt"))
        self.assertFalse(matcher.is_ignored("src/abbc.txt"))

    def test_double_star_patterns_including_zero_directory_match(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                "**/secret.txt",
                "src/**/test_*.py",
                "logs/**",
            ],
            case_insensitive=False,
        )

        self.assertTrue(matcher.is_ignored("secret.txt"))
        self.assertTrue(matcher.is_ignored("a/secret.txt"))
        self.assertTrue(matcher.is_ignored("a/b/c/secret.txt"))
        self.assertFalse(matcher.is_ignored("a/mysecret.txt"))

        self.assertTrue(matcher.is_ignored("src/test_a.py"))
        self.assertTrue(matcher.is_ignored("src/unit/test_a.py"))
        self.assertTrue(matcher.is_ignored("src/unit/core/test_scanner.py"))
        self.assertFalse(matcher.is_ignored("test_a.py"))
        self.assertFalse(matcher.is_ignored("other/src/test_a.py"))

        self.assertTrue(matcher.is_ignored("logs/app.log"))
        self.assertTrue(matcher.is_ignored("logs/2026/11/app.log"))
        self.assertFalse(matcher.is_ignored("logs", is_dir=True))
        self.assertFalse(matcher.is_ignored("other/logs/app.log"))

    def test_character_classes_exclude_slash(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                "file[0-9].txt",
                "file[!a].txt",
                "dir[!x]name",
            ],
            case_insensitive=False,
        )

        self.assertTrue(matcher.is_ignored("file0.txt"))
        self.assertTrue(matcher.is_ignored("nested/file9.txt"))
        self.assertFalse(matcher.is_ignored("filea.txt"))
        self.assertFalse(matcher.is_ignored("file10.txt"))
        self.assertFalse(matcher.is_ignored("file/.txt"))

        self.assertTrue(matcher.is_ignored("fileb.txt"))
        self.assertTrue(matcher.is_ignored("file7.txt"))
        self.assertFalse(matcher.is_ignored("filea.txt"))
        self.assertFalse(matcher.is_ignored("file/.txt"))

        self.assertTrue(matcher.is_ignored("diryname"))
        self.assertFalse(matcher.is_ignored("dirxname"))
        self.assertFalse(matcher.is_ignored("dir/name"))

    def test_negation_last_matching_rule_wins_and_can_prune_directory(self) -> None:
        matcher = IgnoreMatcher.from_lines(
            [
                "*.log",
                "!important.log",
                "build/",
                "dist/",
                "!build/keep.txt",
            ],
            case_insensitive=False,
        )

        self.assertTrue(matcher.is_ignored("app.log"))
        self.assertFalse(matcher.is_ignored("important.log"))
        self.assertFalse(matcher.is_ignored("logs/important.log"))

        self.assertTrue(matcher.is_ignored("build", is_dir=True))
        self.assertTrue(matcher.is_ignored("build/drop.txt"))
        self.assertFalse(matcher.is_ignored("build/keep.txt"))

        self.assertFalse(matcher.can_prune_directory("build"))
        self.assertTrue(matcher.can_prune_directory("dist"))
        self.assertFalse(matcher.can_prune_directory("src"))

        later_ignore_wins = IgnoreMatcher.from_lines(
            [
                "!important.log",
                "*.log",
                "!build/keep.txt",
                "build/",
            ],
            case_insensitive=False,
        )
        self.assertTrue(later_ignore_wins.is_ignored("important.log"))
        self.assertTrue(later_ignore_wins.is_ignored("build/keep.txt"))
        self.assertTrue(later_ignore_wins.can_prune_directory("build"))

    def test_case_sensitive_vs_case_insensitive_matching(self) -> None:
        patterns = ["*.LOG", "Build/", "!build/Keep.txt"]

        cs_matcher = IgnoreMatcher.from_lines(patterns, case_insensitive=False)
        self.assertTrue(cs_matcher.is_ignored("app.LOG"))
        self.assertFalse(cs_matcher.is_ignored("app.log"))
        self.assertTrue(cs_matcher.is_ignored("Build/out.bin"))
        self.assertFalse(cs_matcher.is_ignored("build/out.bin"))
        self.assertTrue(cs_matcher.can_prune_directory("Build"))

        ci_matcher = IgnoreMatcher.from_lines(patterns, case_insensitive=True)
        self.assertTrue(ci_matcher.is_ignored("app.LOG"))
        self.assertTrue(ci_matcher.is_ignored("app.log"))
        self.assertTrue(ci_matcher.is_ignored("App.Log"))
        self.assertTrue(ci_matcher.is_ignored("build/out.bin"))
        self.assertTrue(ci_matcher.is_ignored("BUILD/out.bin"))
        self.assertFalse(ci_matcher.is_ignored("Build/keep.txt"))
        self.assertFalse(ci_matcher.can_prune_directory("Build"))


class TestLoadIgnoreMatcherAndRepoIgnore(unittest.TestCase):
    """Tests for load_ignore_matcher and the repository's real .sentinelignore."""

    def test_load_ignore_matcher_missing_default_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            matcher = load_ignore_matcher(root, case_insensitive=False)

        self.assertEqual(matcher.rules, ())
        self.assertFalse(matcher.is_ignored("node_modules/a.js"))
        self.assertFalse(matcher.is_ignored("app.log"))

    def test_load_ignore_matcher_existing_default_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / ".sentinelignore").write_text("*.tmp\ncache/\n", encoding="utf-8")
            matcher = load_ignore_matcher(root, case_insensitive=False)

        self.assertTrue(matcher.is_ignored("data.tmp"))
        self.assertTrue(matcher.is_ignored("cache/item.bin"))
        self.assertFalse(matcher.is_ignored("src/main.py"))

    def test_load_ignore_matcher_explicit_missing_raises_oserror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            missing_file = root / "missing.sentinelignore"
            with self.assertRaises(OSError):
                load_ignore_matcher(root, ignore_file=missing_file, case_insensitive=False)

    def test_load_ignore_matcher_explicit_file_overrides_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / ".sentinelignore").write_text("*.log\n", encoding="utf-8")
            explicit = root / "custom.ignore"
            explicit.write_text("*.bak\n", encoding="utf-8")

            matcher = load_ignore_matcher(root, ignore_file=explicit, case_insensitive=False)

        self.assertTrue(matcher.is_ignored("old.bak"))
        self.assertFalse(matcher.is_ignored("app.log"))

    def test_real_repo_sentinelignore_rules(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        sentinelignore_path = repo_root / ".sentinelignore"
        self.assertTrue(
            sentinelignore_path.is_file(),
            f"Expected repository .sentinelignore at {sentinelignore_path}",
        )

        matcher = load_ignore_matcher(repo_root, case_insensitive=False)

        self.assertTrue(matcher.is_ignored("node_modules/a.js"))
        self.assertTrue(matcher.is_ignored("src/__pycache__/x.pyc"))
        self.assertTrue(matcher.is_ignored(".env"))
        self.assertTrue(matcher.is_ignored("app.log"))
        self.assertTrue(matcher.is_ignored("dist/bundle.js"))
        self.assertTrue(matcher.is_ignored("build/out.o"))
        self.assertFalse(matcher.is_ignored("src/main.py"))
        self.assertFalse(matcher.is_ignored("node_modules", is_dir=False))


if __name__ == "__main__":
    unittest.main()
