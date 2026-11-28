from __future__ import annotations

import dataclasses
import fnmatch
from pathlib import PurePosixPath

from ..core.models import ChangeRecord, ScanResult

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Any path containing one of these folder segments is HIGH.
_HIGH_DIRS = (
    ".github/workflows/", ".github/actions/", ".circleci/", ".gitlab/",
    "deploy/", "deployment/", "deployments/", "ci/",
)

# Exact (lower-case) file names that are HIGH.
_HIGH_NAMES = frozenset({
    # container / compose
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    # CI definitions
    "action.yml", "action.yaml", "jenkinsfile", ".gitlab-ci.yml", ".travis.yml",
    "appveyor.yml", "azure-pipelines.yml", "cloudbuild.yaml",
    # dependency manifests and lockfiles
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lockb", "pyproject.toml", "setup.py", "setup.cfg",
    "pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock",
    "constraints.txt", "gemfile", "gemfile.lock", "cargo.toml", "cargo.lock",
    "go.mod", "go.sum", "composer.json", "composer.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "gradle.lockfile", "packages.lock.json",
    # package-manager configuration (can redirect installs to a rogue registry)
    ".npmrc", ".pypirc", "pip.conf", "nuget.config",
    # Sentinel itself: editing ignore rules can hide tampering
    ".sentinelignore",
})

# Glob patterns (matched against the lower-case file name) that are HIGH.
_HIGH_GLOBS = (
    "dockerfile.*", "*.dockerfile", "docker-compose*.yml", "docker-compose*.yaml",
    "requirements*.txt",
    "deploy*.sh", "deploy*.ps1", "deploy*.bat", "deploy*.cmd", "deploy*.py",
    "release*.sh", "release*.ps1", "publish*.sh", "publish*.ps1",
)

_MEDIUM_SUFFIXES = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue",
    ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd", ".vbs",
    ".exe", ".dll", ".sys", ".msi", ".jar", ".so",
    ".java", ".cs", ".go", ".rs", ".c", ".cpp", ".h",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".sql",
})


def _normalise(path: str) -> str:
    text = path.replace("\\", "/").lower()
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _is_high(path: str) -> bool:
    norm = _normalise(path)
    name = PurePosixPath(norm).name
    padded = "/" + norm
    if any("/" + marker in padded for marker in _HIGH_DIRS):
        return True
    if name in _HIGH_NAMES:
        return True
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in _HIGH_GLOBS)


def _is_medium(path: str) -> bool:
    norm = _normalise(path)
    pure = PurePosixPath(norm)
    name = pure.name
    return (
        pure.suffix in _MEDIUM_SUFFIXES
        or name.startswith(".env")
        or name == "makefile"
    )


def classify_change(change: ChangeRecord) -> str:
    """Return ``"LOW"``, ``"MEDIUM"`` or ``"HIGH"`` for one change record."""
    paths = [p for p in (change.path, change.old_path, change.new_path) if p]
    if any(_is_high(p) for p in paths):
        return HIGH
    if any(_is_medium(p) for p in paths):
        return MEDIUM
    return LOW


# Contract section 10.4 calls this function classify_severity, section 8.3 calls it
# classify_change. Both names are provided so either caller works.
classify_severity = classify_change


def apply_severity(result: ScanResult) -> ScanResult:
    """Return a copy of ``result`` with ``severity`` set on every change."""
    changes = [
        dataclasses.replace(change, severity=classify_change(change))
        for change in result.changes
    ]
    return dataclasses.replace(result, changes=changes)