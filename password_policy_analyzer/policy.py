from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PasswordPolicy:
    # Core
    min_length: int = 12
    max_length: int = 128

    # Optional / legacy composition checks
    require_upper: bool = False
    require_lower: bool = False
    require_digit: bool = False
    require_symbol: bool = False

    # Character handling
    allow_spaces: bool = True
    allow_unicode: bool = True
    normalize_unicode_nfc: bool = False

    # Weak password checks
    local_blocklist_path: Path | None = None
    check_pwned_passwords: bool = False
    # optional online check via k-anonymity

    # Context checks (like username/company name)
    forbid_context_words: bool = True


@dataclass(frozen=True)
class PolicyViolation:
    code: str
    message: str
    help_text: str | None = None


@dataclass(frozen=True)
class PasswordAnalysis:
    is_compliant: bool
    violations: tuple[PolicyViolation, ...] = field(default_factory=tuple)
    suggestions: tuple[str, ...] = field(default_factory=tuple)


def modern_default_policy() -> PasswordPolicy:
    """
    A simple baseline: length-first + optional blocklist.
    Composition rules disabled by default on purpose.
    """
    return PasswordPolicy(min_length=12, max_length=128)


def legacy_strict_policy() -> PasswordPolicy:
    """
    Example of a "legacy enterprise" style policy.
    """
    return PasswordPolicy(
        min_length=12,
        max_length=128,
        require_upper=True,
        require_lower=True,
        require_digit=True,
        require_symbol=True,
    )
