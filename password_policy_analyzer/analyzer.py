from __future__ import annotations

from dataclasses import replace
import string
import unicodedata
from pathlib import Path

from .policy import PasswordPolicy, PolicyViolation, PasswordAnalysis
from .weak_passwords import load_blocklist, check_pwned_passwords_k_anonymity


_SYMBOLS = set(string.punctuation)


def analyze_password(
    password: str,
    policy: PasswordPolicy,
    *,
    context_words: list[str] | None = None,
) -> PasswordAnalysis:
    """
    Returns a structured analysis result.
    This is designed for password *creation/change* flows (detailed feedback is okay).
    """
    context_words = context_words or []

    normalized = _apply_normalization(password, policy)

    violations: list[PolicyViolation] = []
    suggestions: list[str] = []

    violations.extend(_check_length(normalized, policy))
    violations.extend(_check_character_rules(normalized, policy))
    violations.extend(_check_composition(normalized, policy))

    if policy.forbid_context_words and context_words:
        violations.extend(_check_context_words(normalized, context_words))

    violations.extend(_check_blocklist(normalized, policy))
    violations.extend(_check_pwned(normalized, policy))

    # Suggestions (not hard failures)
    suggestions.extend(_general_suggestions(normalized, policy))

    is_ok = len(violations) == 0
    return PasswordAnalysis(
        is_compliant=is_ok,
        violations=tuple(violations),
        suggestions=tuple(suggestions),
    )


def _apply_normalization(password: str, policy: PasswordPolicy) -> str:
    # keep it explicit; do nothing unless enabled
    if policy.normalize_unicode_nfc:
        return unicodedata.normalize("NFC", password)
    return password


def _check_length(password: str, policy: PasswordPolicy) -> list[PolicyViolation]:
    out: list[PolicyViolation] = []

    if len(password) < policy.min_length:
        out.append(
            PolicyViolation(
                code="length_too_short",
                message=f"Password must be at least {policy.min_length} characters.",
                help_text="Long passphrases are usually easier to remember and harder to guess.",
            )
        )

    if len(password) > policy.max_length:
        out.append(
            PolicyViolation(
                code="length_too_long",
                message=f"Password must be at most {policy.max_length} characters.",
                help_text="Rejecting (not truncating) avoids surprising login bugs and performance issues.",
            )
        )

    return out


def _check_character_rules(password: str, policy: PasswordPolicy) -> list[PolicyViolation]:
    out: list[PolicyViolation] = []

    if not policy.allow_spaces and any(ch.isspace() for ch in password):
        out.append(
            PolicyViolation(
                code="spaces_not_allowed",
                message="Spaces are not allowed by this policy.",
                help_text="If you control the system, allowing spaces is generally more user-friendly.",
            )
        )

    if not policy.allow_unicode:
        # Allow only basic ASCII printable characters
        # This is intentionally strict and will flag emojis / non-latin letters.
        for ch in password:
            if ord(ch) > 127:
                out.append(
                    PolicyViolation(
                        code="unicode_not_allowed",
                        message="Unicode characters are not allowed by this policy.",
                        help_text="If possible, allow Unicode to support better passphrases and international users.",
                    )
                )
                break

    return out


def _check_composition(password: str, policy: PasswordPolicy) -> list[PolicyViolation]:
    # These are optional legacy checks; many modern policies avoid forcing them.
    out: list[PolicyViolation] = []

    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(ch in _SYMBOLS for ch in password)

    if policy.require_upper and not has_upper:
        out.append(PolicyViolation("missing_upper", "Add at least one uppercase letter (A–Z)."))
    if policy.require_lower and not has_lower:
        out.append(PolicyViolation("missing_lower", "Add at least one lowercase letter (a–z)."))
    if policy.require_digit and not has_digit:
        out.append(PolicyViolation("missing_digit", "Add at least one digit (0–9)."))
    if policy.require_symbol and not has_symbol:
        out.append(PolicyViolation("missing_symbol", "Add at least one symbol (example: ! or #)."))

    return out


def _check_context_words(password: str, context_words: list[str]) -> list[PolicyViolation]:
    out: list[PolicyViolation] = []
    lowered = password.casefold()

    for word in context_words:
        cleaned = word.strip()
        if not cleaned:
            continue
        if cleaned.casefold() in lowered:
            out.append(
                PolicyViolation(
                    code="contains_context_word",
                    message=f"Password contains a context word: '{cleaned}'.",
                    help_text="Avoid using your name/username/company name inside passwords.",
                )
            )
            break

    return out


def _check_blocklist(password: str, policy: PasswordPolicy) -> list[PolicyViolation]:
    if not policy.local_blocklist_path:
        return []

    path: Path = policy.local_blocklist_path
    if not path.exists():
        return [
            PolicyViolation(
                code="blocklist_missing",
                message=f"Blocklist file not found: {path}",
                help_text="Fix your config or disable blocklist checking.",
            )
        ]

    blocked = load_blocklist(path)
    if password in blocked:
        return [
            PolicyViolation(
                code="blocklisted_password",
                message="This password is in a common/weak password list.",
                help_text="Pick something unique—avoid small edits like adding '1!' to a common word.",
            )
        ]

    return []


def _check_pwned(password: str, policy: PasswordPolicy) -> list[PolicyViolation]:
    if not policy.check_pwned_passwords:
        return []

    try:
        match = check_pwned_passwords_k_anonymity(password)
    except Exception:
        # Realistic behavior: don’t fail closed if the network is down for an educational tool,
        # but be transparent.
        return [
            PolicyViolation(
                code="pwned_check_failed",
                message="Could not complete breach check (network/API error).",
                help_text="Try again later or disable pwned check in your config.",
            )
        ]

    if match.is_pwned:
        return [
            PolicyViolation(
                code="pwned_password",
                message="This password appears in known breach data.",
                help_text=f"Seen {match.breach_count} times in breaches. Choose a different password.",
            )
        ]

    return []


def _general_suggestions(password: str, policy: PasswordPolicy) -> list[str]:
    tips: list[str] = []

    if len(password) < max(14, policy.min_length):
        tips.append("Consider using a longer passphrase (14+ characters) for better security.")

    if password.lower() == password or password.upper() == password:
        tips.append(
            "Mixing words or using a multi-word passphrase can improve strength and memorability."
        )

    tips.append("Use unique passwords per site (a password manager helps).")
    return tips
