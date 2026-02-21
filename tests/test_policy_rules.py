from pathlib import Path

from password_policy_analyzer.analyzer import analyze_password
from password_policy_analyzer.policy import PasswordPolicy


def test_context_word_violation():
    policy = PasswordPolicy(min_length=8, forbid_context_words=True)
    res = analyze_password("Daniil12345", policy, context_words=["daniil"])
    assert not res.is_compliant
    assert any(v.code == "contains_context_word" for v in res.violations)


def test_composition_rules_enabled():
    policy = PasswordPolicy(
        min_length=8,
        require_upper=True,
        require_lower=True,
        require_digit=True,
        require_symbol=True,
    )

    res = analyze_password("Password1", policy)  # missing symbol
    assert not res.is_compliant
    assert any(v.code == "missing_symbol" for v in res.violations)


def test_missing_blocklist_file_is_reported(tmp_path: Path):
    missing = tmp_path / "does_not_exist.txt"
    policy = PasswordPolicy(min_length=8, local_blocklist_path=missing)

    res = analyze_password("somepassword", policy)
    assert not res.is_compliant
    assert any(v.code == "blocklist_missing" for v in res.violations)
