from pathlib import Path

from password_policy_analyzer.analyzer import analyze_password
from password_policy_analyzer.policy import PasswordPolicy


def test_too_short():
    policy = PasswordPolicy(min_length=12)
    res = analyze_password("short", policy)
    assert not res.is_compliant
    assert any(v.code == "length_too_short" for v in res.violations)


def test_blocklisted_password(tmp_path: Path):
    blocklist = tmp_path / "block.txt"
    blocklist.write_text("password\n123456\n", encoding="utf-8")

    policy = PasswordPolicy(min_length=8, local_blocklist_path=blocklist)
    res = analyze_password("password", policy)
    assert not res.is_compliant
    assert any(v.code == "blocklisted_password" for v in res.violations)


def test_good_passphrase():
    policy = PasswordPolicy(min_length=12)
    res = analyze_password("Correct Horse Battery Staple", policy)
    assert res.is_compliant


def test_short_password_scores_low():
    policy = PasswordPolicy(min_length=12)
    res = analyze_password("short", policy)
    assert res.rating == "Weak"
    assert res.score < 40


def test_long_varied_password_scores_high():
    policy = PasswordPolicy(min_length=12)
    res = analyze_password("Tr0ub4dor&3xtra!", policy)
    assert res.rating in ("Good", "Strong")
    assert res.score >= 60


def test_blocklisted_password_is_penalized_in_score(tmp_path: Path):
    blocklist = tmp_path / "block.txt"
    blocklist.write_text("password\n", encoding="utf-8")

    policy = PasswordPolicy(min_length=1, local_blocklist_path=blocklist)
    res = analyze_password("password", policy)
    assert not res.is_compliant
    assert res.score <= 30
