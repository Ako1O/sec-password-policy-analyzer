from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .analyzer import analyze_password
from .config import load_policy_from_toml
from .policy import modern_default_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="password-policy-analyzer",
        description="Evaluate a password against a configurable password policy (educational).",
    )
    p.add_argument("--config", type=Path, help="Path to TOML config file.")
    p.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read password from stdin (careful: may leak in shell history/pipes).",
    )
    p.add_argument(
        "--context",
        action="append",
        default=[],
        help="Context words to forbid (e.g., username, company name). Can be used multiple times.",
    )
    return p


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        return sys.stdin.read().rstrip("\n")
    return getpass.getpass("Enter a password to evaluate: ")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    policy = modern_default_policy()
    if args.config:
        policy = load_policy_from_toml(args.config)

    password = _read_password(args)
    result = analyze_password(password, policy, context_words=args.context)

    if result.is_compliant:
        print("✅ Password is compliant with the policy.")
    else:
        print("❌ Password is NOT compliant.")
        print()
        print("Violations:")
        for v in result.violations:
            print(f"- [{v.code}] {v.message}")
            if v.help_text:
                print(f"    ↳ {v.help_text}")

    if result.suggestions:
        print()
        print("Suggestions:")
        for tip in result.suggestions:
            print(f"- {tip}")

    return 0 if result.is_compliant else 2
