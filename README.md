![CI](../../actions/workflows/ci.yml/badge.svg)
# sec-password-policy-analyzer

Educational Python CLI tool that evaluates passwords against a configurable policy.
It focuses on **how password rules are enforced in real systems** (length checks, composition rules, weak-password blocklists),
and provides clear, structured feedback when a password fails validation.

> This project is for learning and demo purposes — it is not a full authentication system.

---

## Features

-  Minimum and maximum length checks
-  Optional character requirements (upper/lower/digit/symbol)
-  Detects weak passwords using a local blocklist
-  Optional breach check via HIBP (k-anonymity range API)
-  Context checks (prevents passwords containing username/company words)
-  Clear error messages + suggestions
-  TOML-based policy configuration

---

## Why this matters (security concepts)

This project demonstrates:

- Password policy enforcement (server-side validation)
- Authentication hardening
- Preventing weak/common credentials
- Safer input handling (e.g., using hidden input in CLI)
- Understanding tradeoffs: **modern “length-first” policies vs legacy composition rules**

---

## Project structure

```text
sec-password-policy-analyzer/
├─ password_policy_analyzer/
│  ├─ __init__.py
│  ├─ __main__.py
│  ├─ cli.py
│  ├─ analyzer.py
│  ├─ policy.py
│  ├─ config.py
│  └─ weak_passwords.py
├─ data/
│  └─ common_passwords_sample.txt
├─ examples/
│  └─ policy.example.toml
└─ tests/
   └─ test_analyzer.py
```

---
## Installation

### Option A: Run locally (editable install)
```bash
pip install -e .
```

Then run:
```bash
password-policy-analyzer
```

### Option B: Run as a module (no script required)
```bas
python -m password_policy_analyzer
```

---
## Usage
## 1) Default policy (length-first)
```bash 
password-policy-analyzer
```
> The tool will prompt for a password using hidden input (won’t show what you type).

## 2) Use a config file (TOML)
```bash
password-policy-analyzer --config examples/policy.example.toml
```

## 3) Forbid context words (username, company, etc.)
```bash
password-policy-analyzer --config examples/policy.example.toml --context daniil --context pecs
```

## 4) Read password from stdin (use carefully)
```bash
echo "SomePasswordHere" | password-policy-analyzer --password-stdin
```
> Warning: stdin/password piping can leak secrets in shell history/logs. Use only for testing.

---
## Example output

If the password fails:
```Plain text
❌ Password is NOT compliant.

Violations:
- [length_too_short] Password must be at least 12 characters.
    ↳ Long passphrases are usually easier to remember and harder to guess.

Suggestions:
- Consider using a longer passphrase (14+ characters) for better security.
- Use unique passwords per site (a password manager helps).
```

---
## Configuration
Example: examples/policy.example.toml
```TOML
[policy]
min_length = 12
max_length = 128

require_upper = false
require_lower = false
require_digit = false
require_symbol = false

allow_spaces = true
allow_unicode = true
normalize_unicode_nfc = false

local_blocklist_path = "data/common_passwords_sample.txt"
check_pwned_passwords = false

forbid_context_words = true
```
### Notes
- Composition rules are optional and disabled by default (many modern policies prefer length + blocklist).
- The blocklist sample is intentionally small; you can replace it with a larger list.

---
## Exit codes

Designed for automation / CI:

- 0	Password is compliant
- 2	At least one policy violation found

---
## Tests
```bash
pip install pytest
pytest
```
---
## Limitations

- This tool does not manage users, login sessions, hashing, or authentication storage.
- The breach check depends on network availability and is optional.
- Detection rules are intentionally transparent for learning (not for adversarial environments).
- 

---
## Why content-based checks matter

- Many real systems reject weak passwords at creation time to reduce account takeover risk.
- This tool demonstrates common policy checks and their tradeoffs (length-first vs strict composition rules).

---
## Development

```bash
pip install -e . pytest pytest-cov ruff
ruff check .
ruff format .
pytest --cov=password_policy_analyzer --cov-report=term-missing
```
