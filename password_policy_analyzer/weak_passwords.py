from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import urllib.request


def load_blocklist(path: Path) -> set[str]:
    """
    Loads a newline-delimited password list.
    Keep it dumb and predictable: exact matches, UTF-8, ignore empty lines.
    """
    blocked: set[str] = set()
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            item = line.strip()
            if item:
                blocked.add(item)
    return blocked


@dataclass(frozen=True)
class PwnedPasswordMatch:
    is_pwned: bool
    breach_count: int = 0


def check_pwned_passwords_k_anonymity(password: str, timeout_s: float = 3.0) -> PwnedPasswordMatch:
    """
    Queries HIBP Pwned Passwords Range API using k-anonymity.
    Sends only SHA1 prefix (first 5 chars), matches suffix locally.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "password-policy-analyzer/0.1.0"},
    )

    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = resp.read().decode("utf-8", errors="replace")

    for line in body.splitlines():
        # format: HASH_SUFFIX:COUNT
        if ":" not in line:
            continue
        remote_suffix, count_str = line.split(":", 1)
        if remote_suffix.strip().upper() == suffix:
            try:
                return PwnedPasswordMatch(is_pwned=True, breach_count=int(count_str.strip()))
            except ValueError:
                return PwnedPasswordMatch(is_pwned=True, breach_count=0)

    return PwnedPasswordMatch(is_pwned=False, breach_count=0)
