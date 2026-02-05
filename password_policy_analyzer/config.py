from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import tomllib

from .policy import PasswordPolicy


def load_policy_from_toml(path: Path) -> PasswordPolicy:
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    raw_policy = data.get("policy", {})
    if not isinstance(raw_policy, dict):
        raise ValueError("Invalid config: [policy] must be a table/object")

    # Convert strings to Path where needed
    if "local_blocklist_path" in raw_policy and raw_policy["local_blocklist_path"]:
        raw_policy["local_blocklist_path"] = Path(raw_policy["local_blocklist_path"])

    # Filter unknown keys to avoid confusing errors
    allowed_keys = set(asdict(PasswordPolicy()).keys())
    cleaned = {k: v for k, v in raw_policy.items() if k in allowed_keys}

    return PasswordPolicy(**cleaned)
