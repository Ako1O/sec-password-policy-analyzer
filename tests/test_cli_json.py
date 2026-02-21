import json
import subprocess
import sys


def test_cli_json_output():
    cmd = [sys.executable, "-m", "password_policy_analyzer", "--format", "json", "--password-stdin"]
    proc = subprocess.run(cmd, input="short\n", text=True, capture_output=True)
    assert proc.returncode == 2

    data = json.loads(proc.stdout)
    assert data["is_compliant"] is False
    assert any(v["code"] == "length_too_short" for v in data["violations"])