"""Every module's own --selftest passes when run from the package and prints the counted summary line."""
import re
import subprocess
import sys

import pytest

MODULES = ["finding", "walk", "scanners", "manifests", "score", "goal", "orphans", "works", "complete", "explain", "report", "cli",
           "mcp_server"]


@pytest.mark.parametrize("mod", MODULES)
def test_module_selftest(mod):
    r = subprocess.run([sys.executable, "-m", "code_guardian." + mod, "--selftest"], capture_output=True, text=True,
                       timeout=180)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    last = r.stdout.strip().splitlines()[-1]
    m = re.fullmatch(r"(\w+) selftest: (\d+) checks, (\d+) passed, 0 failed", last)
    assert m and m.group(1) == mod and m.group(2) == m.group(3) and int(m.group(2)) > 0, last
