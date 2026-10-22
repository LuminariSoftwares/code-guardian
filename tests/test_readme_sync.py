"""The README's check tables and the weight tables in score.py say the same thing: change them together,
and every message the troubleshooting table quotes is one the code really produces."""
import re
from pathlib import Path

from code_guardian import score

ROOT = Path(__file__).resolve().parent.parent
ROW = re.compile(r"^\| `([a-z_]+(?:\.[a-z_]+)*)` \|.*\| (OK|INFO|WARN|FAIL) \| (\d+) \|$")


def readme_rows():
    rows = {}
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m:
            rows[(m.group(1), m.group(2))] = int(m.group(3))
    return rows


def test_every_weight_is_in_the_readme():
    rows = readme_rows()
    for name, table in score.TABLES.items():
        for key, weight in table.items():
            assert rows.get(key) == weight, (name, key, weight, rows.get(key))


def test_every_scored_readme_row_is_in_the_code():
    for key, weight in readme_rows().items():
        if weight:
            assert score.TABLES[score.dimension_of(key[0])].get(key) == weight, key


def test_every_catalogue_code_is_in_the_readme_catalogue():
    from code_guardian import catalogue
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text[text.index("## Check catalogue"):text.index("## Goal contract")]
    for code, entry in catalogue.CATALOGUE.items():
        row = [ln for ln in section.splitlines() if ln.startswith("| `%s` |" % code)]
        assert len(row) == 1, code
        assert entry["fix"].replace("|", "\\|") in row[0], code


def test_troubleshooting_table_quotes_real_messages():
    """The README promises these strings are pinned by tests. Each one has to come from the code (or, for a message
    assembled at run time, from the fragment the code holds), or the promise is empty."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    table = text[text.index("<!-- troubleshooting:start -->"):text.index("<!-- troubleshooting:end -->")]
    source = "\n".join((ROOT / "code_guardian" / name).read_text(encoding="utf-8")
                       for name in ("mcp_server.py", "report.py", "goal.py", "cli.py"))
    for fragment in ("does not exist: %s", "no Python files and no manifests to judge", "PATH is unreadable",
                     "must be a list of strings"):
        assert fragment in source, fragment
    for quoted in ("path does not exist", "no Python files and no manifests to judge", "PATH is unreadable",
                   "entry_points must be a list of strings"):
        assert quoted in table, quoted
