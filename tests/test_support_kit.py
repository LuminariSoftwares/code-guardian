"""The support kit stays in place: SUPPORT.md exists, blank issues stay off, and the issue forms are valid GitHub
issue forms (parse, every field has an id, the quick-start checkbox is required)."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FORMS = ROOT / ".github" / "ISSUE_TEMPLATE"
FORM_NAMES = ("bug_report.yml", "feature_request.yml")
INPUT_TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}


def load(name):
    return yaml.safe_load((FORMS / name).read_text(encoding="utf-8"))


def test_support_md_exists_and_names_the_contract():
    text = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")
    assert text.startswith("# Support")
    assert "acknowledgement within a day" in text
    assert "private vulnerability reporting" in text


def test_contributing_links_support_md():
    assert "[SUPPORT.md](SUPPORT.md)" in (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


def test_code_of_conduct_exists():
    assert (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8").startswith("# Code of Conduct")


def test_blank_issues_stay_off_and_security_link_is_private_reporting():
    config = load("config.yml")
    assert config["blank_issues_enabled"] is False
    urls = {link["name"]: link["url"] for link in config["contact_links"]}
    assert urls["Security issue"] == "https://github.com/LuminariSoftwares/code-guardian/security/advisories/new"
    assert "Question" in urls
    for link in config["contact_links"]:
        assert set(link) == {"name", "url", "about"}


@pytest.mark.parametrize("name", FORM_NAMES)
def test_issue_form_is_valid(name):
    form = load(name)
    assert form["name"] and form["description"]
    ids = []
    for item in form["body"]:
        assert item["type"] in INPUT_TYPES, item
        assert item.get("id"), item
        ids.append(item["id"])
        if item["type"] != "markdown":
            assert item["attributes"]["label"], item
        else:
            assert item["attributes"]["value"], item
    assert len(ids) == len(set(ids))


def test_bug_form_asks_for_what_support_md_promises():
    form = load("bug_report.yml")
    assert "needs-info" in form["labels"]
    by_id = {item["id"]: item for item in form["body"]}
    assert {"version", "os", "python", "command", "output", "expected", "quick-start"} <= set(by_id)
    for key in ("version", "os", "python", "command", "output", "expected"):
        assert by_id[key]["validations"]["required"] is True, key
    boxes = by_id["quick-start"]["attributes"]["options"]
    assert [b["label"] for b in boxes] == ["I ran the quick start as written"]
    assert boxes[0]["required"] is True


def test_nothing_promises_a_fix_time():
    for path in [ROOT / "SUPPORT.md", *(FORMS / n for n in (*FORM_NAMES, "config.yml"))]:
        text = path.read_text(encoding="utf-8").lower()
        for phrase in ("within a week", "within 48", "within 72", "will be fixed", "fix within"):
            assert phrase not in text, (path.name, phrase)
