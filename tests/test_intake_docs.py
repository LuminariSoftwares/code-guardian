"""Repo intake documentation stays true: every rule is documented, the credit line is present, the hash-list format is
documented and the miss form is a valid issue form."""
from pathlib import Path

import yaml

from code_guardian import intake, intake_rules

ROOT = Path(__file__).resolve().parent.parent
CREDIT = ("Check categories inspired by public write-ups on repo-borne malware (including Carter Perez's erinyes research); "
          "implemented independently.")


def doc():
    return (ROOT / "docs" / "intake.md").read_text(encoding="utf-8")


def test_every_rule_is_in_the_docs_table_with_a_title():
    text = doc()
    for rule, info in intake_rules.RULES.items():
        assert "`%s`" % rule in text, rule
        assert info["title"] in text, rule


def test_the_docs_name_no_rule_that_does_not_exist():
    import re
    named = set(re.findall(r"`((?:hook|hidden|text|binary|exec|lure|hollow|hash)\.[a-z_]+)`", doc()))
    assert named <= set(intake_rules.RULES), named - set(intake_rules.RULES)


def test_credit_line_in_the_docs_and_the_readme():
    assert CREDIT in doc()
    assert CREDIT in (ROOT / "README.md").read_text(encoding="utf-8")


def test_docs_cover_the_hash_format_the_stars_token_and_the_advisory_model():
    text = doc()
    for needle in ("known_bad_hashes.json", "CODE_GUARDIAN_BAD_HASHES", "CODE_GUARDIAN_GITHUB_TOKEN", "not a guarantee",
                   "Advisory first", "tests/intake_cases", "SARIF", "read-only copy"):
        assert needle in text, needle


def test_the_shipped_hash_list_documents_its_format():
    import json
    assert "SHA-256" in json.loads(intake.HASH_FILE.read_text(encoding="utf-8"))["format"]


def test_miss_form_is_a_valid_issue_form():
    form = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / "intake_miss.yml").read_text(encoding="utf-8"))
    assert form["name"] and form["description"]
    ids = [i["id"] for i in form["body"]]
    assert len(ids) == len(set(ids)) and {"kind", "rule", "synthetic"} <= set(ids)
    assert all(i.get("id") for i in form["body"])
    assert "real malware" in yaml.safe_dump(form).lower(), "the form must tell people not to paste a real sample"
