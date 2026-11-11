"""Repo intake, core: quarantine (item 8), the known-bad hash list (item 7), confidence, verdict, JSON and SARIF
(item 10). Written before intake.py existed; red first."""
import hashlib
import json
import os
import stat

import pytest

from code_guardian import intake
from intake_helpers import mk, of

JSON_KEYS = {"rule", "confidence", "file", "line", "match", "summary", "why", "false_positives"}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def test_the_scan_reads_a_read_only_copy_never_the_clone(tmp_path, monkeypatch):
    src = mk(tmp_path / "clone", {"a.py": "x = 1\n", "d/b.txt": "hello\n"})
    seen = {}
    real = intake._analyse

    def spy(copy_root, manifest, *args, **kw):
        seen["root"] = copy_root
        seen["same_as_clone"] = os.path.realpath(copy_root) == os.path.realpath(src)
        seen["writable"] = [rel for rel in manifest
                            if os.stat(os.path.join(copy_root, *rel.split("/"))).st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)]
        return real(copy_root, manifest, *args, **kw)

    monkeypatch.setattr(intake, "_analyse", spy)
    res = intake.scan(src)
    assert seen["same_as_clone"] is False and seen["writable"] == []
    assert not os.path.exists(seen["root"]), "the copy is removed afterwards"
    assert res["quarantine"] == {"scanned": "read-only copy", "files": 2, "symlinks_skipped": 0, "truncated": 0}


def test_the_clone_is_left_exactly_as_it_was(tmp_path):
    src = mk(tmp_path / "clone", {"a.py": "x = 1\n", "d/b.txt": "hi\n"})

    def snap():
        return sorted((dp, fn, os.stat(os.path.join(dp, fn)).st_mtime_ns, os.stat(os.path.join(dp, fn)).st_mode)
                      for dp, _, fns in os.walk(src) for fn in fns)

    before = snap()
    intake.scan(src)
    assert snap() == before


def test_a_symlink_out_of_the_clone_is_not_followed(tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"MZ" + b"\0" * 200)
    src = mk(tmp_path / "clone", {"a.py": "x = 1\n"})
    os.symlink(outside, os.path.join(src, "link.png"))
    res = intake.scan(src)
    assert res["quarantine"]["symlinks_skipped"] == 1
    assert res["findings"] == []
    assert any(s["file"] == "link.png" and s["reason"] == "symlink" for s in res["skipped"])


def test_a_file_is_not_a_folder(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("x=1\n")
    with pytest.raises(intake.UsageError):
        intake.scan(str(f))
    with pytest.raises(intake.UsageError):
        intake.scan(str(tmp_path / "missing"))


# ---- the known-bad hash list ---------------------------------------------------------------------------------------

def test_the_shipped_hash_list_is_empty_and_documented():
    assert intake.load_bad_hashes() == {}
    shipped = json.load(open(os.path.join(os.path.dirname(intake.__file__), "data", "known_bad_hashes.json"), encoding="utf-8"))
    assert shipped["sha256"] == {} and shipped["schema_version"] == 1 and "format" in shipped


def test_a_hash_match_forces_a_malicious_verdict(tmp_path):
    payload = b"synthetic benign bytes standing in for a known-bad sample\n"
    src = mk(tmp_path / "clone", {"docs/notes.txt": payload, "a.py": "x = 1\n"})
    lst = tmp_path / "bad.json"
    lst.write_text(json.dumps({"schema_version": 1, "sha256": {_sha(payload).upper(): "synthetic test sample"}}))
    res = intake.scan(src, bad_hashes=str(lst))
    hit = of(res, "hash.known_bad")
    assert len(hit) == 1 and hit[0]["file"] == "docs/notes.txt" and hit[0]["confidence"] == "high"
    assert "synthetic test sample" in hit[0]["match"] and _sha(payload) in hit[0]["match"]
    assert res["verdict"]["level"] == "malicious"
    assert intake.exit_code(res) == 1
    assert intake.scan(src)["verdict"]["level"] == "nothing_flagged"


def test_hash_list_from_the_environment_is_merged(tmp_path, monkeypatch):
    payload = b"another synthetic stand-in\n"
    src = mk(tmp_path / "clone", {"x.dat": payload})
    lst = tmp_path / "mine.json"
    lst.write_text(json.dumps({"schema_version": 1, "sha256": {_sha(payload): "mine"}}))
    monkeypatch.setenv("CODE_GUARDIAN_BAD_HASHES", str(lst))
    assert intake.scan(src)["verdict"]["level"] == "malicious"


@pytest.mark.parametrize("body", ["not json", '{"schema_version": 1, "sha256": {"abc": "short"}}',
                                  '{"schema_version": 9, "sha256": {}}', '[]'])
def test_a_bad_hash_list_stops_the_scan_with_a_usage_error(tmp_path, body):
    lst = tmp_path / "bad.json"
    lst.write_text(body)
    with pytest.raises(intake.UsageError):
        intake.load_bad_hashes(str(lst))


# ---- confidence, verdict, output -----------------------------------------------------------------------------------

def _f(conf):
    return {"rule": "x.y", "confidence": conf, "file": "f", "line": 1, "match": "m", "summary": "s",
            "why": "w", "false_positives": "fp"}


def test_verdict_levels_follow_the_highest_confidence_and_are_always_advisory():
    assert intake.verdict_of([])["level"] == "nothing_flagged"
    assert intake.verdict_of([_f("low")])["level"] == "weak_signals"
    assert intake.verdict_of([_f("low"), _f("medium")])["level"] == "review"
    assert intake.verdict_of([_f("medium"), _f("high")])["level"] == "suspicious"
    assert intake.verdict_of([_f("high")], known_bad=True)["level"] == "malicious"
    for fs in ([_f("low")], [_f("medium")], [_f("high")]):
        v = intake.verdict_of(fs)
        assert v["trust"] == "advisory" and "not proof" in v["text"].lower()


def test_no_checks_fired_says_it_is_not_a_guarantee(tmp_path):
    res = intake.scan(mk(tmp_path / "c", {"a.py": "x = 1\n"}))
    text = intake.render(res)
    assert res["verdict"]["level"] == "nothing_flagged"
    assert "not a guarantee" in res["verdict"]["text"].lower()
    assert "not a guarantee" in text.lower()
    assert res["verdict"]["trust"] == "advisory"


def test_json_has_the_finding_shape_and_names_what_was_not_checked(tmp_path):
    payload = b"synthetic stand-in\n"
    src = mk(tmp_path / "c", {"a.dat": payload, "node_modules/x/index.js": "x\n"})
    lst = tmp_path / "b.json"
    lst.write_text(json.dumps({"schema_version": 1, "sha256": {_sha(payload): "t"}}))
    doc = json.loads(intake.to_json(intake.scan(src, bad_hashes=str(lst))))
    assert doc["schema_version"] == 1 and doc["trust"] == "advisory" and doc["tool"] == "code-guardian intake"
    assert set(doc["findings"][0]) == JSON_KEYS
    assert {"dir": "node_modules", "reason": "not scanned"} in doc["skipped_dirs"]


def test_sarif_has_a_rule_a_location_and_the_matched_text_per_finding(tmp_path):
    payload = b"synthetic stand-in\n"
    src = mk(tmp_path / "c", {"a.dat": payload})
    lst = tmp_path / "b.json"
    lst.write_text(json.dumps({"schema_version": 1, "sha256": {_sha(payload): "t"}}))
    res = intake.scan(src, bad_hashes=str(lst))
    sarif = intake.to_sarif(res)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "code-guardian"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "hash.known_bad" in rule_ids
    r = run["results"][0]
    assert r["ruleId"] == "hash.known_bad" and r["level"] == "error"
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.dat"
    assert r["properties"]["confidence"] == "high" and r["message"]["text"]
    assert run["properties"]["verdict"]["level"] == "malicious"
    assert r["partialFingerprints"]["intakeFingerprint/v1"]


def test_sarif_levels_map_confidence():
    res = {"findings": [dict(_f("high"), rule="hash.known_bad"), dict(_f("medium"), rule="hook.npm_lifecycle"),
                        dict(_f("low"), rule="hidden.long_line")],
           "verdict": intake.verdict_of([_f("high")]), "version": "t"}
    levels = [r["level"] for r in intake.to_sarif(res)["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_sarif_validates_against_the_official_schema(tmp_path):
    schema_path = os.environ.get("CODE_GUARDIAN_SARIF_SCHEMA")
    jsonschema = pytest.importorskip("jsonschema")
    if not schema_path:
        pytest.skip("set CODE_GUARDIAN_SARIF_SCHEMA to the SARIF 2.1.0 schema file (the CI sarif job does)")
    payload = b"synthetic stand-in\n"
    src = mk(tmp_path / "c", {"a.dat": payload})
    lst = tmp_path / "b.json"
    lst.write_text(json.dumps({"schema_version": 1, "sha256": {_sha(payload): "t"}}))
    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    errors = list(jsonschema.Draft4Validator(schema).iter_errors(intake.to_sarif(intake.scan(src, bad_hashes=str(lst)))))
    assert errors == [], [e.message for e in errors[:3]]


def test_the_cli_exit_codes_and_formats(tmp_path, capsys):
    from code_guardian import cli
    clean = mk(tmp_path / "clean", {"a.py": "x = 1\n"})
    payload = b"synthetic stand-in\n"
    bad = mk(tmp_path / "bad", {"a.dat": payload})
    lst = tmp_path / "b.json"
    lst.write_text(json.dumps({"schema_version": 1, "sha256": {_sha(payload): "t"}}))
    assert cli.main(["intake", clean]) == 0
    assert "not a guarantee" in capsys.readouterr().out.lower()
    assert cli.main(["intake", bad, "--bad-hashes", str(lst), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["verdict"]["level"] == "malicious"
    assert cli.main(["intake", bad, "--bad-hashes", str(lst), "--sarif"]) == 1
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"
    assert cli.main(["intake", bad, "--bad-hashes", str(lst), "--fail-on", "high"]) == 1
    assert cli.main(["intake", str(tmp_path / "nope")]) == 2
    assert cli.main(["intake", clean, "--bad-hashes", str(tmp_path / "missing.json")]) == 2


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes need POSIX")
def test_a_named_pipe_does_not_hang_the_copy_and_is_skipped(tmp_path):
    src = mk(tmp_path / "clone", {"a.py": "x = 1\n"})
    os.mkfifo(os.path.join(src, "pipe"))
    res = intake.scan(src)
    assert {"file": "pipe", "reason": "not a regular file"} in res["skipped"] and res["quarantine"]["files"] == 1
