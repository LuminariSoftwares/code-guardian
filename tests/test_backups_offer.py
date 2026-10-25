"""backups.offer beyond tests/test_p93_s1_acceptance.py: skipped files are counted, the folder-first order and the sort
hold on ties, a real walk agrees with the offer, and the importer and named-by checks follow the same counting."""
import ast

from code_guardian import backups, orphans, walk


def inv(python=(), other=(), skipped=()):
    return {"python": sorted(python), "manifests": [], "other": sorted(other), "skipped": [(r, "binary") for r in skipped],
            "excluded": 0, "ignored": 0}


def f(code, level, node):
    return {"code": code, "level": level, "node": node}


def test_skipped_files_count_under_the_glob_that_drops_them():
    offered, _ = backups.offer([f("secret.key", "FAIL", "_archive/a.py:1")],
                               inv(python=["_archive/a.py"], skipped=["_archive/blob.bin"]))
    assert [(g["glob"], g["files"], g["findings"]) for g in offered] == [("_archive/*", 2, 1)]


def test_equal_mark_globs_are_ordered_by_glob_text_and_offered_by_findings_then_glob():
    found = [f("secret.key", "FAIL", "a.py.pre-1:1"), f("secret.key", "FAIL", "b.py.backup-1:1")]
    offered, _ = backups.offer(found, inv(python=["a.py.pre-1", "b.py.backup-1"]))
    assert [g["glob"] for g in offered] == ["*.backup-*", "*.pre-*"]


def test_a_file_inside_a_copy_folder_counts_under_the_folder_not_its_own_mark():
    found = [f("secret.key", "FAIL", "_archive/a.py.bak-1:1"), f("secret.key", "FAIL", "src/b.py.bak-2:1")]
    offered, _ = backups.offer(found, inv(python=["_archive/a.py.bak-1", "src/b.py.bak-2"]))
    assert [(g["glob"], g["files"], g["findings"]) for g in offered] == [("*.bak-*", 1, 1), ("_archive/*", 1, 1)]


def test_a_candidate_whose_findings_all_belong_to_an_earlier_glob_is_neither_offered_nor_held():
    found = [f("secret.key", "FAIL", "_archive/a.py.backup-1:1")]
    offered, held = backups.offer(found, inv(python=["_archive/a.py.backup-1"]))
    assert [g["glob"] for g in offered] == ["_archive/*"] and held == []


def test_the_offer_matches_what_a_real_walk_leaves_out(tmp_path):
    names = ["app/main.py", "_archive/a.py", "_archive/b.py.backup-1", "src/x.py.backup-2", ".pre-commit-config.yaml",
             "z.py.pre-fix-1", "tmp_old/y.py.backup-3"]
    for rel in names:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x = 1\n", encoding="utf-8")
    full = walk.walk(str(tmp_path))
    paths = full["python"] + full["manifests"] + full["other"] + [r for r, _ in full["skipped"]]
    found = [f("secret.key", "FAIL", r + ":1") for r in ("_archive/a.py", "_archive/b.py.backup-1", "src/x.py.backup-2",
                                                         "z.py.pre-fix-1", ".pre-commit-config.yaml")]
    offered, held = backups.offer(found, full)
    assert held == []
    left_out = walk.walk(str(tmp_path), exclude=[g["glob"] for g in offered])
    kept = set(left_out["python"] + left_out["manifests"] + left_out["other"] + [r for r, _ in left_out["skipped"]])
    assert len(paths) - len(kept) == sum(g["files"] for g in offered)


def test_importers_and_named_by_follow_the_counting():
    files = {"app/main.py": "from old import a\n", "old/__init__.py": "", "old/a.py": "X = 1\n",
             "old/b.py.bak-1": "Y = 2\n"}
    trees = {r: ast.parse(s) for r, s in files.items() if r.endswith(".py")}
    held = backups.offer([f("secret.key", "FAIL", "old/a.py:1"), f("secret.key", "FAIL", "old/b.py.bak-1:1")],
                         inv(python=list(files)), orphans.Graph(trees), files)[1]
    assert [h["glob"] for h in held] == ["old/*"] and held[0]["why"] == "app/main.py imports it"
