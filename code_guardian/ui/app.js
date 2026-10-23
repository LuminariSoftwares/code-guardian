"use strict";
// code-guardian ui: the page. It talks only to the local server's API (/api/scan, /api/scans, /api/file) with the
// token from the link's fragment (#t=...). It never computes a score or a sentence: every number and every sentence
// on the page comes from the report and its plain-language layer. Text from the report is always set as text, never
// as markup.

(function () {
  var API_SCAN = "/api/scan";
  var API_SCANS = "/api/scans";
  var API_FILE = "/api/file";
  var API_EXPLAIN = "/api/explain";
  var MAX_EXPLAIN = 200;  // lines per question; the server refuses more
  var PICK_HINT = "Select some lines above, or type a start and end line, to ask what they do.";
  var POLL_MS = 800;

  var LEVEL_WORD = { FAIL: "High", WARN: "Medium", INFO: "Low" };
  var GROUPS = [
    { key: "High", note: "Safe checks that matched a pattern they treat as serious." },
    { key: "Medium", note: "Safe checks that matched, but may be fine where they are." },
    { key: "Low", note: "Things to know about; not a problem on their own." },
    { key: "Quality", note: "Whether it works and whether the project is complete: tests, README, licence and the like." }
  ];
  var HARM_CLASS = { "High": "lvl-High", "Medium": "lvl-Medium", "Low": "lvl-Low",
                     "No known risks found": "harm-none", "Could not check": "lvl-Unknown" };
  var DIM_TITLE = { safe: "Safe", works: "Works", complete: "Complete", overall: "Overall" };
  var SCREENS = ["notoken", "open", "result", "fixfirst", "findings", "code", "compare"];
  var RESULT_SCREENS = ["result", "fixfirst", "findings", "code", "compare"];

  var state = {
    token: readToken(),
    results: {},      // scan id -> {id, report, plain}, the scans this page ran
    current: null,    // the result on screen
    screen: null,
    file: null,       // rel of the file in the viewer
    files: {},        // "id\nrel" -> /api/file body
    scanning: false,
    again: false,     // a "Check again" is running
    range: null,      // {lo, hi}: the lines picked in the viewer, 1-based and inclusive
    ask: 0            // counts questions and resets; an answer for an older count is dropped
  };

  // ---- the token: only ever from the fragment ------------------------------------------------------------------

  function readToken() {
    var m = /(?:^#|&)t=([^&]+)/.exec(window.location.hash || "");
    if (!m) return "";
    try { return decodeURIComponent(m[1]); } catch (e) { return ""; }
  }

  // ---- the API -------------------------------------------------------------------------------------------------

  function ApiError(status, body) {
    this.status = status;
    this.body = body || {};
  }

  function call(url, options) {
    if (url.indexOf("/api/") !== 0) throw new Error("not an API path");
    var opts = options || {};
    var headers = { "X-CG-Token": state.token };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(url, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      cache: "no-store",
      credentials: "omit"
    }).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (body) {
        if (!resp.ok) throw new ApiError(resp.status, body);
        return body;
      });
    }, function () {
      throw new ApiError(0, { error: "network" });
    });
  }

  function fileUrl(id, rel) {
    return API_FILE + "?id=" + encodeURIComponent(id) + "&rel=" + encodeURIComponent(rel);
  }

  // ---- small DOM helpers ---------------------------------------------------------------------------------------

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function plural(n, word) {
    return n + " " + word + (n === 1 ? "" : "s");
  }

  // 33 -> "33/100", joined from a bare slash so no string in this file looks like a path to the URL check.
  function outOf(n) {
    return n + "/" + 100;
  }

  function clock(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  // "risky/runner.py:7" -> {rel, line}; "." or "" -> null (the whole project, not one file).
  function parseWhere(where) {
    if (!where || where === ".") return null;
    var m = /^(.*?):(\d+)(?::\d+)?$/.exec(String(where));
    if (m && m[1]) return { rel: m[1], line: parseInt(m[2], 10) };
    return { rel: String(where), line: null };
  }

  // Which score a finding belongs to, read from the report's own weight table; codes it does not list fall back to
  // the scorer's prefixes, and anything else is Safe, as the scorer does.
  function dimensionOf(code, report) {
    var weights = (report && report.weights) || {};
    var names = ["safe", "works", "complete"];
    for (var i = 0; i < names.length; i++) {
      var table = weights[names[i]] || {};
      for (var key in table) {
        if (Object.prototype.hasOwnProperty.call(table, key) && key.split(" ")[0] === code) return names[i];
      }
    }
    code = String(code || "");
    if (code.indexOf("works.") === 0 || code.indexOf("orphan.") === 0) return "works";
    if (code.indexOf("complete.") === 0) return "complete";
    return "safe";
  }

  function groupOf(card, report) {
    if (dimensionOf(card.code, report) !== "safe") return "Quality";
    return LEVEL_WORD[card.level] || "Low";
  }

  function whereButton(where, label) {
    var loc = parseWhere(where);
    if (!loc) return el("span", "where-none", "The whole project, not one file");
    var b = el("button", "link mono", label || (loc.line ? loc.rel + " line " + loc.line : loc.rel));
    b.type = "button";
    b.addEventListener("click", function () { openCode(loc.rel, loc.line); });
    return b;
  }

  // ---- screens -------------------------------------------------------------------------------------------------

  function show(screen, push) {
    SCREENS.forEach(function (name) { $("screen-" + name).hidden = name !== screen; });
    var inResult = RESULT_SCREENS.indexOf(screen) >= 0 && !!state.current;
    $("tabs").hidden = !inResult;
    $("scanned").hidden = !inResult;
    $("summary-rail").hidden = !inResult;
    $("new-check").hidden = !inResult;
    $("main").className = (inResult ? "with-rail" : "") + (screen === "code" ? " wide" : "");
    var tabs = $("tabs").querySelectorAll("button");
    for (var i = 0; i < tabs.length; i++) {
      if (tabs[i].getAttribute("data-screen") === screen) tabs[i].setAttribute("aria-current", "page");
      else tabs[i].removeAttribute("aria-current");
    }
    if (push !== false && state.screen && state.screen !== screen) {
      try { window.history.pushState({ screen: screen }, "", window.location.href); } catch (e) { /* not needed */ }
    }
    state.screen = screen;
    if (screen === "open") refreshRecent();
    window.scrollTo(0, 0);
  }

  function noToken(why) {
    if (why) $("notoken-why").textContent = why;
    show("notoken", false);
  }

  // ---- open: the form, the OS hint, the recent list -----------------------------------------------------------

  function osHint() {
    var ua = (navigator.userAgent || "") + " " + (navigator.platform || "");
    if (/Win/i.test(ua)) {
      return "On Windows: in File Explorer, right-click the folder and choose “Copy as path”, then paste it here. The quotes are fine.";
    }
    if (/Mac/i.test(ua) && !/iPhone|iPad/i.test(ua)) {
      return "On a Mac: in Finder, select the folder, hold Option, right-click it and choose “Copy … as Pathname”, then paste it here.";
    }
    if (/Linux|X11/i.test(ua) && !/Android/i.test(ua)) {
      return "On Linux: type or paste the folder's full path, such as ~/projects/my-app.";
    }
    return "Type or paste the full path of the folder on the computer where code-guardian is running.";
  }

  function latestPerPath(entries) {
    var seen = {};
    var out = [];
    for (var i = entries.length - 1; i >= 0; i--) {
      var e = entries[i];
      if (seen[e.path]) continue;
      seen[e.path] = true;
      out.push(e);
    }
    return out;
  }

  function renderRecent(entries) {
    var list = $("recent");
    clear(list);
    var rows = latestPerPath(entries);
    $("recent-empty").hidden = rows.length > 0;
    rows.forEach(function (e) {
      var li = el("li");
      var b = el("button", "recent-item");
      b.type = "button";
      b.appendChild(el("span", "mono", e.path));
      var meta;
      if (e.state === "scanning") meta = "Checking now…";
      else if (e.grade) meta = "Grade " + e.grade + " · " + e.overall + " out of 100" + (e.status && e.status !== "COMPLETE" ? " · " + e.status : "") + " · " + clock(e.when);
      else meta = "No grade" + (e.status ? " · " + e.status : "") + " · " + clock(e.when);
      b.appendChild(el("span", "meta", meta));
      b.disabled = e.state === "scanning" || state.scanning;
      b.addEventListener("click", function () {
        if (state.results[e.id]) {
          setResult(state.results[e.id]);
          show("result");
        } else {
          startScan(e.path);
        }
      });
      li.appendChild(b);
      list.appendChild(li);
    });
  }

  function refreshRecent() {
    return call(API_SCANS).then(function (entries) {
      renderRecent(entries);
      return entries;
    }, handleApiError);
  }

  function handleApiError(err) {
    if (err && err.status === 403 && err.body && err.body.error === "token") {
      noToken("This link is from an earlier run of code-guardian, or it was copied without its key, so the page cannot use it.");
    } else if (err && err.status === 0) {
      showOpenError("code-guardian is not answering. Is it still running in the terminal? If you closed it, run code-guardian ui again and open the new link.");
    }
    return null;
  }

  function showOpenError(text) {
    var box = $("open-error");
    box.textContent = text;
    box.hidden = !text;
  }

  // ---- scanning ------------------------------------------------------------------------------------------------

  function setScanning(path, on) {
    state.scanning = on;
    $("scan-button").disabled = on;
    $("scan-button").textContent = on ? "Checking…" : "Check this folder";
    var box = $("scanning");
    box.hidden = !on;
    if (on) paintScanning(path, null);
  }

  function paintScanning(path, since) {
    var box = $("scanning");
    clear(box);
    box.appendChild(el("span", "spinner"));
    box.appendChild(el("strong", null, "Checking "));
    box.appendChild(el("span", "mono", path));
    var secs = since ? Math.max(0, Math.round((Date.now() - since) / 1000)) : 0;
    box.appendChild(el("span", null, secs ? " — " + secs + " s so far" : "…"));
  }

  function startScan(path) {
    path = String(path || "").trim();
    if (!path || state.scanning || state.again) return;
    showOpenError("");
    if (state.screen !== "open") show("open");
    $("path").value = path;
    setScanning(path, true);
    var started = Date.now();
    var timer = window.setInterval(function () {
      call(API_SCANS).then(function (entries) {
        renderRecent(entries);
        paintScanning(path, started);
      }, function () { /* the scan call reports errors */ });
    }, POLL_MS);
    return scan(path).then(function (result) {
      window.clearInterval(timer);
      setScanning(path, false);
      setResult(result);
      show("result");
    }, function (err) {
      window.clearInterval(timer);
      setScanning(path, false);
      if (err.status === 403 && err.body.error === "token") return handleApiError(err);
      if (err.status === 0) return handleApiError(err);
      showOpenError(scanErrorText(err));
      refreshRecent();
    });
  }

  // One POST /api/scan. The path as asked is kept with the result, so "Check again" asks for the same thing.
  function scan(path) {
    return call(API_SCAN, { method: "POST", body: { path: path, goal_file: null } }).then(function (result) {
      result.asked = path;
      state.results[result.id] = result;
      return result;
    });
  }

  function scanErrorText(err) {
    var detail = err.body.detail ? String(err.body.detail) : "";
    if (err.body.error === "path") return "That folder was not found. Check the path and try again. (" + detail + ")";
    if (err.body.error === "goal") return "The project's goal file could not be read: " + detail;
    if (err.body.error === "scan") return "The check stopped with an error (" + detail + "). Nothing was changed in the folder.";
    return "The check could not start (" + (err.body.error || err.status) + ").";
  }

  // "Check again": scan the same folder now, on demand only, and stay on the tab the reader is on. Every tab and
  // the rail are redrawn from the new response; an open file is opened again from the new scan.
  function checkAgain() {
    if (!state.current || state.again || state.scanning) return;
    var path = state.current.asked || state.current.report.path;
    var screen = state.screen;
    var file = screen === "code" ? state.file : null;
    var line = file ? parseInt($("jump-line").value, 10) || null : null;
    setAgain(true, "Checking the folder again…");
    return scan(path).then(function (result) {
      setAgain(false, "");
      setResult(result);
      show(screen, false);
      if (file) openCode(file, line);
    }, function (err) {
      if (err.status === 0 || (err.status === 403 && err.body.error === "token")) {
        setAgain(false, "");
        return handleApiError(err);
      }
      setAgain(false, "Could not check again: " + scanErrorText(err));
    });
  }

  function setAgain(on, text) {
    state.again = on;
    ["check-again", "check-again-summary"].forEach(function (id) {
      $(id).disabled = on;
      $(id).textContent = on ? "Checking…" : "Check again";
    });
    if (text || on) $("rail-when").textContent = text;
  }

  // ---- one result ----------------------------------------------------------------------------------------------

  function setResult(result) {
    state.current = result;
    state.file = null;
    var rep = result.report;
    var plain = result.plain;
    $("scanned-path").textContent = rep.path;
    var entry = null;
    $("scanned-when").textContent = "";
    $("rail-when").textContent = "";
    call(API_SCANS).then(function (entries) {
      for (var i = 0; i < entries.length; i++) if (entries[i].id === result.id) entry = entries[i];
      if (entry && state.current === result) {
        $("scanned-when").textContent = "· checked at " + clock(entry.when);
        $("rail-when").textContent = "checked at " + clock(entry.when);
      }
    }, function () { /* the time is a nicety */ });
    renderRail(rep, plain);
    renderSummary(rep, plain);
    renderFixFirst(rep, plain);
    renderFindings(rep, plain);
    renderFileList(rep, plain);
    resetViewer();
  }

  function renderSummary(rep, plain) {
    var checked = plain.checked || [];
    var lead = checked.length && checked[0].label === "Not fully checked" ? checked[0] : null;
    var banner = $("banner");
    banner.hidden = !lead;
    banner.className = "banner" + (rep.status === "INVALID" ? " invalid" : "");
    if (lead) {
      $("banner-word").textContent = rep.status === "INVALID" ? "INVALID — no grade" : rep.status + " — not everything was checked";
      $("banner-text").textContent = lead.text;
    }

    var harm = plain.harm || {};
    $("harm").className = "harm " + harmClass(harm);
    $("harm-word").textContent = harm.level || "Could not check";
    $("partial-flag").hidden = !harm.partial;
    $("harm-why").textContent = harm.why || "";

    var scores = rep.scores || {};
    var line = $("grade-line");
    clear(line);
    if (scores.grade) {
      line.appendChild(document.createTextNode("Grade "));
      line.appendChild(el("span", "grade-letter", scores.grade));
      line.appendChild(document.createTextNode(" · " + scores.overall + " out of 100"));
    } else {
      line.textContent = "No grade";
    }

    var list = $("sentences");
    clear(list);
    ["safe", "works", "complete", "overall"].forEach(function (d) {
      var li = el("li");
      li.appendChild(el("span", "dim", DIM_TITLE[d]));
      li.appendChild(el("span", null, (plain.sentences || {})[d] || ""));
      list.appendChild(li);
    });

    var ul = $("checked");
    clear(ul);
    checked.forEach(function (c, i) {
      if (i === 0 && lead) return; // already the banner
      var li = el("li");
      li.appendChild(el("span", null, c.text));
      if (c.files) li.appendChild(el("span", "depth", depthWord(c.depth)));
      ul.appendChild(li);
    });
  }

  function harmClass(harm) {
    return HARM_CLASS[harm.level] || "lvl-Unknown";
  }

  // The rail: grade, how worried to be, Safe, how many fixes and findings. Every number is read from the response.
  function renderRail(rep, plain) {
    var scores = rep.scores || {};
    $("rail-grade").textContent = scores.grade ? scores.grade + " (" + outOf(scores.overall) + ")" : "No grade";
    var harm = plain.harm || {};
    $("rail-harm").className = "rail-harm " + harmClass(harm);
    $("rail-harm-word").textContent = harm.level || "Could not check";
    $("rail-partial").hidden = !harm.partial;
    $("rail-safe").textContent = scores.safe === null || scores.safe === undefined ? "not scored" : outOf(scores.safe);
    var fixes = (plain.fix_first || []).length;
    $("rail-fix").textContent = fixes ? plural(fixes, "item") : "nothing";
    var counts = { High: 0, Medium: 0, Low: 0, Quality: 0 };
    (plain.cards || []).forEach(function (c) { counts[groupOf(c, rep)] += 1; });
    $("rail-high").textContent = String(counts.High);
    $("rail-medium").textContent = String(counts.Medium);
    $("rail-low").textContent = String(counts.Low);
    $("rail-quality").textContent = String(counts.Quality);
  }

  function depthWord(depth) {
    if (depth === "full") return "Depth: full analysis";
    if (depth === "secrets+manifests") return "Depth: read for keys and install settings only";
    if (depth === "secrets only") return "Depth: read for keys only";
    if (depth === "not read") return "Depth: not read";
    return "Depth: " + depth;
  }

  function renderFixFirst(rep, plain) {
    var list = $("fix-list");
    clear(list);
    var rows = plain.fix_first || [];
    $("fix-empty").hidden = rows.length > 0;
    // The scan's own notes on its ranking (such as why a Safe fix shows +0 and still comes first) go above the list.
    var notes = plain.fix_first_notes || [];
    var box = $("fix-notes-body");
    clear(box);
    notes.forEach(function (n) { box.appendChild(el("p", null, n)); });
    $("fix-notes").hidden = !notes.length;
    rows.forEach(function (row) {
      var li = el("li", "card");
      li.appendChild(el("h3", null, row.title));
      var meta = el("p", "fix-meta");
      var group = fixGroup(row, rep, plain);
      if (group) meta.appendChild(el("span", "chip " + group, group));
      meta.appendChild(document.createTextNode("In " + plural(row.count, "place") + " \u00b7 fixing only this adds " +
        plural(row.gain, "point") + " \u00b7 grade after: " + row.grade_after));
      li.appendChild(meta);
      if (row.how) {
        var how = el("p", "how");
        how.appendChild(el("strong", null, "What to do: "));
        how.appendChild(document.createTextNode(row.how));
        li.appendChild(how);
      }
      li.appendChild(whereButton(row.first_location, parseWhere(row.first_location)
        ? "Open " + describe(row.first_location) : null));
      list.appendChild(li);
    });
  }

  // A plan row names its check by title and level; the card with the same two gives its group.
  function fixGroup(row, rep, plain) {
    var cards = plain.cards || [];
    for (var i = 0; i < cards.length; i++) {
      if (cards[i].what === row.title && cards[i].level === row.level) return groupOf(cards[i], rep);
    }
    return null;
  }

  function describe(where) {
    var loc = parseWhere(where);
    if (!loc) return "the whole project";
    return loc.line ? loc.rel + " at line " + loc.line : loc.rel;
  }

  function renderFindings(rep, plain) {
    var cards = plain.cards || [];
    var groups = {};
    GROUPS.forEach(function (g) { groups[g.key] = []; });
    cards.forEach(function (c) { groups[groupOf(c, rep)].push(c); });
    $("findings-intro").textContent = cards.length
      ? plural(cards.length, "finding") + ". Each one says where it is, what the check saw, why that can matter and what to do."
      : "The checks reported nothing.";
    var box = $("groups");
    clear(box);
    GROUPS.forEach(function (g) {
      var rows = groups[g.key];
      if (!rows.length) return;
      // High and Medium start open; Low and Quality start folded so the phone page stays short.
      var sec = el("details", "group");
      sec.open = g.key === "High" || g.key === "Medium";
      var sum = el("summary", "group-title");
      sum.appendChild(el("span", "chip " + g.key, g.key));
      sum.appendChild(el("span", "count", plural(rows.length, "finding")));
      sec.appendChild(sum);
      sec.appendChild(el("p", "group-note", g.note));
      rows.forEach(function (c) { sec.appendChild(findingCard(c, g.key)); });
      box.appendChild(sec);
    });
  }

  function findingCard(c, group) {
    var card = el("article", "card");
    card.appendChild(el("h3", null, c.what));
    var meta = el("p", "card-meta");
    meta.appendChild(el("span", "chip " + group, group));
    meta.appendChild(document.createTextNode("Confidence: " + (c.confidence || "not given")));
    card.appendChild(meta);
    card.appendChild(whereButton(c.where));
    card.appendChild(el("p", "why", c.why));
    if (c.how) {
      var how = el("p", "how");
      how.appendChild(el("strong", null, "What to do: "));
      how.appendChild(document.createTextNode(c.how));
      card.appendChild(how);
    }
    var tech = el("details", "tech");
    tech.appendChild(el("summary", null, "Technical details"));
    var dl = el("dl");
    [["Check", c.code], ["Level", c.level], ["Where", c.where], ["Fingerprint", c.fingerprint]].forEach(function (p) {
      dl.appendChild(el("dt", null, p[0]));
      dl.appendChild(el("dd", "mono", p[1] === null || p[1] === undefined ? "" : p[1]));
    });
    tech.appendChild(dl);
    card.appendChild(tech);
    return card;
  }

  // ---- code ----------------------------------------------------------------------------------------------------

  // The API does not list a scan's files, so the viewer lists the files the findings point to.
  function filesOf(rep, plain) {
    var counts = {};
    (plain.cards || []).forEach(function (c) {
      var loc = parseWhere(c.where);
      if (loc) counts[loc.rel] = (counts[loc.rel] || 0) + 1;
    });
    return Object.keys(counts).sort().map(function (rel) { return { rel: rel, n: counts[rel] }; });
  }

  function notesFor(rel) {
    var rep = state.current.report;
    var byLine = {};
    (state.current.plain.cards || []).forEach(function (c) {
      var loc = parseWhere(c.where);
      if (!loc || loc.rel !== rel || !loc.line) return;
      (byLine[loc.line] = byLine[loc.line] || []).push({ group: groupOf(c, rep), card: c });
    });
    return byLine;
  }

  function renderFileList(rep, plain) {
    var list = $("file-list");
    clear(list);
    var files = filesOf(rep, plain);
    if (!files.length) list.appendChild(el("li", "hint", "No finding points at a single file."));
    files.forEach(function (f) {
      var li = el("li");
      var b = el("button", "file-btn");
      b.type = "button";
      b.setAttribute("data-rel", f.rel);
      b.appendChild(el("span", "mono", f.rel));
      b.appendChild(el("span", "n", String(f.n)));
      b.setAttribute("aria-label", f.rel + ", " + plural(f.n, "finding"));
      b.addEventListener("click", function () { openCode(f.rel, null); });
      li.appendChild(b);
      list.appendChild(li);
    });
  }

  function resetViewer() {
    $("file-name").textContent = "Pick a file";
    var pre = $("code");
    clear(pre);
    pre.appendChild(el("span", "code-empty", "Pick a file from the list, or tap a location on a finding."));
    clearRange();
  }

  function markCurrentFile(rel) {
    var buttons = $("file-list").querySelectorAll(".file-btn");
    for (var i = 0; i < buttons.length; i++) {
      if (buttons[i].getAttribute("data-rel") === rel) buttons[i].setAttribute("aria-current", "true");
      else buttons[i].removeAttribute("aria-current");
    }
  }

  function openCode(rel, line) {
    if (!state.current) return;
    if (state.screen !== "code") show("code");
    var id = state.current.id;
    var key = id + "\n" + rel;
    markCurrentFile(rel);
    $("file-name").textContent = rel;
    var got = state.files[key] ? Promise.resolve(state.files[key]) : call(fileUrl(id, rel)).then(function (body) {
      state.files[key] = body;
      return body;
    });
    return got.then(function (body) {
      if (!state.current || state.current.id !== id) return;
      state.file = rel;
      renderCode(rel, body);
      if (line) jumpTo(line);
    }, function (err) {
      var pre = $("code");
      clear(pre);
      var why = { file: "That file is not there any more.", binary: "That file is not text, so it cannot be shown.",
                  outside: "That file is outside the checked folder.", scan: "This check is no longer held by code-guardian; run it again." };
      if (err.status === 0 || (err.status === 403 && err.body.error === "token")) handleApiError(err);
      pre.appendChild(el("span", "code-empty", why[err.body.error] || "The file could not be opened."));
    });
  }

  function renderCode(rel, body) {
    var pre = $("code");
    clear(pre);
    var notes = notesFor(rel);
    var frag = document.createDocumentFragment();
    (body.lines || []).forEach(function (text, i) {
      var n = i + 1;
      var row = el("span", "line" + (notes[n] ? " flagged" : ""));
      row.id = "L" + n;
      row.setAttribute("data-line", String(n));
      row.appendChild(el("span", "ln", String(n)));
      row.appendChild(el("span", "src", text.length ? text : " "));
      frag.appendChild(row);
      (notes[n] || []).forEach(function (note, k) {
        frag.appendChild(lineNote(note, "N" + n + "-" + k));
      });
    });
    if (body.truncated) frag.appendChild(el("span", "code-empty", "Only the first 2 MB of this file is shown."));
    if (!(body.lines || []).length) frag.appendChild(el("span", "code-empty", "This file is empty."));
    pre.appendChild(frag);
    $("jump-line").max = String((body.lines || []).length || 1);
    clearRange();
  }

  // A note under a flagged line: the level and the check's title; tapping it opens the card's why and what to do.
  function lineNote(note, id) {
    var card = note.card;
    var tag = el("span", "line-note " + note.group);
    var toggle = el("button", "note-toggle");
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-controls", id);
    toggle.appendChild(el("strong", null, note.group + ": "));
    toggle.appendChild(document.createTextNode(card.what));
    var more = el("span", "note-more", "What this means");
    toggle.appendChild(more);
    var body = el("span", "note-body");
    body.id = id;
    body.hidden = true;
    body.appendChild(el("span", "note-why", card.why));
    if (card.how) {
      var how = el("span", "note-how");
      how.appendChild(el("strong", null, "What to do: "));
      how.appendChild(document.createTextNode(card.how));
      body.appendChild(how);
    }
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      more.textContent = open ? "Hide" : "What this means";
      body.hidden = !open;
    });
    tag.appendChild(toggle);
    tag.appendChild(body);
    return tag;
  }

  function jumpTo(line) {
    var pre = $("code");
    var old = pre.querySelectorAll(".line.target");
    for (var i = 0; i < old.length; i++) old[i].classList.remove("target");
    var row = $("L" + line);
    if (!row) return;
    row.classList.add("target");
    $("jump-line").value = String(line);
    // Scroll the code box, not the page, so the line sits a few rows from the top of the box.
    pre.scrollTop = Math.max(0, row.offsetTop - pre.offsetTop - 3 * row.offsetHeight);
    if (window.matchMedia("(max-width: 899px)").matches) {
      var top = pre.getBoundingClientRect().top + window.pageYOffset - 64;
      window.scrollTo(0, Math.max(0, top));
    }
  }

  function lineOf(node) {
    while (node && node !== document.body) {
      if (node.nodeType === 1 && node.classList.contains("line")) return parseInt(node.getAttribute("data-line"), 10);
      if (node.nodeType === 1 && node.classList.contains("line-note")) {
        var prev = node.previousElementSibling;
        while (prev && !prev.classList.contains("line")) prev = prev.previousElementSibling;
        return prev ? parseInt(prev.getAttribute("data-line"), 10) : null;
      }
      node = node.parentNode;
    }
    return null;
  }

  // ---- the lines picked for "Explain these lines" -----------------------------------------------------------------

  function fileLength() {
    var body = state.current && state.file ? state.files[state.current.id + "\n" + state.file] : null;
    return body ? (body.lines || []).length : 0;
  }

  function closePanel() {
    state.ask += 1;
    $("explain-panel").hidden = true;
    clear($("explain-body"));
  }

  function paintRange() {
    var rows = $("code").querySelectorAll(".line.picked");
    for (var i = 0; i < rows.length; i++) rows[i].classList.remove("picked");
    var r = state.range;
    if (r) {
      for (var n = r.lo; n <= r.hi; n++) {
        var row = $("L" + n);
        if (row) row.classList.add("picked");
      }
    }
    $("explain").disabled = !r;
    $("selection-note").textContent = r
      ? (r.lo === r.hi ? "Line " + r.lo : "Lines " + r.lo + "–" + r.hi) + " of " + state.file + " (" + plural(r.hi - r.lo + 1, "line") + ")."
      : PICK_HINT;
  }

  function say(text) {
    var box = $("range-msg");
    box.textContent = text || "";
    box.hidden = !text;
  }

  function clearRange() {
    state.range = null;
    $("line-start").value = "";
    $("line-end").value = "";
    $("line-start").max = $("line-end").max = String(fileLength() || 1);
    say("");
    closePanel();
    paintRange();
  }

  // Pick lines lo..hi: clamped to the file and to MAX_EXPLAIN lines, with a plain message when it had to move. The
  // fields always show what will be used.
  function pickRange(lo, hi) {
    var n = fileLength();
    var msg = "";
    if (!n) return;
    if (lo < 1) { lo = 1; msg = "The first line is 1."; }
    if (lo > n) { lo = n; hi = Math.max(hi, lo); msg = "This file has " + plural(n, "line") + "."; }
    if (hi > n) { hi = n; msg = "This file has " + plural(n, "line") + "."; }
    if (hi < lo) { say("The end line cannot come before the start line."); state.range = null; paintRange(); closePanel(); return; }
    if (hi - lo + 1 > MAX_EXPLAIN) { hi = lo + MAX_EXPLAIN - 1; msg = "Up to " + MAX_EXPLAIN + " lines at a time, so the end line was moved to " + hi + "."; }
    var changed = !state.range || state.range.lo !== lo || state.range.hi !== hi;
    state.range = { lo: lo, hi: hi };
    $("line-start").value = String(lo);
    $("line-end").value = String(hi);
    say(msg);
    paintRange();
    if (changed) closePanel();
  }

  function onFields() {
    if (!state.file) return;
    var lo = parseInt($("line-start").value, 10);
    var hi = parseInt($("line-end").value, 10);
    if (isNaN(lo) || isNaN(hi)) {
      state.range = null;
      say($("line-start").value || $("line-end").value ? "Type both a start line and an end line." : "");
      paintRange();
      closePanel();
      return;
    }
    pickRange(lo, hi);
  }

  function onSelection() {
    if (state.screen !== "code" || !state.file) return;
    var sel = window.getSelection();
    var pre = $("code");
    // Anything outside the code (a click in a field or on a button) leaves the picked lines as they are.
    if (!sel || sel.isCollapsed || !pre.contains(sel.anchorNode) || !pre.contains(sel.focusNode)) return;
    var a = lineOf(sel.anchorNode);
    var b = lineOf(sel.focusNode);
    if (!a || !b) return;
    pickRange(Math.min(a, b), Math.max(a, b));
  }

  // ---- ask the person's own model ------------------------------------------------------------------------------

  function panelOpen() {
    $("explain-panel").hidden = false;
    var body = $("explain-body");
    clear(body);
    return body;
  }

  function panelNote(text, alert) {
    var p = el("p", alert ? "alert" : "hint", text);
    if (alert) p.setAttribute("role", "alert");
    $("explain-body").appendChild(p);
  }

  function explainError(err) {
    if (err && err.status === 0) return "code-guardian is not answering. Is it still running in the terminal?";
    if (err && err.status === 403 && err.body.error === "token") return "This link is from an earlier run of code-guardian.";
    if (err && err.body && err.body.detail) return err.body.detail;
    return "The lines could not be sent to your model.";
  }

  function askBody(dry) {
    return { id: state.current.id, rel: state.file, start: state.range.lo, end: state.range.hi, dry_run: dry || undefined };
  }

  // Step 1: nothing is sent. Ask the server where the lines would go and say so, with a button to send them.
  function explainClick() {
    if (!state.current || !state.file || !state.range) return;
    var mine = ++state.ask;
    var shown = state.range;
    var body = panelOpen();
    body.appendChild(el("p", "hint", "Checking where these lines would go…"));
    call(API_EXPLAIN, { method: "POST", body: askBody(true) }).then(function (res) {
      if (mine !== state.ask) return;
      body = panelOpen();
      if (!res.sent) {
        $("sent-to").textContent = "Sent to: nothing. No model is set up.";
        panelNote(res.note, false);
        return;
      }
      var n = shown.hi - shown.lo + 1;
      $("sent-to").textContent = "Sent to: nothing yet.";
      body.appendChild(el("p", null, (n === 1 ? "This line goes" : "These " + n + " lines go") + " to your model at " +
        res.sent.host + " (" + res.sent.model + "). Nothing else is sent."));
      var row = el("div", "row");
      var send = el("button", "primary", "Send " + (n === 1 ? "this line" : "these lines"));
      send.type = "button";
      send.addEventListener("click", function () { sendLines(res.sent); });
      var cancel = el("button", "ghost", "Cancel");
      cancel.type = "button";
      cancel.addEventListener("click", closePanel);
      row.appendChild(send);
      row.appendChild(cancel);
      body.appendChild(row);
      send.focus();
    }, function (err) {
      if (mine !== state.ask) return;
      panelOpen();
      panelNote(explainError(err), true);
    });
  }

  // Step 2: the person confirmed. Send exactly those lines and show the answer, or the note saying why not.
  function sendLines(sent) {
    var mine = ++state.ask;
    var body = panelOpen();
    var wait = el("p", "status-line", "asking your model…");
    wait.setAttribute("role", "status");
    body.appendChild(wait);
    $("explain").disabled = true;
    call(API_EXPLAIN, { method: "POST", body: askBody(false) }).then(function (res) {
      if (mine !== state.ask) return;
      body = panelOpen();
      $("explain").disabled = !state.range;
      if (res.text) {
        body.appendChild(el("p", "explain-body-text", res.text));
        panelNote("Answered by " + sent.model + " at " + sent.host + ". " + plural(sent.lines, "line") + " of " + state.file + " were sent.", false);
        $("sent-to").textContent = "Sent to: " + sent.host + " (" + sent.model + "), " + plural(sent.lines, "line") + " of " + state.file + ".";
      } else {
        panelNote(res.note || "The model did not answer.", true);
      }
    }, function (err) {
      if (mine !== state.ask) return;
      panelOpen();
      $("explain").disabled = !state.range;
      panelNote(explainError(err), true);
    });
  }

  // ---- wiring --------------------------------------------------------------------------------------------------

  function wire() {
    $("scan-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      startScan($("path").value);
    });
    $("new-check").addEventListener("click", function () { show("open"); $("path").focus(); });
    $("check-again").addEventListener("click", checkAgain);
    $("check-again-summary").addEventListener("click", checkAgain);
    var jumps = document.querySelectorAll("[data-screen]");
    for (var i = 0; i < jumps.length; i++) {
      jumps[i].addEventListener("click", function (ev) { show(ev.currentTarget.getAttribute("data-screen")); });
    }
    $("jump-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var n = parseInt($("jump-line").value, 10);
      if (state.file && n > 0) jumpTo(n);
    });
    document.addEventListener("selectionchange", onSelection);
    ["line-start", "line-end"].forEach(function (id) { $(id).addEventListener("input", onFields); });
    $("range-form").addEventListener("submit", function (ev) { ev.preventDefault(); explainClick(); });
    $("explain").addEventListener("click", explainClick);
    window.addEventListener("popstate", function (ev) {
      var screen = ev.state && ev.state.screen;
      if (!screen || SCREENS.indexOf(screen) < 0) screen = state.current ? "result" : "open";
      if (RESULT_SCREENS.indexOf(screen) >= 0 && !state.current) screen = "open";
      show(screen, false);
    });
    $("os-hint").textContent = osHint();
  }

  function start() {
    wire();
    if (!state.token) return noToken();
    try { window.history.replaceState({ screen: "open" }, "", window.location.href); } catch (e) { /* not needed */ }
    show("open", false);
    refreshRecent().then(function (entries) {
      if (!entries) return;
      // A folder named on the command line was checked before the page opened; the API keeps the list, not the
      // report, so the page checks the newest one again to show it.
      var done = entries.filter(function (e) { return e.state === "done"; });
      if (done.length && !state.current) startScan(done[done.length - 1].path);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
