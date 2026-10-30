"""Run with:  python -m pytest -q   (or simply: python tests/test_engine.py)"""
import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.executor import run_code  # noqa: E402
from app.services.language import detect_language  # noqa: E402
from app.services.sast_engine import apply_all_fixes, apply_fix, scan_code  # noqa: E402

VULN_PY = '''import sqlite3
from flask import Flask, request
app = Flask(__name__)
SECRET_KEY = "hunter2hunter2"

@app.route("/u")
def u():
    name = request.args.get("name")
    cur = sqlite3.connect("a.db").cursor()
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(q)
    cur.execute(f"DELETE FROM users WHERE name = '{name}'")
    return "<h1>" + name + "</h1>"

def calc(x):
    return eval(x)

if __name__ == "__main__":
    app.run(debug=True)
'''

VULN_JS = '''const express = require("express");
const db = require("./db");
const app = express();
const apiKey = "sk-123456789";
app.get("/u", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id, (e, r) => res.json(r));
  res.send("<p>" + req.query.name + "</p>");
});
function render(x) { document.getElementById("a").innerHTML = x; }
function calc(s) { return eval(s); }
'''


def test_language_detection():
    assert detect_language("def f():\n    print(1)\n") == "python"
    assert detect_language("const a = 1;\nconsole.log(a)") == "javascript"
    assert detect_language("x", "main.py") == "python"
    assert detect_language("") == "unknown"


def test_scan_python_finds_issues_and_scores():
    r = scan_code(VULN_PY)
    assert r["status"] == "success"
    rules = {f["rule_id"] for f in r["findings"]}
    assert {"SQL_INJECTION", "HARDCODED_SECRET", "XSS", "CODE_EXECUTION", "DEBUG_ENABLED"} <= rules
    assert r["score"] < 40 and "starts at 100" in r["explanation"]


def test_fix_loop_converges_python():
    res = apply_all_fixes(VULN_PY, "python")
    ast.parse(res["code"])
    again = scan_code(res["code"])
    assert again["status"] == "success" and again["findings"] == [] and again["score"] == 100


def test_fix_loop_converges_javascript():
    res = apply_all_fixes(VULN_JS, "javascript")
    again = scan_code(res["code"])
    assert again["findings"] == [] and again["score"] == 100


def test_single_fix_then_rescan_has_fewer_findings():
    r = scan_code(VULN_PY)
    f = r["findings"][0]
    out = apply_fix(VULN_PY, "python", f["rule_id"], f["line"], f["snippet"])
    assert out["applied"]
    assert len(scan_code(out["code"])["findings"]) < len(r["findings"])


def test_unsuccessful_scans():
    assert scan_code("")["status"] == "failed"
    assert scan_code("def broken(:\n  pass")["status"] == "failed"
    assert scan_code("public class A {}", "java")["status"] == "failed"


def test_clean_code_scores_100():
    r = scan_code("def add(a, b):\n    return a + b\n")
    assert r["status"] == "success" and r["score"] == 100 and r["grade"] == "A"


def test_comments_are_ignored():
    assert scan_code("# eval(x)\ndef f():\n    pass\n")["findings"] == []


def test_executor_runs_python():
    r = run_code("print('hi')", "python")
    assert r["status"] == "passed" and "hi" in r["stdout"]
    assert run_code("raise SystemExit(3)", "python")["status"] == "failed"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
