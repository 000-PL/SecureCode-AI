"""Rule based SAST engine for Python and JavaScript.

Every rule can (a) detect a vulnerable line, (b) explain it and (c) produce a concrete
secure replacement ("fix"). Fixes are deterministic, so the scan -> fix -> re-scan loop
always converges on code the engine itself considers secure.
"""
import ast
import io
import re
import tokenize
from dataclasses import dataclass, field

from .language import SUPPORTED, detect_language, display_name
from .sast_utils import (
    emit_literal, find_matching, indent_of, is_dynamic, parameterize, split_top, text_of, to_parts, SQL_RE,
)

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- context
class Ctx:
    def __init__(self, code: str, lang: str):
        self.code = code
        self.lang = lang
        self.lines = code.split("\n")
        self.esm = bool(re.search(r"(?m)^\s*import\s.+\sfrom\s+['\"]", code))
        low = code.lower()
        if re.search(r"\b(pg|psycopg2?)\b", low) and not re.search(r"mysql|sqlite", low):
            self.style = "numbered" if lang == "javascript" else "pyformat"
        elif re.search(r"mysql|pymysql|psycopg|mariadb", low) and lang == "python":
            self.style = "pyformat"
        else:
            self.style = "qmark"

    def placeholder(self, n: int) -> str:
        return {"qmark": "?", "pyformat": "%s", "numbered": f"${n}"}[self.style]

    def wrap_str(self, expr: str) -> str:
        return f"str({expr})" if self.lang == "python" else f"String({expr})"

    def params(self, items: list) -> str:
        if self.lang == "python":
            return "(" + ", ".join(items) + ("," if len(items) == 1 else "") + ")"
        return "[" + ", ".join(items) + "]"


@dataclass
class Fix:
    edits: dict                      # 0-based line index -> replacement text (may hold "\n")
    prelude: list = field(default_factory=list)   # [(line_to_add, marker_regex_if_already_present)]


def py_import(name: str):
    return (f"import {name}", rf"(?m)^import\s+[^\n#]*\b{name}\b")


def js_require(var: str, module: str, ctx: Ctx):
    if ctx.esm:
        line = f'import {var} from "{module}";'
    else:
        line = f'const {var} = require("{module}");'
    return (line, rf"""(require\(\s*['"]{module}['"]\s*\)|from\s+['"]{module}['"])""")


JS_ESCAPE_HELPER = (
    'const escapeHtml = (s) => String(s).replace(/[&<>"\']/g, (c) => '
    '({ "&": "&amp;", "<": "&lt;", ">": "&gt;", \'"\': "&quot;", "\'": "&#39;" }[c]));',
    r"\bescapeHtml\b\s*=",
)
JS_SAFE_EQUAL = (
    "const safeEqual = (a, b) => { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); "
    'return x.length === y.length && require("crypto").timingSafeEqual(x, y); };',
    r"\bsafeEqual\b\s*=",
)


# --------------------------------------------------------------------------- helpers
def _call_span(line: str, pattern: str):
    """Locate `pattern` (regex ending in an opening paren) and its matching close paren."""
    m = re.search(pattern, line)
    if not m:
        return None
    open_idx = m.end() - 1
    close_idx = find_matching(line, open_idx)
    if close_idx == -1:
        return None
    return m, open_idx, close_idx


def _rebuild_parts(parts, wrap_expr, lang) -> str:
    """Re-emit string parts as one expression, applying wrap_expr to dynamic pieces."""
    if lang == "javascript":
        out = "`"
        for kind, val in parts:
            out += val.replace("`", "\\`") if kind == "text" else "${" + wrap_expr(val) + "}"
        return out + "`"
    pieces = []
    for kind, val in parts:
        pieces.append(emit_literal(val) if kind == "text" else wrap_expr(val))
    return " + ".join(pieces) if pieces else '""'


# --------------------------------------------------------------------------- detectors / fixers
# Each detector returns a dict (match info) or None. Each fixer returns Fix or None.

# ---- SQL injection
_PY_SQL_CALL = r"\.execute\("
_JS_SQL_CALL = r"\.(?:query|execute|all|get|run)\("
_ASSIGN_PY = re.compile(r"^(\s*)([A-Za-z_]\w*)\s*=\s*(.+?)\s*$")
_ASSIGN_JS = re.compile(r"^(\s*)(?:(const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*$")


def _sqli_call_info(ctx: Ctx, line: str):
    pat = _PY_SQL_CALL if ctx.lang == "python" else _JS_SQL_CALL
    span = _call_span(line, pat)
    if not span:
        return None
    m, o, c = span
    inner = line[o + 1:c]
    pieces = split_top(inner, ",")
    if ctx.lang == "python" and len(pieces) > 1:
        return None
    if ctx.lang == "javascript" and len(pieces) > 1 and pieces[1].strip().startswith("["):
        return None
    parts = to_parts(pieces[0])
    if not parts or not is_dynamic(parts) or not SQL_RE.search(text_of(parts)):
        return None
    return {"kind": "call", "open": o, "close": c, "pieces": pieces, "parts": parts}


def _sqli_assign_info(ctx: Ctx, lines: list, idx: int):
    line = lines[idx]
    if ctx.lang == "python":
        m = _ASSIGN_PY.match(line)
        if not m or line.lstrip().startswith(("#", "return", "if ", "elif ")):
            return None
        indent, name, rhs, decl = m.group(1), m.group(2), m.group(3), ""
    else:
        m = _ASSIGN_JS.match(line)
        if not m:
            return None
        indent, decl, name, rhs = m.group(1), m.group(2) or "", m.group(3), m.group(4)
    if re.match(r"^\s*=", rhs):
        return None
    semi = rhs.rstrip().endswith(";")
    parts = to_parts(rhs)
    if not parts or not is_dynamic(parts) or not SQL_RE.search(text_of(parts)):
        return None
    use_pat = (rf"\.execute\(\s*{re.escape(name)}\s*\)" if ctx.lang == "python"
               else rf"\.(?:query|execute|all|get|run)\(\s*{re.escape(name)}\s*[,)]")
    uses = [j for j in range(idx + 1, min(len(lines), idx + 40)) if re.search(use_pat, lines[j])]
    if not uses:
        return None
    return {"kind": "assign", "indent": indent, "decl": decl, "name": name, "parts": parts, "semi": semi, "uses": uses}


def detect_sqli(ctx, lines, idx):
    line = lines[idx]
    info = _sqli_call_info(ctx, line)
    if info:
        return info
    return _sqli_assign_info(ctx, lines, idx)


def fix_sqli(ctx, lines, idx, info):
    sql, params = parameterize(info["parts"], ctx.placeholder, ctx.wrap_str)
    lit = emit_literal(sql)
    if info["kind"] == "call":
        line = lines[idx]
        inner = line[info["open"] + 1:info["close"]]
        rest = inner[len(info["pieces"][0]):] if ctx.lang == "javascript" else ""
        new = line[:info["open"] + 1] + lit + ", " + ctx.params(params) + rest + line[info["close"]:]
        return Fix({idx: new})
    name, ind = info["name"], info["indent"]
    pname = f"{name}_params"
    edits = {}
    if ctx.lang == "python":
        edits[idx] = f"{ind}{name} = {lit}\n{ind}{pname} = {ctx.params(params)}"
        for j in info["uses"]:
            edits[j] = re.sub(rf"(\.execute\(\s*){re.escape(name)}(\s*\))", rf"\1{name}, {pname}\2", lines[j], count=1)
    else:
        first = f"{ind}{info['decl']} {name} = {lit};" if info["decl"] else f"{ind}{name} = {lit};"
        edits[idx] = f"{first}\n{ind}const {pname} = {ctx.params(params)};"
        for j in info["uses"]:
            edits[j] = re.sub(
                rf"(\.(?:query|execute|all|get|run)\(\s*){re.escape(name)}(\s*[,)])", rf"\1{name}, {pname}\2", lines[j], count=1
            )
    return Fix(edits)


# ---- Command injection
def _py_cmd_info(ctx, line):
    span = _call_span(line, r"\bos\.(?:system|popen)\(")
    if span:
        m, o, c = span
        arg = line[o + 1:c]
        parts = to_parts(arg)
        if parts and is_dynamic(parts):
            return {"kind": "os", "name": "popen" if "popen" in m.group(0) else "system", "span": span, "parts": parts}
        if re.fullmatch(r"\s*[A-Za-z_][\w.\[\]'\"]*\s*", arg):
            return {"kind": "os", "name": "popen" if "popen" in m.group(0) else "system", "span": span, "parts": [("expr", arg.strip())]}
        return None
    span = _call_span(line, r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\(")
    if span and re.search(r"shell\s*=\s*True", line):
        m, o, c = span
        pieces = split_top(line[o + 1:c], ",")
        first = pieces[0].strip()
        parts = None if first.startswith("[") else (to_parts(first) or [("expr", first)])
        if parts and not is_dynamic(parts) and not first.startswith(("\"", "'")):
            parts = [("expr", first)]
        return {"kind": "sub", "span": span, "pieces": pieces, "parts": parts}
    return None


def _py_shlex_expr(parts):
    def wrap(e):
        return f"shlex.quote(str({e}))"
    pieces = []
    for kind, val in parts:
        pieces.append(emit_literal(val) if kind == "text" else wrap(val))
    return " + ".join(pieces)


def fix_py_cmd(ctx, lines, idx, info):
    line = lines[idx]
    m, o, c = info["span"]
    pre = [py_import("shlex"), py_import("subprocess")]
    if info["kind"] == "os":
        cmd = _py_shlex_expr(info["parts"])
        if info["name"] == "system":
            call = f"subprocess.run(shlex.split({cmd}), check=False)"
        else:
            call = f"subprocess.Popen(shlex.split({cmd}), stdout=subprocess.PIPE, text=True).stdout"
        new = line[:m.start()] + call + line[c + 1:]
        return Fix({idx: new}, pre)
    pieces = info["pieces"]
    rest_pieces = [p for p in pieces[1:] if not re.fullmatch(r"\s*shell\s*=\s*True\s*", p)]
    if info["parts"] is None:                      # first argument is already a list
        first_new, pre_needed = pieces[0].strip(), False
    else:
        first_new, pre_needed = f"shlex.split({_py_shlex_expr(info['parts'])})", True
    inner = ", ".join([first_new] + [p.strip() for p in rest_pieces])
    return Fix({idx: line[:o + 1] + inner + line[c:]}, pre if pre_needed else [])


def detect_cmdi(ctx, lines, idx):
    line = lines[idx]
    if ctx.lang == "python":
        return _py_cmd_info(ctx, line)
    span = _call_span(line, r"(?<![\w$])(?:child_process\.)?exec(?:Sync)?\(")
    if not span:
        return None
    m, o, c = span
    pieces = split_top(line[o + 1:c], ",")
    parts = to_parts(pieces[0])
    if not parts or not is_dynamic(parts):
        if re.fullmatch(r"\s*[A-Za-z_$][\w$.]*\s*", pieces[0]):
            parts = [("expr", pieces[0].strip())]
        else:
            return None
    return {"span": span, "pieces": pieces, "parts": parts, "sync": "Sync" in m.group(0), "qualified": "child_process." in m.group(0)}


def fix_js_cmd(ctx, lines, idx, info):
    line = lines[idx]
    m, o, c = info["span"]
    parts = info["parts"]
    words, cur = [], []
    for kind, val in parts:
        if kind == "text":
            chunks = re.split(r"(\s+)", val)
            for ch in chunks:
                if ch == "":
                    continue
                if ch.isspace():
                    if cur:
                        words.append(cur)
                        cur = []
                else:
                    cur.append(("text", ch))
        else:
            cur.append(("expr", val))
    if cur:
        words.append(cur)
    if not words or any(k != "text" for k, _ in words[0]):
        return None
    prog = "".join(v for _, v in words[0])
    args = []
    for w in words[1:]:
        if all(k == "text" for k, _ in w):
            args.append(emit_literal("".join(v for _, v in w)))
        elif len(w) == 1:
            args.append(w[0][1])
        else:
            args.append("`" + "".join(v.replace("`", "\\`") if k == "text" else "${" + v + "}" for k, v in w) + "`")
    rest = line[o + 1:c][len(info["pieces"][0]):]
    fn = "execFileSync" if info["sync"] else "execFile"
    head = ("child_process." if info["qualified"] else "") + fn
    new = line[:m.start()] + head + "(" + emit_literal(prog) + ", [" + ", ".join(args) + "]" + rest + line[c:]
    pre = []
    if not info["qualified"]:
        if ctx.esm:
            pre.append((f'import {{ {fn} }} from "child_process";', rf"\b{fn}\b"))
        else:
            pre.append((f'const {{ {fn} }} = require("child_process");', rf"\b{fn}\b\s*[,}}]"))
    return Fix({idx: new}, pre)


# ---- eval / exec
def detect_code_exec(ctx, lines, idx):
    line = lines[idx]
    if ctx.lang == "python":
        if re.search(r"(?<![\w.])eval\(", line):
            return {"fn": "eval"}
        if re.search(r"(?<![\w.])exec\(", line):
            return {"fn": "exec"}
        return None
    if re.search(r"(?<![\w$.])eval\(", line):
        return {"fn": "eval"}
    if re.search(r"\bnew\s+Function\(", line):
        return {"fn": "Function"}
    return None


def fix_code_exec(ctx, lines, idx, info):
    line = lines[idx]
    if ctx.lang == "python":
        if info["fn"] == "eval":
            return Fix({idx: re.sub(r"(?<![\w.])eval\(", "ast.literal_eval(", line)}, [py_import("ast")])
        return Fix({idx: indent_of(line) + 'raise ValueError("Dynamic code execution is disabled for security reasons")'})
    if info["fn"] == "eval":
        return Fix({idx: re.sub(r"(?<![\w$.])eval\(", "JSON.parse(", line)})
    return Fix({idx: indent_of(line) + 'throw new Error("Dynamic code execution is disabled for security reasons");'})


# ---- hardcoded secrets
SECRET_RE = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9_])
    (?P<key>["']?[A-Za-z0-9_\-]*?(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|token)[A-Za-z0-9_\-]*["']?)
    \s*(?:===|==|=|:)\s*
    (?P<lit>(?P<q>["'])(?P<val>[^"'\n]{3,})(?P=q))
    """
)
_NON_SECRET_SUFFIX = re.compile(
    r"(?i)(label|text|prompt|placeholder|hint|msg|message|field|type|name|url|path|header|file|length|len|"
    r"min|max|expiry|expires|ttl|policy|route|endpoint|id)$"
)


def detect_secret(ctx, lines, idx):
    line = lines[idx]
    if re.search(r"os\.environ|getenv|process\.env", line):
        return None
    for m in SECRET_RE.finditer(line):
        key = m.group("key").strip("\"'")
        val = m.group("val")
        if _NON_SECRET_SUFFIX.search(key) or re.search(r"\s", val) or val.startswith(("<", "$", "{")):
            continue
        if re.fullmatch(r"(?i)(password|passwd|pwd|secret|token|username|email)", val):
            continue
        between = line[m.end("key"):m.start("lit")].strip()
        return {"key": key, "span": (m.start("lit"), m.end("lit")), "cmp": between in ("==", "===")}
    return None


def fix_secret(ctx, lines, idx, info):
    line = lines[idx]
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", info["key"])
    env = re.sub(r"[^A-Z0-9]+", "_", snake.upper()).strip("_") or "SECRET"
    s, e = info["span"]
    if ctx.lang == "python":
        expr = f'os.environ.get("{env}")' if info["cmp"] else f'os.environ.get("{env}", "")'
        return Fix({idx: line[:s] + expr + line[e:]}, [py_import("os")])
    return Fix({idx: line[:s] + f"process.env.{env}" + line[e:]})


# ---- weak hashing
def detect_weak_hash(ctx, lines, idx):
    line = lines[idx]
    if ctx.lang == "python":
        m = re.search(r"\bhashlib\.(md5|sha1)\(", line)
    else:
        m = re.search(r"""createHash\(\s*(['"])(md5|sha1)\1\s*\)""", line)
    return {"algo": m.group(m.lastindex if ctx.lang == "javascript" else 1)} if m else None


def fix_weak_hash(ctx, lines, idx, info):
    line = lines[idx]
    if ctx.lang == "python":
        return Fix({idx: re.sub(r"\bhashlib\.(md5|sha1)\(", "hashlib.sha256(", line)})
    return Fix({idx: re.sub(r"""createHash\(\s*(['"])(md5|sha1)\1\s*\)""", 'createHash("sha256")', line)})


# ---- insecure deserialisation
def detect_deser(ctx, lines, idx):
    line = lines[idx]
    if ctx.lang != "python":
        return None
    if re.search(r"\bpickle\.loads?\(|\bcPickle\.loads?\(|\bmarshal\.loads?\(", line):
        return {"fn": "pickle"}
    if re.search(r"\byaml\.load\(", line) and "SafeLoader" not in line:
        return {"fn": "yaml"}
    return None


def fix_deser(ctx, lines, idx, info):
    line = lines[idx]
    if info["fn"] == "yaml":
        new = line.replace("yaml.load(", "yaml.safe_load(")
        new = re.sub(r",\s*Loader\s*=\s*[\w.]+", "", new)
        return Fix({idx: new})
    new = re.sub(r"\b(?:c?[Pp]ickle|marshal)\.(loads?)\(", r"json.\1(", line)
    return Fix({idx: new}, [py_import("json")])


# ---- weak randomness
_CTX_WORDS = re.compile(r"(?i)token|password|passwd|secret|otp|session|api_?key|salt|nonce|reset|csrf|captcha")
_ARG = r"(?:[^(),]|\([^()]*\))+"


def detect_weak_random(ctx, lines, idx):
    line = lines[idx]
    window = " ".join(lines[max(0, idx - 3):idx + 1])
    if not _CTX_WORDS.search(window):
        return None
    if ctx.lang == "python":
        return {} if re.search(r"\brandom\.(random|randint|choice|choices|randrange)\(", line) else None
    return {} if re.search(r"\bMath\.random\(\)", line) else None


def fix_weak_random(ctx, lines, idx, info):
    line = lines[idx]
    if ctx.lang == "javascript":
        new = re.sub(r"\bMath\.random\(\)", "(crypto.randomInt(0, 2147483647) / 2147483647)", line)
        return Fix({idx: new}, [js_require("crypto", "crypto", ctx)])
    new = line
    new = re.sub(rf"\brandom\.randint\(\s*({_ARG})\s*,\s*({_ARG})\s*\)", r"(secrets.randbelow((\2) - (\1) + 1) + (\1))", new)
    new = re.sub(rf"\brandom\.randrange\(\s*({_ARG})\s*\)", r"secrets.randbelow(\1)", new)
    new = re.sub(rf"\brandom\.choices\(\s*({_ARG})\s*,\s*k\s*=\s*(\w+)\s*\)", r"[secrets.choice(\1) for _ in range(\2)]", new)
    new = re.sub(r"\brandom\.choice\(", "secrets.choice(", new)
    new = re.sub(r"\brandom\.random\(\)", "(secrets.randbelow(10**9) / 10**9)", new)
    if new == line:
        return None
    return Fix({idx: new}, [py_import("secrets")])


# ---- debug mode / TLS verification
def detect_debug(ctx, lines, idx):
    if ctx.lang != "python":
        return None
    return {} if re.search(r"\bdebug\s*=\s*True\b|^\s*DEBUG\s*=\s*True\b", lines[idx]) else None


def fix_debug(ctx, lines, idx, info):
    return Fix({idx: re.sub(r"(?i)(\bdebug\s*=\s*)True\b", lambda m: m.group(1) + "False", lines[idx])})


def detect_tls(ctx, lines, idx):
    line = lines[idx]
    if ctx.lang == "python":
        if re.search(r"\bverify\s*=\s*False\b", line) or "_create_unverified_context" in line:
            return {}
        return None
    if re.search(r"rejectUnauthorized\s*:\s*false", line) or re.search(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]", line):
        return {}
    return None


def fix_tls(ctx, lines, idx, info):
    line = lines[idx]
    new = re.sub(r"\bverify\s*=\s*False\b", "verify=True", line)
    new = new.replace("ssl._create_unverified_context", "ssl.create_default_context")
    new = re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", new)
    new = re.sub(r"(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*)(['\"])0\2", r"\1\g<2>1\2", new)
    return Fix({idx: new})


# ---- XSS
_HTML_TAG = re.compile(r"<\s*/?[A-Za-z!][^>]*>?")


def detect_xss(ctx, lines, idx):
    line = lines[idx]
    s = line.strip()
    if ctx.lang == "python":
        if not re.search(r"\breturn\b|render_template_string\(|make_response\(|Response\(|\.write\(", line):
            return None
        for m in re.finditer(r"""[fF](["'])(.*?)\1""", line):
            body = m.group(2)
            if _HTML_TAG.search(body) and re.search(r"(?<!\{)\{[^{}]+\}", body):
                if not all(x.strip().startswith(("html.escape", "escape(")) for x in re.findall(r"\{([^{}]+)\}", body)):
                    return {"mode": "fstring"}
        mm = re.search(r"\breturn\s+(.+)$", line)
        if mm:
            parts = to_parts(mm.group(1))
            if parts and is_dynamic(parts) and _HTML_TAG.search(text_of(parts)):
                if not all(v.strip().startswith(("html.escape", "escape(")) for k, v in parts if k == "expr"):
                    return {"mode": "return", "ret": mm, "parts": parts}
        return None
    # javascript
    m = re.search(r"\.innerHTML\s*=(?!=)\s*(.+?);?\s*$", line)
    if m:
        rhs = m.group(1).strip()
        parts = to_parts(rhs)
        lit = re.match(r"""^(["']).*\1$""", rhs)
        if lit and not parts:
            return None
        if rhs in ("''", '""', "``"):
            return None
        return {"mode": "innerHTML"}
    if re.search(r"\.insertAdjacentHTML\(", line):
        return {"mode": "adjacent"}
    if re.search(r"\bdocument\.write(ln)?\(", line):
        span = _call_span(line, r"\bdocument\.write(?:ln)?\(")
        if span:
            arg = line[span[1] + 1:span[2]]
            parts = to_parts(arg)
            if not (literal_ok(arg) and not parts):
                return {"mode": "docwrite", "span": span}
    span = _call_span(line, r"\bres\.(?:send|write|end)\(")
    if span:
        arg = line[span[1] + 1:span[2]]
        parts = to_parts(arg)
        if parts and is_dynamic(parts) and _HTML_TAG.search(text_of(parts)):
            if not all(v.strip().startswith("escapeHtml(") for k, v in parts if k == "expr"):
                return {"mode": "resend", "span": span, "parts": parts}
    return None


def literal_ok(arg: str) -> bool:
    return bool(re.match(r"""^\s*(["']).*\1\s*$""", arg))


def fix_xss(ctx, lines, idx, info):
    line = lines[idx]
    mode = info["mode"]
    if ctx.lang == "python":
        pre = [py_import("html")]
        if mode == "fstring":
            def fs(m):
                body = re.sub(
                    r"(?<!\{)\{([^{}]+)\}(?!\})",
                    lambda x: x.group(0) if x.group(1).strip().startswith(("html.escape", "escape(")) else "{html.escape(str(" + x.group(1) + "))}",
                    m.group(2),
                )
                return f"f{m.group(1)}{body}{m.group(1)}"
            new = re.sub(r"""[fF](["'])(.*?)\1""", fs, line)
            return Fix({idx: new}, pre)
        mm = info["ret"]
        expr = _rebuild_parts(info["parts"], lambda e: f"html.escape(str({e}))", "python")
        return Fix({idx: line[:mm.start(1)] + expr}, pre)
    if mode == "innerHTML":
        return Fix({idx: line.replace(".innerHTML", ".textContent")})
    if mode == "adjacent":
        return Fix({idx: line.replace(".insertAdjacentHTML(", ".insertAdjacentText(")})
    if mode == "docwrite":
        m, o, c = info["span"]
        arg = line[o + 1:c]
        return Fix({idx: line[:m.start()] + f"document.body.appendChild(document.createTextNode({arg}))" + line[c + 1:]})
    m, o, c = info["span"]
    expr = _rebuild_parts(info["parts"], lambda e: f"escapeHtml({e})", "javascript")
    arg = line[o + 1:c]
    rest = split_top(arg, ",")
    tail = arg[len(rest[0]):] if len(rest) > 1 else ""
    return Fix({idx: line[:o + 1] + expr + tail + line[c:]}, [JS_ESCAPE_HELPER])


# ---- path traversal
def detect_path(ctx, lines, idx):
    line = lines[idx]
    if ctx.lang == "python":
        span = _call_span(line, r"(?<![\w.])open\(|\bsend_file\(")
        tainted = r"request\.|input\(|sys\.argv"
    else:
        span = _call_span(line, r"\bfs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync)\(|\bres\.sendFile\(")
        tainted = r"\breq\.|process\.argv"
    if not span:
        return None
    first = split_top(line[span[1] + 1:span[2]], ",")[0]
    if re.search(tainted, first) and "basename" not in first:
        return {"span": span, "first": first}
    return None


def fix_path(ctx, lines, idx, info):
    line = lines[idx]
    m, o, c = info["span"]
    first = info["first"]
    inner = line[o + 1:c]
    new_first = ("os.path.basename(" if ctx.lang == "python" else "path.basename(") + first.strip() + ")"
    new = line[:o + 1] + new_first + inner[len(first):] + line[c:]
    pre = [py_import("os")] if ctx.lang == "python" else [js_require("path", "path", ctx)]
    return Fix({idx: new}, pre)


# ---- weak password comparison
_TOK = r"""(?:[\w.'"\[\]]|\([^()]*\))+"""
_CMP = re.compile(rf"(?P<l>{_TOK})\s*(?P<op>===|==)\s*(?P<r>{_TOK})")


def detect_weak_cmp(ctx, lines, idx):
    line = lines[idx]
    if "compare_digest" in line or "timingSafeEqual" in line or "safeEqual" in line:
        return None
    for m in _CMP.finditer(line):
        l, r = m.group("l"), m.group("r")
        if not re.search(r"(?i)password|passwd|pwd", l + r):
            continue
        if l[0] in "'\"" or r[0] in "'\"" or r[0].isdigit() or l.lower().startswith("len("):
            continue
        if r in ("None", "null", "undefined", "True", "False", "true", "false") or l in ("None", "null", "undefined"):
            continue
        if re.match(r"(os\.environ|os\.getenv|process\.env)", r):
            continue
        if l.count("(") != l.count(")") or r.count("(") != r.count(")") or l.count("[") != l.count("]") or r.count("[") != r.count("]"):
            continue
        return {"m": m}
    return None


def fix_weak_cmp(ctx, lines, idx, info):
    line, m = lines[idx], info["m"]
    l, r = m.group("l"), m.group("r")
    if ctx.lang == "python":
        rep = f"hmac.compare_digest(str({l}).encode(), str({r}).encode())"
        return Fix({idx: line[:m.start()] + rep + line[m.end():]}, [py_import("hmac")])
    rep = f"safeEqual({l}, {r})"
    return Fix({idx: line[:m.start()] + rep + line[m.end():]}, [JS_SAFE_EQUAL])


# ---- JWT signature verification disabled
def detect_jwt(ctx, lines, idx):
    return {} if re.search(r"""verify_signature["']?\s*:\s*False|jwt\.decode\(.*verify\s*=\s*False""", lines[idx]) else None


def fix_jwt(ctx, lines, idx, info):
    new = re.sub(r"(verify_signature[\"']?\s*:\s*)False", r"\1True", lines[idx])
    new = re.sub(r"(jwt\.decode\(.*verify\s*=\s*)False", r"\1True", new)
    return Fix({idx: new})


# --------------------------------------------------------------------------- rule registry
@dataclass
class Rule:
    id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    langs: tuple
    message: str
    cause: str
    impact: str
    how: dict
    detect: callable
    fix: callable


BOTH = ("python", "javascript")
PY = ("python",)

RULES = [
    Rule(
        "SQL_INJECTION", "SQL Injection", "critical", "CWE-89", "A03:2021 Injection", BOTH,
        "User-controlled data is concatenated or formatted directly into an SQL query string.",
        "The query is built by joining strings (+, f-string, %, .format or template literal), so the database cannot tell the "
        "difference between the SQL you wrote and the data a user typed.",
        "An attacker can enter input such as ' OR '1'='1 to bypass logins, read or modify any table, or delete the whole database.",
        {"python": "Use a parameterized query: put placeholders (? or %s) in the SQL text and pass the values as a separate tuple "
                   "to cursor.execute(sql, params). The driver then treats the values strictly as data.",
         "javascript": "Use a parameterized query: put placeholders (? or $1) in the SQL text and pass the values as a separate array "
                       "to db.query(sql, [values]). The driver then treats the values strictly as data."},
        detect_sqli, fix_sqli),
    Rule(
        "COMMAND_INJECTION", "OS Command Injection", "critical", "CWE-78", "A03:2021 Injection", BOTH,
        "A shell command is built from dynamic data and executed through a shell.",
        "Functions such as os.system, os.popen, subprocess(shell=True) or child_process.exec pass the whole string to a shell, "
        "which interprets characters like ; | && and $().",
        "An attacker can append their own commands (for example '; rm -rf /') and run arbitrary programs with your application's privileges.",
        {"python": "Avoid the shell. Call subprocess.run() with an argument list (shlex.split) and never shell=True; quote every "
                   "dynamic value with shlex.quote().",
         "javascript": "Use child_process.execFile(program, [args]) so arguments are passed directly to the program without a shell."},
        detect_cmdi, lambda c, l, i, n: fix_py_cmd(c, l, i, n) if c.lang == "python" else fix_js_cmd(c, l, i, n)),
    Rule(
        "CODE_EXECUTION", "Dynamic Code Execution (eval/exec)", "critical", "CWE-95", "A03:2021 Injection", BOTH,
        "eval(), exec() or new Function() executes a string as code.",
        "The program evaluates text as source code at run time. If any part of that text can be influenced by a user, "
        "the user effectively gets to write your program.",
        "Remote code execution: full control of the application, data theft and server takeover.",
        {"python": "Never eval/exec untrusted text. Use ast.literal_eval() for literals (numbers, lists, dicts) or parse input with json.loads().",
         "javascript": "Never eval untrusted text. Use JSON.parse() for data and explicit logic (lookup tables, switch statements) for behaviour."},
        detect_code_exec, fix_code_exec),
    Rule(
        "INSECURE_DESERIALIZATION", "Insecure Deserialization", "critical", "CWE-502", "A08:2021 Software and Data Integrity Failures", PY,
        "pickle/marshal/yaml.load can construct arbitrary objects from untrusted data.",
        "These formats can embed instructions that run while the data is being loaded, so loading data is the same as running code.",
        "An attacker who controls the serialized data can execute arbitrary code on your machine.",
        {"python": "Use a data-only format: json.loads() instead of pickle, and yaml.safe_load() instead of yaml.load()."},
        detect_deser, fix_deser),
    Rule(
        "HARDCODED_SECRET", "Hardcoded Credentials / Secrets", "high", "CWE-798", "A07:2021 Identification and Authentication Failures", BOTH,
        "A password, token, API key or secret is written directly in the source code.",
        "Secrets were typed into the file for convenience. Source code is copied, shared, committed to Git and logged, "
        "so every secret in it is effectively public.",
        "Anyone with access to the code (or its Git history) can log in as your application, call paid APIs or read protected data.",
        {"python": "Read secrets from environment variables (os.environ.get) or a secrets manager and keep them out of version control (.env in .gitignore).",
         "javascript": "Read secrets from environment variables (process.env.NAME) or a secrets manager and keep them out of version control (.env in .gitignore)."},
        detect_secret, fix_secret),
    Rule(
        "XSS", "Cross-Site Scripting (XSS)", "high", "CWE-79", "A03:2021 Injection", BOTH,
        "Untrusted data is written into HTML without escaping.",
        "User input is placed inside HTML (innerHTML, document.write, or an HTML response string) so the browser parses it as markup, "
        "not as plain text.",
        "An attacker can inject <script> code that steals session cookies, performs actions as the victim or defaces the page.",
        {"python": "Escape every dynamic value with html.escape() (or use a template engine with auto-escaping) before putting it in HTML.",
         "javascript": "Write user data with textContent / createTextNode (not innerHTML / document.write), and escape values placed into HTML strings."},
        detect_xss, fix_xss),
    Rule(
        "PATH_TRAVERSAL", "Path Traversal (Insecure Input Handling)", "high", "CWE-22", "A01:2021 Broken Access Control", BOTH,
        "A file path is taken directly from user input.",
        "The file name supplied by the user is used without validation, so values such as ../../etc/passwd can escape the intended folder.",
        "An attacker can read or overwrite files anywhere the application has access, such as configuration files or private keys.",
        {"python": "Reduce the input to a bare file name with os.path.basename() and join it to a fixed base directory; reject anything else.",
         "javascript": "Reduce the input to a bare file name with path.basename() and join it to a fixed base directory; reject anything else."},
        detect_path, fix_path),
    Rule(
        "TLS_VERIFICATION_DISABLED", "Certificate Verification Disabled", "high", "CWE-295", "A02:2021 Cryptographic Failures", BOTH,
        "TLS certificate validation is switched off.",
        "verify=False / rejectUnauthorized:false was probably added to silence a certificate error during development and left in place.",
        "Attackers on the network can impersonate the server (man-in-the-middle) and read or alter all traffic, including credentials.",
        {"python": "Keep certificate verification on (verify=True). If you use a private CA, pass its bundle via verify='path/to/ca.pem'.",
         "javascript": "Keep rejectUnauthorized: true. If you use a private CA, supply it with the ca option instead."},
        detect_tls, fix_tls),
    Rule(
        "JWT_SIGNATURE_DISABLED", "JWT Signature Verification Disabled", "high", "CWE-347", "A07:2021 Identification and Authentication Failures", PY,
        "JWT tokens are decoded without verifying their signature.",
        "The decode call was configured with verify_signature=False, so any token is accepted as genuine.",
        "Anyone can forge a token and impersonate any user, including administrators.",
        {"python": "Always verify the signature: jwt.decode(token, key, algorithms=['HS256'])."},
        detect_jwt, fix_jwt),
    Rule(
        "WEAK_HASH", "Weak Hashing Algorithm (MD5/SHA-1)", "medium", "CWE-327", "A02:2021 Cryptographic Failures", BOTH,
        "MD5 or SHA-1 is used for hashing.",
        "These algorithms are old and fast; collisions can be generated and passwords can be brute-forced quickly.",
        "Hashes can be forged or cracked, weakening integrity checks and password storage.",
        {"python": "Use hashlib.sha256 (or better, a password hash such as bcrypt/argon2/scrypt for passwords).",
         "javascript": "Use createHash('sha256') (or better, bcrypt/argon2/scrypt for passwords)."},
        detect_weak_hash, fix_weak_hash),
    Rule(
        "WEAK_RANDOM", "Insecure Random Number Generator", "medium", "CWE-338", "A02:2021 Cryptographic Failures", BOTH,
        "A predictable random generator is used for a security value (token, password, OTP...).",
        "random / Math.random are designed for simulations, not security; their output can be predicted from a few observed values.",
        "Attackers can guess reset tokens, session IDs or one-time codes.",
        {"python": "Use the secrets module (secrets.choice, secrets.randbelow, secrets.token_urlsafe).",
         "javascript": "Use crypto.randomInt() or crypto.randomBytes() from the crypto module."},
        detect_weak_random, fix_weak_random),
    Rule(
        "WEAK_PASSWORD_COMPARE", "Insecure Password Comparison", "medium", "CWE-208", "A07:2021 Identification and Authentication Failures", BOTH,
        "A password is compared with == / === (which also implies it is stored or handled as plain text).",
        "Normal string comparison stops at the first different character, so response time leaks how close a guess was.",
        "Timing attacks can recover secrets character by character; plain-text storage exposes every password on a leak.",
        {"python": "Compare with hmac.compare_digest() and store only salted password hashes (bcrypt/argon2).",
         "javascript": "Compare with crypto.timingSafeEqual() (wrapped in a length check) and store only salted password hashes (bcrypt/argon2)."},
        detect_weak_cmp, fix_weak_cmp),
    Rule(
        "DEBUG_ENABLED", "Debug Mode Enabled", "medium", "CWE-489", "A05:2021 Security Misconfiguration", PY,
        "The application runs with debug=True.",
        "Debug mode was left on from development; frameworks such as Flask/Django then expose an interactive debugger and stack traces.",
        "Attackers can read source code and secrets from error pages and, with Flask's Werkzeug debugger, run code remotely.",
        {"python": "Set debug=False (or read it from configuration) in anything that is not a local development run."},
        detect_debug, fix_debug),
]


# --------------------------------------------------------------------------- scanning
def _skip_lines(code: str, lang: str) -> set:
    """0-based indexes of comment lines and lines inside multi-line strings / block comments."""
    skip = set()
    lines = code.split("\n")
    for i, l in enumerate(lines):
        s = l.strip()
        if s.startswith("#") and lang == "python":
            skip.add(i)
        if s.startswith("//") and lang == "javascript":
            skip.add(i)
    if lang == "python":
        try:
            for tok in tokenize.generate_tokens(io.StringIO(code).readline):
                if tok.type == tokenize.STRING and tok.start[0] != tok.end[0]:
                    skip.update(range(tok.start[0] - 1, tok.end[0]))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass
    else:
        in_block = False
        for i, l in enumerate(lines):
            s = l.strip()
            if in_block:
                skip.add(i)
                if "*/" in s:
                    in_block = False
            elif s.startswith("/*"):
                skip.add(i)
                if "*/" not in s:
                    in_block = True
            elif s.startswith("*"):
                skip.add(i)
    return skip


def _scan_raw(code: str, lang: str):
    ctx = Ctx(code, lang)
    skip = _skip_lines(code, lang)
    raw = []
    for idx, _ in enumerate(ctx.lines):
        if idx in skip or not ctx.lines[idx].strip():
            continue
        seen_rules = set()
        for rule in RULES:
            if lang not in rule.langs or rule.id in seen_rules:
                continue
            try:
                info = rule.detect(ctx, ctx.lines, idx)
            except Exception:  # a single broken rule must never abort the whole scan
                info = None
            if info is None:
                continue
            try:
                fix = rule.fix(ctx, ctx.lines, idx, info)
            except Exception:
                fix = None
            seen_rules.add(rule.id)
            raw.append((rule, idx, fix))
    return ctx, raw


def _fix_preview(ctx: Ctx, fix: Fix):
    if not fix:
        return None
    edits = [{"line": i + 1, "before": ctx.lines[i], "after": new} for i, new in sorted(fix.edits.items())]
    prelude = [line for line, marker in fix.prelude if not re.search(marker, ctx.code)]
    return {"edits": edits, "prelude": prelude}


def compute_score(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    breakdown, total = [], 0
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            pts = counts[sev] * SEVERITY_WEIGHT[sev]
            total += pts
            breakdown.append({"severity": sev, "count": counts[sev], "weight": SEVERITY_WEIGHT[sev], "deduction": pts})
    score = max(0, 100 - total)
    if score >= 90:
        grade, rating = "A", "Secure"
    elif score >= 75:
        grade, rating = "B", "Good - minor issues"
    elif score >= 60:
        grade, rating = "C", "Moderate risk"
    elif score >= 40:
        grade, rating = "D", "High risk"
    else:
        grade, rating = "F", "Critical risk"
    if not findings:
        explanation = ("The score starts at 100 and every vulnerability found subtracts points by severity. "
                       "No vulnerabilities were detected by the SAST rules, so the score stays at 100 (grade A).")
    else:
        weights = ", ".join(f"{s.capitalize()} = -{w}" for s, w in SEVERITY_WEIGHT.items() if s in ("critical", "high", "medium", "low"))
        detail = "; ".join(f"{b['count']} {b['severity']} x {b['weight']} = -{b['deduction']}" for b in breakdown)
        explanation = (f"The score starts at 100 and each finding subtracts points by severity ({weights}). "
                       f"Your code has {len(findings)} finding(s): {detail}. Total deduction: {total}"
                       f"{' (capped so the score cannot go below 0)' if total > 100 else ''}, "
                       f"giving {score}/100 (grade {grade}, {rating}).")
    return {"score": score, "grade": grade, "rating": rating, "counts": counts, "breakdown": breakdown, "explanation": explanation}


def python_syntax_error(code: str):
    try:
        ast.parse(code)
        return None
    except SyntaxError as e:
        return f"Python syntax error on line {e.lineno}: {e.msg}"
    except (ValueError, RecursionError) as e:
        return f"Python source could not be parsed: {e}"


def scan_code(code: str, language: str | None = None, filename: str | None = None) -> dict:
    """Run the SAST engine. Returns a dict with status 'success' or 'failed'."""
    code = (code or "").replace("\r\n", "\n").replace("\r", "\n")
    if not code.strip():
        return {"status": "failed", "language": "unknown", "error": "No code to scan. Write or upload some code first.", "findings": []}
    lang = (language or "").lower() or detect_language(code, filename)
    if lang in ("auto", ""):
        lang = detect_language(code, filename)
    if lang not in SUPPORTED:
        name = display_name(lang)
        return {"status": "failed", "language": lang,
                "error": f"{name} is not supported by the SAST engine yet. Supported languages: Python and JavaScript.",
                "findings": []}
    if lang == "python":
        err = python_syntax_error(code)
        if err:
            return {"status": "failed", "language": lang, "error": err, "findings": []}
    ctx, raw = _scan_raw(code, lang)
    findings = []
    for rule, idx, fix in raw:
        findings.append({
            "rule_id": rule.id, "title": rule.title, "severity": rule.severity, "cwe": rule.cwe, "owasp": rule.owasp,
            "line": idx + 1, "snippet": ctx.lines[idx].strip()[:300], "message": rule.message,
            "cause": rule.cause, "impact": rule.impact, "how_to_fix": rule.how.get(lang) or next(iter(rule.how.values())),
            "fixable": fix is not None, "fix": _fix_preview(ctx, fix),
        })
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["line"]))
    result = {"status": "success", "language": lang, "error": None, "findings": findings, "lines_scanned": len(ctx.lines)}
    result.update(compute_score(findings))
    return result


# --------------------------------------------------------------------------- applying fixes
def _insert_prelude(code: str, lang: str, items: list) -> str:
    lines = code.split("\n")
    new = [line for line, marker in items if not re.search(marker, code)]
    seen, uniq = set(), []
    for n in new:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    if not uniq:
        return code
    pos = 0
    limit = min(len(lines), 80)
    if lang == "python":
        try:
            tree = ast.parse(code)
            for node in tree.body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    pos = max(pos, node.end_lineno)
                elif isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) \
                        and isinstance(node.value.value, str) and node is tree.body[0]:
                    pos = max(pos, node.end_lineno)
                elif not isinstance(node, (ast.Import, ast.ImportFrom)):
                    if pos == 0 and node.lineno > 1:
                        # no imports at all: put them above the first real statement, below leading comments
                        pos = node.lineno - 1
                        while pos > 0 and lines[pos - 1].strip() == "":
                            pos -= 1
                    break
        except SyntaxError:
            pos = 0
        if pos == 0:
            while pos < limit and (lines[pos].startswith("#!") or lines[pos].startswith("# -*-")):
                pos += 1
    else:
        for i in range(limit):
            s = lines[i].strip()
            if re.match(r"^(const|let|var)\s+.*=\s*require\(", s) or re.match(r"^import\s", s) or s.startswith(("'use strict'", '"use strict"')):
                pos = i + 1
        if pos == 0:
            while pos < limit and (lines[pos].startswith("#!") or lines[pos].strip().startswith("//")):
                pos += 1
    lines[pos:pos] = uniq
    return "\n".join(lines)


def _apply(ctx: Ctx, fix: Fix, lang: str) -> str:
    lines = list(ctx.lines)
    for i, new in fix.edits.items():
        lines[i] = new
    code = "\n".join(lines)
    return _insert_prelude(code, lang, fix.prelude)


def apply_fix(code: str, language: str, rule_id: str, line: int, snippet: str | None = None) -> dict:
    """Apply the fix of one finding. The finding is located by rule + snippet text (closest line wins),
    so it is still found after other fixes shifted the line numbers."""
    code = (code or "").replace("\r\n", "\n")
    lang = (language or detect_language(code)).lower()
    ctx, raw = _scan_raw(code, lang)
    candidates = [(rule, idx, fix) for rule, idx, fix in raw if rule.id == rule_id]
    if snippet:
        matched = [c for c in candidates if ctx.lines[c[1]].strip()[:300] == snippet.strip()[:300]]
        candidates = matched
    if not candidates:
        return {"code": code, "applied": False,
                "message": "This finding was not found in the current code (it may already be fixed or the line was edited)."}
    rule, idx, fix = min(candidates, key=lambda c: abs(c[1] + 1 - line))
    if not fix:
        return {"code": code, "applied": False, "message": "This finding has no automatic fix. Please edit the code manually."}
    return {"code": _apply(ctx, fix, lang), "applied": True, "message": f"Fix applied for {rule.title}."}


def apply_all_fixes(code: str, language: str) -> dict:
    """Repeatedly apply fixes (re-scanning after each) until no fixable finding remains."""
    code = (code or "").replace("\r\n", "\n")
    lang = (language or detect_language(code)).lower()
    applied, tried = 0, set()
    for _ in range(200):
        ctx, raw = _scan_raw(code, lang)
        candidate = None
        for rule, idx, fix in sorted(raw, key=lambda r: -r[1]):
            if fix and (rule.id, ctx.lines[idx]) not in tried:
                candidate = (rule, idx, fix)
                break
        if not candidate:
            break
        rule, idx, fix = candidate
        new_code = _apply(ctx, fix, lang)
        if new_code == code:
            tried.add((rule.id, ctx.lines[idx]))
            continue
        code = new_code
        applied += 1
    return {"code": code, "applied": applied > 0, "count": applied,
            "message": f"Applied {applied} automatic fix(es)." if applied else "No automatic fixes were applicable."}
