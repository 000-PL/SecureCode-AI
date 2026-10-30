"""Low-level, string-aware helpers used by the SAST rules and auto-fixers."""
import re

QUOTES = "'\"`"
OPEN, CLOSE = "([{", ")]}"

SQL_RE = re.compile(
    r"(\bSELECT\b.+\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b.+\bSET\b|\bDELETE\s+FROM\b)", re.I | re.S
)


def walk(s: str, start: int = 0):
    """Yield (index, char) for every character that is NOT inside a quoted string."""
    q = None
    i = start
    n = len(s)
    while i < n:
        ch = s[i]
        if q:
            if ch == "\\":
                i += 2
                continue
            if ch == q:
                q = None
            i += 1
            continue
        if ch in QUOTES:
            q = ch
            i += 1
            continue
        yield i, ch
        i += 1


def find_matching(s: str, open_idx: int) -> int:
    depth = 0
    for i, ch in walk(s, open_idx):
        if ch in OPEN:
            depth += 1
        elif ch in CLOSE:
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_top(s: str, sep: str) -> list:
    """Split on a single-char separator at bracket depth 0, outside strings (raw pieces)."""
    parts, depth, last = [], 0, 0
    for i, ch in walk(s):
        if ch in OPEN:
            depth += 1
        elif ch in CLOSE:
            depth -= 1
        elif ch == sep and depth == 0:
            if sep == "+" and (s[i + 1:i + 2] in ("=", "+") or s[i - 1:i] == "+"):
                continue
            parts.append(s[last:i])
            last = i + 1
    parts.append(s[last:])
    return parts


def find_top_char(s: str, target: str) -> int:
    depth = 0
    for i, ch in walk(s):
        if ch in OPEN:
            depth += 1
        elif ch in CLOSE:
            depth -= 1
        elif ch == target and depth == 0:
            return i
    return -1


_LIT = re.compile(r"""^[rRuUbB]?(["'])(.*)\1$""", re.S)


def literal_text(tok: str):
    """Return the raw body of a plain string literal, else None."""
    tok = tok.strip()
    m = _LIT.match(tok)
    if m:
        q, body = m.group(1), m.group(2)
        if re.search(r"(?<!\\)" + re.escape(q), body):
            return None
        return body
    if len(tok) >= 2 and tok[0] == "`" and tok[-1] == "`" and "${" not in tok:
        return tok[1:-1]
    return None


def _merge(segs: list) -> list:
    out = []
    for kind, val in segs:
        if kind == "text" and out and out[-1][0] == "text":
            out[-1] = ("text", out[-1][1] + val)
        elif kind == "text" and val == "":
            continue
        else:
            out.append((kind, val))
    return out


def _cut_spec(expr: str) -> str:
    depth = 0
    for i, ch in walk(expr):
        if ch in OPEN:
            depth += 1
        elif ch in CLOSE:
            depth -= 1
        elif depth == 0 and ch in ":!" and expr[i + 1:i + 2] != "=":
            return expr[:i]
    return expr


def parse_fstring(tok: str):
    m = re.match(r"""^[fF](["'])(.*)\1$""", tok.strip(), re.S)
    if not m:
        return None
    body, segs, i, buf = m.group(2), [], 0, ""
    while i < len(body):
        if body.startswith("{{", i):
            buf += "{"
            i += 2
        elif body.startswith("}}", i):
            buf += "}"
            i += 2
        elif body[i] == "{":
            depth, j = 1, i + 1
            while j < len(body) and depth:
                depth += (body[j] == "{") - (body[j] == "}")
                j += 1
            expr = _cut_spec(body[i + 1:j - 1]).strip()
            segs.append(("text", buf))
            buf = ""
            segs.append(("expr", expr))
            i = j
        else:
            buf += body[i]
            i += 1
    segs.append(("text", buf))
    return _merge(segs)


def parse_template(tok: str):
    tok = tok.strip()
    if not (len(tok) >= 2 and tok[0] == "`" and tok[-1] == "`"):
        return None
    body, segs, i, buf = tok[1:-1], [], 0, ""
    while i < len(body):
        if body.startswith("${", i):
            depth, j = 1, i + 2
            while j < len(body) and depth:
                depth += (body[j] == "{") - (body[j] == "}")
                j += 1
            segs.append(("text", buf))
            buf = ""
            segs.append(("expr", body[i + 2:j - 1].strip()))
            i = j
        else:
            buf += body[i]
            i += 1
    segs.append(("text", buf))
    return _merge(segs)


def to_parts(expr: str):
    """Break a string-building expression into [("text", s) | ("expr", e)].

    Understands Python f-strings, JS template literals, "%" formatting, str.format()
    and "+" concatenation. Returns None if the expression is not a string builder.
    """
    e = expr.strip()
    if e.endswith(";"):
        e = e[:-1].strip()
    if e.startswith("(") and find_matching(e, 0) == len(e) - 1:
        e = e[1:-1].strip()
    segs = parse_fstring(e)
    if segs is None:
        segs = parse_template(e)
    if segs is not None:
        return segs

    m = re.match(r"""^(["'])(.*?)\1\s*\.format\((.*)\)$""", e, re.S)
    if m:
        args = [a.strip() for a in split_top(m.group(3), ",") if a.strip()]
        out, i, auto = [], 0, 0
        for piece in re.split(r"(\{\w*\})", m.group(2)):
            pm = re.fullmatch(r"\{(\w*)\}", piece)
            if pm:
                key = pm.group(1)
                if key == "":
                    val = args[auto] if auto < len(args) else "None"
                    auto += 1
                elif key.isdigit():
                    val = args[int(key)] if int(key) < len(args) else "None"
                else:
                    val = next((a.split("=", 1)[1].strip() for a in args if a.startswith(key + "=")), key)
                out.append(("expr", val))
            else:
                out.append(("text", piece))
        return _merge(out)

    pidx = find_top_char(e, "%")
    if pidx > 0:
        lit = literal_text(e[:pidx])
        if lit is not None:
            right = e[pidx + 1:].strip()
            if right.startswith("(") and find_matching(right, 0) == len(right) - 1:
                args = [a.strip() for a in split_top(right[1:-1], ",") if a.strip()]
            else:
                args = [right]
            out, k = [], 0
            for piece in re.split(r"(%[sdifr%])", lit):
                if piece == "%%":
                    out.append(("text", "%"))
                elif re.fullmatch(r"%[sdifr]", piece):
                    out.append(("expr", args[k] if k < len(args) else "None"))
                    k += 1
                else:
                    out.append(("text", piece))
            return _merge(out)

    pieces = split_top(e, "+")
    if len(pieces) > 1:
        out = []
        for p in pieces:
            lit = literal_text(p)
            out.append(("text", lit) if lit is not None else ("expr", p.strip()))
        return _merge(out)
    return None


def is_dynamic(parts) -> bool:
    return bool(parts) and any(k == "expr" for k, _ in parts)


def text_of(parts) -> str:
    return "".join(v for k, v in parts if k == "text")


def emit_literal(text: str) -> str:
    """Emit text as a double-quoted literal (valid in both Python and JavaScript)."""
    return '"' + re.sub(r'(?<!\\)"', r'\\"', text) + '"'


def parameterize(parts, placeholder, wrap):
    """Turn string-building parts into (sql_text, [param expressions]).

    placeholder(n) -> placeholder for the n-th parameter (1-based).
    wrap(expr)     -> expression converting a value to str (used for LIKE patterns).
    """
    parts = [list(p) for p in parts]
    sql, params = "", []
    for k, (kind, val) in enumerate(parts):
        if kind == "text":
            sql += val
            continue
        pre = suf = ""
        m = re.search(r"""(['"])(%?)$""", sql)
        if m:
            q = m.group(1)
            nxt = parts[k + 1][1] if k + 1 < len(parts) and parts[k + 1][0] == "text" else ""
            mm = re.match(r"(%?)" + re.escape(q), nxt)
            if mm:
                pre = m.group(2)
                suf = mm.group(1)
                sql = sql[:m.start()]
                parts[k + 1][1] = nxt[len(mm.group(0)):]
        params.append(f'"{pre}" + {wrap(val)}' + (f' + "{suf}"' if suf else "") if (pre or suf) else val)
        sql += placeholder(len(params))
    return sql, params


def indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]
