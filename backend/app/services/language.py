"""Language detection (filename extension first, then content heuristics)."""
import re

EXT_MAP = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".php": "php", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp",
    ".go": "go", ".rb": "ruby", ".rs": "rust", ".html": "html", ".sql": "sql",
}

SUPPORTED = {"python", "javascript"}

_SIGNATURES = {
    "python": [r"^\s*def \w+\(.*\)\s*:", r"^\s*import \w+", r"^\s*from [\w.]+ import ", r"\bprint\(",
               r"^\s*if __name__ ==", r"^\s*elif .*:", r"^\s*class \w+(\(.*\))?:", r"\bself\.", r"^\s*#(?!include)"],
    "javascript": [r"\bconsole\.log\(", r"\b(const|let|var) \w+\s*=", r"=>", r"\brequire\(", r"^\s*function \w+\(",
                   r"\bdocument\.", r"\bmodule\.exports", r"^\s*import .* from ['\"]", r"\bwindow\."],
    "java": [r"\bpublic (static )?(void|class)\b", r"System\.out\.print", r"\bimport java\."],
    "php": [r"<\?php", r"\$\w+\s*=", r"\becho\b"],
    "c": [r"#include\s*<", r"\bint main\(", r"\bprintf\("],
    "cpp": [r"#include\s*<iostream>", r"\bstd::", r"\bcout\s*<<"],
    "go": [r"^package \w+", r"\bfunc \w+\(", r"\bfmt\.Print"],
    "ruby": [r"^\s*def \w+\s*$", r"\bputs\b", r"^\s*end\s*$"],
    "sql": [r"(?i)^\s*(select|insert into|update|delete from|create table)\b"],
    "html": [r"(?i)<!doctype html", r"(?i)<html", r"(?i)<div"],
}


def detect_language(code: str, filename: str | None = None) -> str:
    """Return a language id such as 'python', 'javascript' or 'unknown'."""
    if filename:
        lower = filename.lower()
        for ext, lang in EXT_MAP.items():
            if lower.endswith(ext):
                return lang
    if not code or not code.strip():
        return "unknown"
    scores = {}
    for lang, patterns in _SIGNATURES.items():
        score = 0
        for p in patterns:
            if re.search(p, code, re.MULTILINE):
                score += 1
        scores[lang] = score
    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return "unknown"
    # tie-break between python / javascript using strong tokens
    if scores.get("python", 0) == scores.get("javascript", 0) and scores["python"] > 0:
        if re.search(r"\b(def|elif|None|True|False)\b", code):
            return "python"
        return "javascript"
    return best


def display_name(lang: str) -> str:
    return {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript", "java": "Java",
            "php": "PHP", "c": "C", "cpp": "C++", "csharp": "C#", "go": "Go", "ruby": "Ruby",
            "rust": "Rust", "html": "HTML", "sql": "SQL"}.get(lang, "Unknown")
