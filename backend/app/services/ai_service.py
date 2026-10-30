"""AI module: explains a vulnerability (cause / impact / how to fix) and prepares the remediation.

Built-in knowledge base is always available. If ANTHROPIC_API_KEY is configured and the user enabled the
external AI service, an LLM rewrites the explanation in friendlier language. The secure *code* always comes from the
deterministic fixer and is verified by re-scanning, so an LLM can never inject an unvalidated fix.
"""
import json
import urllib.request

from ..core.config import settings

STEP_HINTS = {
    "SQL_INJECTION": ["Find the line where the SQL text is joined with user data.",
                      "Replace every inserted value with a placeholder (? or %s).",
                      "Pass the values as a separate tuple/array to execute()/query().",
                      "Re-scan to confirm the query is now parameterized."],
    "COMMAND_INJECTION": ["Stop building a shell command string.",
                          "Call the program directly with an argument list (no shell).",
                          "Quote or validate every user supplied argument.",
                          "Re-scan to confirm no shell is used."],
    "CODE_EXECUTION": ["Identify what the evaluated text is supposed to contain.",
                       "Replace eval/exec with a safe parser (json.loads / ast.literal_eval / JSON.parse).",
                       "Re-scan to confirm no dynamic code execution remains."],
    "INSECURE_DESERIALIZATION": ["Replace pickle/yaml.load with a data-only format.",
                                 "Use json.loads() or yaml.safe_load().",
                                 "Re-scan to confirm."],
    "HARDCODED_SECRET": ["Remove the secret from the source file.",
                         "Read it from an environment variable at run time.",
                         "Rotate the exposed secret - treat it as compromised.",
                         "Add your .env file to .gitignore."],
    "XSS": ["Find where user data is placed inside HTML.",
            "Escape it (html.escape / escapeHtml) or use textContent instead of innerHTML.",
            "Re-scan to confirm."],
    "PATH_TRAVERSAL": ["Never use a user-supplied path directly.",
                       "Reduce it to a file name with basename and join it to a fixed folder.",
                       "Re-scan to confirm."],
}
DEFAULT_STEPS = ["Locate the highlighted line.", "Apply the secure replacement shown in the remediation.", "Re-scan to confirm the issue is gone."]


def explain_finding(finding, language: str, use_llm: bool = True) -> dict:
    base = {
        "summary": finding.message,
        "cause": finding.cause,
        "impact": finding.impact,
        "how_to_fix": finding.how_to_fix,
        "steps": STEP_HINTS.get(finding.rule_id, DEFAULT_STEPS),
        "source": "builtin",
    }
    if use_llm and settings.ANTHROPIC_API_KEY:
        enhanced = _llm_explain(finding, language)
        if enhanced:
            base.update(enhanced)
            base["source"] = "llm"
    return base


def _llm_explain(finding, language: str):
    prompt = (
        "You are a secure-coding tutor for beginner developers. Explain this static-analysis finding in simple language.\n"
        f"Language: {language}\nVulnerability: {finding.title} ({finding.cwe}), severity {finding.severity}\n"
        f"Line {finding.line}: {finding.snippet}\n\n"
        'Reply with ONLY a JSON object: {"summary": "...", "cause": "...", "impact": "...", "how_to_fix": "...", "steps": ["..."]}. '
        "Keep each field under 60 words and do not include code fences."
    )
    body = json.dumps({"model": settings.AI_MODEL, "max_tokens": 700, "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"content-type": "application/json", "x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        parsed = json.loads(text)
        out = {k: parsed[k] for k in ("summary", "cause", "impact", "how_to_fix") if isinstance(parsed.get(k), str) and parsed[k].strip()}
        if isinstance(parsed.get("steps"), list) and parsed["steps"]:
            out["steps"] = [str(s) for s in parsed["steps"]][:6]
        return out or None
    except Exception:
        return None
