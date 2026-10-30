"""Functional testing: run submitted code in a restricted subprocess (timeout + resource limits)."""
import os
import shutil
import subprocess
import sys
import tempfile
import time

from ..core.config import settings

MAX_OUTPUT = 8000


def _py_bootstrap() -> str:
    t = settings.EXECUTION_TIMEOUT
    return (
        "import sys, runpy\n"
        "try:\n"
        "    import resource\n"
        f"    resource.setrlimit(resource.RLIMIT_CPU, ({t + 1}, {t + 1}))\n"
        "    resource.setrlimit(resource.RLIMIT_FSIZE, (10485760, 10485760))\n"
        "    resource.setrlimit(resource.RLIMIT_AS, (805306368, 805306368))\n"
        "except Exception:\n"
        "    pass\n"
        "runpy.run_path(sys.argv[1], run_name='__main__')\n"
    )


def run_code(code: str, language: str, stdin: str = "") -> dict:
    """Return {status: passed|failed|timeout|unavailable|disabled, exit_code, stdout, stderr, duration_ms}."""
    if not settings.ENABLE_CODE_EXECUTION:
        return {"status": "disabled", "exit_code": None, "stdout": "", "stderr": "Code execution is disabled by the administrator.", "duration_ms": 0}
    if language == "python":
        cmd_prefix, suffix = [sys.executable, "-I", "-c", _py_bootstrap()], ".py"
    elif language == "javascript":
        node = shutil.which("node")
        if not node:
            return {"status": "unavailable", "exit_code": None, "stdout": "", "stderr": "Node.js is not installed, so JavaScript cannot be executed.", "duration_ms": 0}
        cmd_prefix, suffix = [node], ".js"
    else:
        return {"status": "unavailable", "exit_code": None, "stdout": "", "stderr": f"Execution is not supported for {language}.", "duration_ms": 0}

    env = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="securecode_") as tmp:
        path = os.path.join(tmp, "main" + suffix)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(code)
        try:
            proc = subprocess.run(
                cmd_prefix + [path], input=stdin or "", capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=settings.EXECUTION_TIMEOUT, cwd=tmp, env=env,
            )
            status = "passed" if proc.returncode == 0 else "failed"
            return {"status": status, "exit_code": proc.returncode, "stdout": proc.stdout[:MAX_OUTPUT],
                    "stderr": proc.stderr[:MAX_OUTPUT], "duration_ms": int((time.time() - started) * 1000)}
        except subprocess.TimeoutExpired as e:
            out = (e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))[:MAX_OUTPUT]
            return {"status": "timeout", "exit_code": None, "stdout": out,
                    "stderr": f"Stopped after {settings.EXECUTION_TIMEOUT}s. Long-running programs such as web servers are expected to time out.",
                    "duration_ms": int((time.time() - started) * 1000)}
        except Exception as e:  # pragma: no cover
            return {"status": "failed", "exit_code": None, "stdout": "", "stderr": f"Could not execute code: {e}", "duration_ms": 0}
