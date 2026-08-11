"""Patched (fixed) fixture for retest-mode demo — all sinks hardened."""

import os
import html
import shlex
import subprocess


def run_cmd_safe(user_input: str) -> str:
    """Safe: shell-quoted input."""
    return subprocess.run("echo " + shlex.quote(user_input), shell=True,
                          capture_output=True, text=True).stdout


def run_cmd(user_input: str) -> str:
    """FIXED: list-form subprocess — no shell interpretation."""
    return subprocess.run(["echo", user_input], capture_output=True,
                          text=True).stdout


def run_cmd_popen(user_input: str) -> str:
    """FIXED: replaced os.popen with list-form subprocess."""
    return subprocess.run(["echo", user_input], capture_output=True,
                          text=True).stdout


def read_note(user_input: str) -> str:
    """FIXED: basename-only — traversal cannot escape the notes dir."""
    safe = os.path.basename(user_input)
    with open(os.path.join("notes", safe)) as f:  # noqa: PTH123
        return f.read()


def echo_safe(user_input: str) -> str:
    """Sanitized output (never a candidate in triage: html.escape)."""
    return html.escape(user_input)


def add(a: int, b: int) -> int:
    return a + b