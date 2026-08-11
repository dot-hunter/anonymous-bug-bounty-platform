"""
app_vuln — deliberately vulnerable fixture for agentic PoC validation tests.

Functions:
  run_cmd(user_input)   : command injection (os.system)         -> CONFIRMED
  read_note(user_input) : path traversal (open("notes/"+input))  -> CONFIRMED
  echo_safe(user_input) : HTML-escaped echo (sanitizer)          -> BLOCKED
  add(a, b)             : clean arithmetic                       -> no finding
Only used in sandboxed tests on this fixture. Do not deploy.
"""

import os
import html
import shlex
import subprocess


def run_cmd_safe(user_input: str) -> str:
    """Safe: shell-quoted input — sanitizer present, auditor must disprove (=> BLOCKED)."""
    return subprocess.run("echo " + shlex.quote(user_input), shell=True,
                          capture_output=True, text=True).stdout


def run_cmd(user_input: str) -> str:
    """Vulnerable: unsanitized shell execution."""
    return subprocess.run("echo " + user_input, shell=True, capture_output=True,
                          text=True).stdout  # noqa: S602


def run_cmd_popen(user_input: str) -> str:
    """Vulnerable (variant): os.popen shell concat."""
    return os.popen("echo " + user_input).read()  # noqa: S605


def read_note(user_input: str) -> str:
    """Vulnerable: path traversal through notes/ prefix."""
    with open("notes/" + user_input) as f:  # noqa: PTH123
        return f.read()


def echo_safe(user_input: str) -> str:
    """Sanitized: controlled output."""
    return html.escape(user_input)


def add(a: int, b: int) -> int:
    """Clean function — no sink, no finding."""
    return a + b


if __name__ == "__main__":
    print(run_cmd("hello"))
    print(read_note("hello.txt"))
    print(echo_safe("<b>x</b>"))
    print(add(2, 3))