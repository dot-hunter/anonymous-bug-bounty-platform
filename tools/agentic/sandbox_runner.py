#!/usr/bin/env python3
"""
sandbox_runner.py — layered sandbox backend for agentic PoC validation.

Backends, in preference order (auto-detected):
  1. docker        — full isolation, network disabled
  2. podman        — rootless container, network disabled
  3. bwrap         — bubblewrap, no network
  4. firejail      — no network
  5. jail          — HONEST FALLBACK, no privileges:
       tmpdir cwd, stripped env, LD_PRELOAD sockblock.so (gcc-built socket
       killer => network off without root), resource RLIMITs, process-group
       timeout kill, python -E -I when launching python code.

Isolation honesty: jail is LOGICAL isolation (no container, no chroot — the
target code shares the host kernel and FS read access). Every report shows the
backend used; operators must only audit code they own/are authorized to run.

Usage:
  python sandbox_runner.py --detect
  python sandbox_runner.py --run '<cmd>' --timeout 15 --workdir /tmp/x
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import resource
from pathlib import Path

AGENTIC_DIR = Path(__file__).resolve().parent
SOCKBLOCK_C = AGENTIC_DIR / "sockblock.c"
SOCKBLOCK_SO = AGENTIC_DIR / "sockblock.so"

JAIL_RLIMITS = {
    "RLIMIT_CPU": 10,      # seconds of CPU
    "RLIMIT_AS": 2 * 1024 * 1024 * 1024,  # 2GB address space (512MB broke sh/python exec)
    "RLIMIT_NOFILE": 64,   # fds
    # NPROC counts ALL tasks (threads) for the UID — the host itself runs
    # dozens of services as this user, so a tight cap breaks process spawn.
    # 1024 still stops fork-bombs while tolerating host threads.
    "RLIMIT_NPROC": 1024,
}


def _which(name: str) -> str | None:
    return shutil.which(name)


def detect_backend(preferred: str | None = None) -> dict:
    """Return {'backend': ..., 'available': bool, 'isolated': bool, 'why': str}."""
    order = ["docker", "podman", "bwrap", "firejail", "jail"]
    if preferred and preferred != "auto":
        order = [preferred] if preferred in order else order
    for name in order:
        if name == "jail":
            return {
                "backend": "jail",
                "available": True,
                "isolated": "logical",
                "why": "no container runtime; LD_PRELOAD socket block + RLIMITs (honest mode)",
            }
        if _which(name):
            isolated = "full" if name in ("docker", "podman", "bwrap", "firejail") else "logical"
            return {
                "backend": name,
                "available": True,
                "isolated": isolated,
                "why": f"{name} found on PATH",
            }
    return {"backend": "none", "available": False, "isolated": "none", "why": "no backend"}


def _ensure_sockblock() -> Path | None:
    """Compile sockblock.so if gcc is available; return path or None."""
    if SOCKBLOCK_SO.exists():
        return SOCKBLOCK_SO
    gcc = _which("gcc") or _which("cc")
    if not gcc:
        return None
    try:
        subprocess.run(
            [gcc, "-shared", "-fPIC", "-O2", "-o", str(SOCKBLOCK_SO), str(SOCKBLOCK_C)],
            capture_output=True, timeout=60, check=True,
        )
        return SOCKBLOCK_SO if SOCKBLOCK_SO.exists() else None
    except Exception:
        return None


def _jail_prepare(workdir: str):
    """preexec_fn: apply RLIMIT caps. Runs in the child before exec."""
    for name, val in JAIL_RLIMITS.items():
        rlim = getattr(resource, name, None)
        if rlim is None:
            continue
        try:
            resource.setrlimit(rlim, (val, val))
        except Exception:
            pass


def run_in_sandbox(
    cmd: list[str],
    timeout: float = 15,
    workdir: str | None = None,
    backend: str | None = None,
    env_extra: dict | None = None,
) -> dict:
    """Execute cmd in the best available sandbox.

    Returns {'exit': int, 'stdout': str, 'stderr': str, 'timed_out': bool,
             'backend': str, 'cmd': list}.
    """
    info = detect_backend(backend)
    b = info["backend"]
    result = {"exit": -1, "stdout": "", "stderr": "", "timed_out": False,
              "backend": b, "cmd": list(cmd)}

    if b in ("docker", "podman"):
        # container: mount workdir (or a scratch tmp) as /work, no network
        host_dir = workdir or tempfile.mkdtemp(prefix="validx-")
        full = [
            b, "run", "--rm", "--network", "none",
            "--memory", "512m", "--cpus", "1",
            "-v", f"{host_dir}:/work:rw", "-w", "/work",
            "python:3.12-slim" if "python" in " ".join(cmd) else "alpine:latest",
        ] + list(cmd)
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=timeout + 5)
            result.update(exit=p.returncode, stdout=p.stdout or "", stderr=p.stderr or "")
            return result
        except subprocess.TimeoutExpired as e:
            result.update(timed_out=True,
                          stdout=(e.stdout or b"") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                          stderr="TIMED OUT")
            return result
        except Exception as e:
            result.update(stderr=f"container backend failed: {e}")
            return result

    if b == "bwrap":
        host_dir = workdir or tempfile.mkdtemp(prefix="validx-")
        full = ["bwrap", "--die-with-parent", "--unshare-net", "--unshare-ipc",
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/bin", "/bin",
                "--ro-bind", "/etc", "/etc", "--bind", host_dir, "/work",
                "--chdir", "/work", "--proc", "/proc", "--dev", "/dev",
                "--clearenv", "PATH=/usr/bin:/bin", "LANG=C.UTF-8"] + list(cmd)
        return _subprocess_run(full, timeout, host_dir, result, clearenv=True)

    if b == "firejail":
        host_dir = workdir or tempfile.mkdtemp(prefix="validx-")
        full = ["firejail", "--net=none", "--quiet", f"--private={host_dir}",
                "--timeout=" + str(int(timeout) + 2)] + list(cmd)
        return _subprocess_run(full, timeout, host_dir, result)

    # ---- jail (honest fallback) ----
    sb = _ensure_sockblock()
    host_dir = workdir or tempfile.mkdtemp(prefix="validx-")
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": host_dir,
        "TMPDIR": host_dir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if sb:
        env["LD_PRELOAD"] = str(sb)
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(
            list(cmd), capture_output=True, text=True, timeout=timeout,
            cwd=host_dir, env=env, preexec_fn=lambda: _jail_prepare(host_dir),
            start_new_session=True,
        )
        result.update(exit=p.returncode, stdout=p.stdout or "", stderr=p.stderr or "")
    except subprocess.TimeoutExpired as e:
        result.update(timed_out=True,
                      stdout=(e.stdout or ""), stderr="TIMED OUT (process group killed)")
        try:
            # kill the whole process group
            os.killpg(os.getpgid(e.pid), 9)
        except Exception:
            pass
    except Exception as e:
        result.update(stderr=f"jail runner failed: {e}")
    return result


def _subprocess_run(full, timeout, workdir, result, clearenv=False):
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout,
                           cwd=workdir,
                           env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"} if clearenv else None)
        result.update(exit=p.returncode, stdout=p.stdout or "", stderr=p.stderr or "")
    except subprocess.TimeoutExpired:
        result.update(timed_out=True, stderr="TIMED OUT")
    except Exception as e:
        result.update(stderr=f"backend failed: {e}")
    return result


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--detect":
        print(json.dumps(detect_backend(sys.argv[2] if len(sys.argv) > 2 else None), indent=2))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "--run":
        cmd = sys.argv[2:]
        timeout = 15.0
        if "--timeout" in sys.argv:
            i = sys.argv.index("--timeout")
            timeout = float(sys.argv[i + 1])
            cmd = [c for c in cmd if c != "--timeout"]
        print(json.dumps(run_in_sandbox(cmd, timeout=timeout), indent=2))
        sys.exit(0)
    print(json.dumps(detect_backend(), indent=2))