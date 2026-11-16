"""Managed subprocess execution with timeout, capture, retcode and audit hooks.

Every engine goes through `run()` so that emergency stop can terminate the
process group and every executed command is recorded reproducibly.
"""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class ExecResult:
    command: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    missing: bool = False
    duration_s: float = 0.0
    argv: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing

    def as_evidence(self) -> dict:
        return {
            "type": "command_output",
            "command": " ".join(shlex.quote(a) for a in self.argv) if self.argv else self.command,
            "returncode": self.returncode,
            "stdout": self.stdout[-20000:],
            "stderr": self.stderr[-4000:],
            "timed_out": self.timed_out,
            "duration_s": round(self.duration_s, 3),
            "missing_executable": self.missing,
        }


class Executor:
    """Tracks live process groups so a global stop can kill them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: dict[int, subprocess.Popen] = {}
        self._stop = threading.Event()

    def reset(self) -> None:
        with self._lock:
            self._procs.clear()
        self._stop.clear()

    def request_stop(self) -> None:
        self._stop.set()
        with self._lock:
            procs = list(self._procs.values())
        for p in procs:
            self._kill(p)

    def stopped(self) -> bool:
        return self._stop.is_set()

    @staticmethod
    def _kill(p: subprocess.Popen) -> None:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            else:
                p.terminate()
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    def run(self, argv: Iterable[str] | str, timeout: int = 120, cwd: str | None = None,
            env: dict | None = None, stdin_data: str | None = None) -> ExecResult:
        import time
        argv_list = shlex.split(argv) if isinstance(argv, str) else list(argv)
        printable = " ".join(shlex.quote(a) for a in argv_list)
        if not argv_list:
            return ExecResult(command=printable, returncode=2, stderr="empty command", missing=True)
        if shutil.which(argv_list[0]) is None:
            return ExecResult(command=printable, returncode=127, argv=argv_list, missing=True,
                              stderr=f"executable not found: {argv_list[0]}")
        if self._stop.is_set():
            return ExecResult(command=printable, returncode=143, argv=argv_list,
                              stderr="execution blocked: emergency stop active")
        started = time.time()
        e = dict(os.environ)
        if env:
            e.update({k: str(v) for k, v in env.items()})
        try:
            p = subprocess.Popen(
                argv_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=cwd, env=e, start_new_session=True,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            )
        except Exception as exc:  # pragma: no cover
            return ExecResult(command=printable, returncode=1, argv=argv_list, stderr=str(exc))
        with self._lock:
            self._procs[p.pid] = p
        try:
            out, err = p.communicate(input=stdin_data, timeout=max(1, timeout))
            timed_out = False
        except subprocess.TimeoutExpired:
            self._kill(p)
            try:
                out, err = p.communicate(timeout=5)
            except Exception:
                out, err = "", ""
            timed_out = True
        finally:
            with self._lock:
                self._procs.pop(p.pid, None)
        return ExecResult(
            command=printable, returncode=p.returncode, stdout=out or "", stderr=err or "",
            timed_out=timed_out, duration_s=time.time() - started, argv=argv_list,
        )


executor = Executor()

def run(argv, timeout: int = 120, **kw) -> ExecResult:
    return executor.run(argv, timeout=timeout, **kw)
