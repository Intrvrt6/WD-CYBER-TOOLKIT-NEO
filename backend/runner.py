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


MAX_STDOUT_BYTES = max(4096, int(os.environ.get("WD_MAX_STDOUT_BYTES", str(1024 * 1024))))
MAX_STDERR_BYTES = max(4096, int(os.environ.get("WD_MAX_STDERR_BYTES", str(256 * 1024))))


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
    def _signal_group(p: subprocess.Popen, sig: int) -> None:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(p.pid), sig)
            elif sig == signal.SIGTERM:
                p.terminate()
            else:
                p.kill()
        except (ProcessLookupError, PermissionError, OSError):
            try:
                if sig == signal.SIGKILL:
                    p.kill()
                elif sig == signal.SIGTERM:
                    p.terminate()
            except Exception:
                pass

    @classmethod
    def _kill(cls, p: subprocess.Popen) -> None:
        """Terminate a complete process group, escalating if it ignores SIGTERM."""
        if p.poll() is not None:
            return
        cls._signal_group(p, signal.SIGTERM)
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                cls._signal_group(p, signal.SIGKILL)
            else:
                p.kill()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    @staticmethod
    def _drain(stream, limit: int, output: bytearray) -> None:
        """Drain a pipe completely while retaining only its last limit bytes."""
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                output.extend(chunk)
                overflow = len(output) - limit
                if overflow > 0:
                    del output[:overflow]
        finally:
            try:
                stream.close()
            except OSError:
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
                argv_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
                cwd=cwd, env=e, start_new_session=True,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            )
        except Exception as exc:  # pragma: no cover
            return ExecResult(command=printable, returncode=1, argv=argv_list, stderr=str(exc))
        with self._lock:
            self._procs[p.pid] = p
        stdout_tail, stderr_tail = bytearray(), bytearray()
        readers = [
            threading.Thread(target=self._drain, args=(p.stdout, MAX_STDOUT_BYTES, stdout_tail), daemon=True),
            threading.Thread(target=self._drain, args=(p.stderr, MAX_STDERR_BYTES, stderr_tail), daemon=True),
        ]
        for thread in readers:
            thread.start()
        writer = None
        if stdin_data is not None:
            def _write_stdin():
                try:
                    p.stdin.write(stdin_data.encode("utf-8"))
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        p.stdin.close()
                    except OSError:
                        pass
            writer = threading.Thread(target=_write_stdin, daemon=True)
            writer.start()
        timed_out = False
        try:
            try:
                p.wait(timeout=max(1, timeout))
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill(p)
            if writer is not None:
                writer.join(timeout=2)
            for thread in readers:
                thread.join(timeout=3)
            if p.poll() is None:
                self._kill(p)
            returncode = p.returncode if p.returncode is not None else 124
        finally:
            with self._lock:
                self._procs.pop(p.pid, None)
        out = bytes(stdout_tail).decode("utf-8", errors="replace")
        err = bytes(stderr_tail).decode("utf-8", errors="replace")
        if len(stdout_tail) >= MAX_STDOUT_BYTES:
            out = "[... earlier stdout truncated ...]\n" + out
        if len(stderr_tail) >= MAX_STDERR_BYTES:
            err = "[... earlier stderr truncated ...]\n" + err
        return ExecResult(
            command=printable, returncode=returncode, stdout=out, stderr=err,
            timed_out=timed_out, duration_s=time.time() - started, argv=argv_list,
        )


executor = Executor()

def run(argv, timeout: int = 120, **kw) -> ExecResult:
    return executor.run(argv, timeout=timeout, **kw)
