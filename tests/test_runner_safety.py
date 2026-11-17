"""Resource-safety tests for the managed subprocess executor."""
import sys

from backend import runner


def test_runner_caps_retained_stdout_and_stderr(monkeypatch):
    monkeypatch.setattr(runner, "MAX_STDOUT_BYTES", 4096)
    monkeypatch.setattr(runner, "MAX_STDERR_BYTES", 4096)
    code = (
        "import sys; "
        "sys.stdout.write('O' * 200000); "
        "sys.stderr.write('E' * 200000)"
    )
    result = runner.Executor().run([sys.executable, "-c", code], timeout=10)
    assert result.returncode == 0
    assert len(result.stdout.encode("utf-8")) <= 4200
    assert len(result.stderr.encode("utf-8")) <= 4200
    assert "stdout truncated" in result.stdout
    assert "stderr truncated" in result.stderr


def test_runner_passes_stdin_without_deadlock():
    result = runner.Executor().run(
        [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
        timeout=5,
        stdin_data="wd-neo-input",
    )
    assert result.ok
    assert "wd-neo-input" in result.stdout


def test_runner_marks_timed_out_process():
    result = runner.Executor().run(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout=1,
    )
    assert result.timed_out
    assert result.returncode != 0



def test_runner_kills_orphaned_child_holding_output_pipes():
    import os
    import time

    if os.name != "posix":
        return
    child = (
        "import signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(30)"
    )
    parent = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', " + repr(child) + "]); "
        "print('child-started', flush=True)"
    )
    started = time.monotonic()
    result = runner.Executor().run([sys.executable, "-c", parent], timeout=5)
    assert result.ok
    assert "child-started" in result.stdout
    assert time.monotonic() - started < 12
