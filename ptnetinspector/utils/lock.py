"""Simple process-level lock to prevent concurrent runs of ptnetinspector."""

from __future__ import annotations

import atexit
import os
import fcntl
from pathlib import Path

from ptnetinspector.utils.path import get_output_dir


_LOCK_FD: int | None = None


def _is_process_running(pid: int) -> bool:
    """Return True if a process with the given PID appears to be alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Lack of permission likely means the process exists but is owned elsewhere
        return True
    return True


def _cleanup_stale_lock(lock_file: Path) -> bool:
    """Remove lock file if the recorded PID is no longer running."""
    try:
        data = lock_file.read_text().strip()
        pid = int(data)
    except (OSError, ValueError):
        pid = None

    if pid is not None and _is_process_running(pid):
        return False

    try:
        lock_file.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _release_lock() -> None:
    """Release the acquired lock if held."""
    global _LOCK_FD
    if _LOCK_FD is None:
        return
    try:
        fcntl.flock(_LOCK_FD, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(_LOCK_FD)
    except OSError:
        pass
    _LOCK_FD = None


def acquire_global_lock(lock_path: Path | None = None) -> None:
    """Acquire a non-blocking lock to ensure single active instance.

    Raises RuntimeError if the lock cannot be acquired.
    """

    global _LOCK_FD
    if _LOCK_FD is not None:
        return

    lock_file = lock_path or (get_output_dir() / ".ptnetinspector.lock")
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    def _attempt_lock() -> int:
        fd_local = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd_local, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd_local
        except OSError:
            os.close(fd_local)
            raise

    try:
        fd = _attempt_lock()
    except OSError as exc:
        # If the existing lock holder is gone, clean the file and retry once
        if _cleanup_stale_lock(lock_file):
            fd = _attempt_lock()
        else:
            raise RuntimeError("Another ptnetinspector process is already running.") from exc

    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    _LOCK_FD = fd
    atexit.register(_release_lock)
