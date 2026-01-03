"""Simple process-level lock to prevent concurrent runs of ptnetinspector.

This module implements a queuing system where multiple processes wait for their turn.
Instead of rejecting concurrent runs, later processes are queued and wait for the
current lock holder to finish before acquiring the lock themselves.
"""

from __future__ import annotations

import atexit
import os
import fcntl
import time
from pathlib import Path

from ptnetinspector.utils.path import get_output_dir


_LOCK_FD: int | None = None
_QUEUE_CHECK_INTERVAL: float = 0.5  # seconds between queue checks


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


def _wait_for_lock_release(lock_file: Path, verbose: bool = True) -> None:
    """Wait for the current lock holder to release the lock.

    Displays a message indicating that this process is waiting in the queue.
    Periodically checks if the lock has been released by polling the lock file.
    """
    import sys
    from ptlibs import ptprinthelper


    waiting_printed = False
    while True:
        # Print waiting message only once
        if verbose and not waiting_printed:
            ptprinthelper.ptprint(
                "Waiting for the previous ptnetinspector process to finish. Your run is queued",
                "INFO",
                condition=True
            )
            waiting_printed = True

        # Check if stale lock and clean it
        if _cleanup_stale_lock(lock_file):
            if verbose:
                ptprinthelper.ptprint(
                    "Previous process terminated. Starting your run now",
                    "INFO",
                    condition=True
                )
            break

        # Try non-blocking lock
        try:
            fd_test = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd_test, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Lock acquired, release immediately as we just needed to test
                fcntl.flock(fd_test, fcntl.LOCK_UN)
                os.close(fd_test)
                if verbose:
                    ptprinthelper.ptprint(
                        "Previous process finished. Starting your run now.",
                        "INFO",
                        condition=True
                    )
                break
            except OSError:
                os.close(fd_test)
        except OSError:
            pass

        time.sleep(_QUEUE_CHECK_INTERVAL)


def acquire_global_lock(lock_path: Path | None = None, verbose: bool = True) -> None:
    """Acquire a lock, waiting for existing lock holders to finish.

    If another process holds the lock, this function will wait and display
    a message about queuing. Once the previous process releases the lock,
    this process acquires it and proceeds.

    Args:
        lock_path: Custom lock file path (defaults to output directory).
        verbose: If True, print messages about waiting (default True).
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

    # Try to acquire lock without blocking first
    try:
        fd = _attempt_lock()
    except OSError as exc:
        # If stale lock exists, clean it and retry once
        if _cleanup_stale_lock(lock_file):
            try:
                fd = _attempt_lock()
            except OSError:
                # Still can't get lock after cleanup, must wait for active process
                _wait_for_lock_release(lock_file, verbose)
                fd = _attempt_lock()
        else:
            # Lock is held by active process, wait for release
            _wait_for_lock_release(lock_file, verbose)
            fd = _attempt_lock()

    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    _LOCK_FD = fd
    atexit.register(_release_lock)
