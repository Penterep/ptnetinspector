"""Reusable burst-control helpers for packet sending.

Provides dynamic burst sizing based on host/interface capacity and adaptive
sendp behavior that reacts to ENOBUFS by reducing burst size and retrying.
"""

from __future__ import annotations

import errno
import logging
import time
from pathlib import Path

from scapy.all import sendp, srp


def _read_sysctl_int(name: str, default: int) -> int:
    path = Path("/proc/sys") / name.replace(".", "/")
    try:
        value = int(path.read_text(encoding="utf-8").strip())
        return value
    except Exception:
        return default


def _read_txqlen(interface: str, default: int = 1000) -> int:
    path = Path("/sys/class/net") / interface / "tx_queue_len"
    try:
        value = int(path.read_text(encoding="utf-8").strip())
        return value if value > 0 else default
    except Exception:
        return default


def estimate_dynamic_burst_limit(
    interface: str,
    packet_size_estimate: int = 192,
    min_burst: int = 16,
    max_burst: int = 128,
    qlen_divisor: int = 8,
) -> int:
    """Estimate initial burst limit from queue depth and socket write buffer."""
    wmem_default = _read_sysctl_int("net.core.wmem_default", 212_992)
    txqlen = _read_txqlen(interface, 1000)

    by_wmem = max(1, wmem_default // max(64, int(packet_size_estimate)))
    by_qlen = max(1, txqlen // max(1, int(qlen_divisor)))

    burst = min(by_wmem, by_qlen)
    burst = max(int(min_burst), min(int(max_burst), int(burst)))
    return burst


def resolve_burst_limit(
    requested_limit: int | None,
    configured_limit: int,
    interface: str,
    logger: logging.Logger,
    context: str,
) -> int:
    """Resolve burst limit with dynamic fallback and debug diagnostics."""
    candidate = configured_limit if requested_limit is None else requested_limit
    try:
        candidate_int = int(candidate)
    except (TypeError, ValueError):
        candidate_int = 0

    if candidate_int > 0:
        return candidate_int

    dynamic = estimate_dynamic_burst_limit(interface)
    logger.debug(
        "Dynamic burst selected for %s: %s (requested=%s, configured=%s)",
        context,
        dynamic,
        requested_limit,
        configured_limit,
    )
    return dynamic


def chunked(items: list, burst_limit: int):
    """Yield chunks according to configured burst limit."""
    if burst_limit <= 0:
        if items:
            yield items
        return
    for idx in range(0, len(items), burst_limit):
        yield items[idx:idx + burst_limit]


def sendp_adaptive(
    packets: list,
    interface: str,
    logger: logging.Logger,
    context: str,
    initial_burst: int,
    min_burst: int = 16,
    max_burst: int = 256,
    max_retries_at_min: int = 2,
    exception_retries: int = 3,
    retry_delay: float = 0.05,
) -> None:
    """Send packets with adaptive burst reduction on ENOBUFS.

    Logs reductions and retries via debug logger.
    """
    if not packets:
        return

    burst = max(min_burst, min(max_burst, int(initial_burst)))
    idx = 0
    success_rounds = 0

    while idx < len(packets):
        current = packets[idx:idx + burst]
        retries_at_min = 0
        general_exception_retries = 0

        while True:
            try:
                sendp(current, iface=interface, verbose=False)
                idx += len(current)
                success_rounds += 1

                if success_rounds >= 3 and burst < max_burst:
                    new_burst = min(max_burst, burst + max(1, burst // 10))
                    if new_burst != burst:
                        logger.debug(
                            "Increasing burst for %s on %s: %d -> %d",
                            context,
                            interface,
                            burst,
                            new_burst,
                        )
                        burst = new_burst
                    success_rounds = 0
                break
            except OSError as ex:
                if ex.errno != errno.ENOBUFS:
                    raise

                success_rounds = 0
                if burst > min_burst:
                    new_burst = max(min_burst, burst // 2)
                    logger.debug(
                        "ENOBUFS in %s on %s, reducing burst: %d -> %d",
                        context,
                        interface,
                        burst,
                        new_burst,
                    )
                    burst = new_burst
                    current = packets[idx:idx + burst]
                    time.sleep(retry_delay)
                    continue

                retries_at_min += 1
                logger.debug(
                    "ENOBUFS in %s on %s at min burst=%d (retry %d/%d)",
                    context,
                    interface,
                    burst,
                    retries_at_min,
                    max_retries_at_min,
                )
                if retries_at_min > max_retries_at_min:
                    raise
                time.sleep(retry_delay * retries_at_min)
            except Exception as ex:
                general_exception_retries += 1
                logger.debug(
                    "sendp exception in %s on %s (retry %d/%d): %s",
                    context,
                    interface,
                    general_exception_retries,
                    exception_retries,
                    ex,
                )
                if general_exception_retries >= max(1, int(exception_retries)):
                    raise
                time.sleep(retry_delay * general_exception_retries)


def sendp_with_retries(
    packets,
    interface: str,
    logger: logging.Logger,
    context: str,
    retries: int = 3,
    retry_delay: float = 0.05,
    verbose: bool = False,
):
    """Send packets with bounded retries on exception."""
    attempts = max(1, int(retries))
    for attempt in range(1, attempts + 1):
        try:
            return sendp(packets, iface=interface, verbose=verbose)
        except Exception as ex:
            if attempt >= attempts:
                raise
            logger.debug(
                "sendp retry for %s on %s after exception (attempt %d/%d): %s",
                context,
                interface,
                attempt,
                attempts,
                ex,
            )
            time.sleep(retry_delay * attempt)


def srp_with_retries(
    packets,
    interface: str,
    logger: logging.Logger,
    context: str,
    retries: int = 3,
    retry_delay: float = 0.05,
    timeout: float | None = None,
    verbose: bool = False,
    threaded: bool = False,
    multi: bool = False,
):
    """Send/receive packets with bounded retries on exception."""
    attempts = max(1, int(retries))
    for attempt in range(1, attempts + 1):
        try:
            kwargs = {
                "iface": interface,
                "verbose": verbose,
                "threaded": threaded,
                "multi": multi,
            }
            if timeout is not None:
                kwargs["timeout"] = timeout
            return srp(packets, **kwargs)
        except Exception as ex:
            if attempt >= attempts:
                raise
            logger.debug(
                "srp retry for %s on %s after exception (attempt %d/%d): %s",
                context,
                interface,
                attempt,
                attempts,
                ex,
            )
            time.sleep(retry_delay * attempt)
