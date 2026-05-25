"""Shared synchronization primitives for Scapy I/O operations.

Scapy's sr/srp helpers may open and close raw sockets from internal worker
threads. Running multiple send/receive transactions concurrently on the same
interface can sporadically trigger EBADF on Linux.
"""

import threading


# Serialize critical sr/srp transactions across send modules.
SCAPY_IO_LOCK = threading.Lock()
