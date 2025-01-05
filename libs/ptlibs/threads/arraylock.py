import threading


class ArrayLock:
    def __init__(self) -> None:
        self.lock = threading.Lock()

    def lock_array_append(self, array, item) -> None:
        self.lock.acquire()
        array.append(item)
        self.lock.release()

    def lock_array_remove(self, array, item) -> None:
        self.lock.acquire()
        array.remove(item)
        self.lock.release()