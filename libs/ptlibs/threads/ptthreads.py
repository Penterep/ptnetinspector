import threading
import time
from typing import Union, Callable

from ptlibs.threads import arraylock


class PtThreads:
    def __init__(self):
        self.threads_list = []
        self.free_threads = []
        self.returns      = []
        self.lock         = threading.Lock()
        self.arraylock    = arraylock.ArrayLock()

    def threads(self, items: Union[list,any], function: Callable[[any], any], threads: int):
        self.free_threads.clear()
        self.threads_list.clear()
        self.returns.clear()
        for i in range(threads):
            self.free_threads.append(i)
            self.threads_list.append("")
        while items:
            if not type(items) == list:
                try:
                    item = next(items).strip()
                except:
                    break
            else:
                item = items[0]
                items.remove(item)
            thread_no = self.free_threads.pop()
            self.threads_list[thread_no] = threading.Thread(target = self.wrapper_worker, args = (item, function, thread_no), daemon=False)
            result = self.threads_list[thread_no].start()
            while not self.free_threads:
                time.sleep(0.01)
            while not items:
                time.sleep(0.01)
                if len(self.free_threads) == threads and not items:
                    return self.returns
        for thread in self.threads_list:
            if thread:
                thread.join()

    def wrapper_worker(self, item: any, function: Callable[[any], any], thread_no: int):
        try:
            self.arraylock.lock_array_append(self.returns, function(item))
        except:
            pass
        self.arraylock.lock_array_append(self.free_threads, thread_no)
