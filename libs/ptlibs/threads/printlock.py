import threading

from ptlibs import ptmisclib


class PrintLock:
    """Printlock is an object that holds an output string for a thread that instantiates this object"""
    def __init__(self) -> None:
        self.output_string = ""
        self.lock = threading.Lock()

    def add_string_to_output(self, string="", condition=True, end="\n", silent=False, trim=False) -> None:
        if condition and not silent:
            if trim:
                string = string.strip()
            if string:
                self.output_string +=  string + end

    def get_output_string(self) -> str:
        """Returns final output string"""
        return self.output_string

    def print_output(self, condition=True, end="\n", flush=True, silent=False) -> None:
        """Prints output if condition"""
        if condition and not silent:
            ptmisclib.ptprint(self.output_string, end=end, flush=flush)

    def lock_print_output(self, condition=True, end="\n", flush=True) -> None:
        if condition:
            self.lock.acquire()
            ptmisclib.ptprint(self.output_string, end=end, flush=flush)
            self.lock.release()

    def lock_print(self, string, condition=True, end="\n", flush=True, clear_to_eol=False) -> None:
        if condition:
            self.lock.acquire()
            ptmisclib.ptprint(string, end=end, flush=flush, clear_to_eol=clear_to_eol)
            self.lock.release()
