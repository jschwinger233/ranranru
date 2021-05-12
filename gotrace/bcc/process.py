import os
import typing

from gotrace.utils import process as procutils


class Process(procutils.Process):
    @classmethod
    def from_bcc_program(cls, bcc_program: str, *, python: str,
                         debug_pid: int):
        return cls(python, bcc_program, debug_pid)

    def __init__(self, python: str, bcc_program: str, debug_pid: int):
        self.bcc_program = bcc_program
        super().__init__(python,
                         '-',
                         BCC_SYMFS='/tmp',
                         DEBUG_PID=str(debug_pid))

        self._r: typing.Optional[int] = None
        self._w: typing.Optional[int] = None

    def prefork(self):
        self._r, self._w = os.pipe()

    def preexec(self):
        os.dup2(self._r, 0, inheritable=True)

    def postfork(self):
        os.write(self._w, self.bcc_program.encode())
        os.close(self._w)
