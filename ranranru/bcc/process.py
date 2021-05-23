import os

from ..utils import process as procutils


class Process(procutils.Process):
    @classmethod
    def from_bcc_program(cls, bcc_program: str, *, python: str):
        self = cls(python, '-', BCC_SYMFS='/tmp')
        self.bcc_program = bcc_program
        self._r: int = None
        self._w: int = None
        return self

    def prefork(self):
        self._r, self._w = os.pipe()

    def preexec(self):
        os.dup2(self._r, 0, inheritable=True)

    def postfork(self):
        os.write(self._w, self.bcc_program.encode())
        os.close(self._w)
