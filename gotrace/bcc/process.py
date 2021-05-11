import os
import typing

from gotrace.utils import process as procutils


class Process(procutils.Process):
    @classmethod
    def from_bcc_program(cls, python: str, bcc_program: str):
        return cls(python, bcc_program)

    def __init__(self, python: str, bcc_program: str):
        self.bcc_program = bcc_program
        super().__init__(python, '-', BCC_SYMFS='/tmp')

        self._r: typing.Optional[int] = None
        self._w: typing.Optional[int] = None

    def prefork(self):
        self._r, self._w = os.pipe()

    def preexec(self):
        os.dup2(self._r, 0, inheritable=True)

    def postfork(self):
        os.write(self._w, self.bcc_program.encode())
        os.close(self._w)
