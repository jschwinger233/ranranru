import re
import os
import typing

from .utils import process as procutils


class Builder:
    pat = re.compile(
        r'(?P<pathname>[^:]+):(?P<uprobe>\S+)\s+\{(?P<script>.*)\}', re.S)

    tmpl = open(os.path.join(os.path.dirname(__file__),
                             'bcc_program.py.tmpl')).read()

    def __init__(self, program: str):
        self.program = program
        self.debug_pid: typing.Optional[int] = None

        self._pathname: typing.Optional[str] = None
        self._uprobe: typing.Optional[str] = None
        self._script: typing.Optional[str] = None

    def parse(self):
        m = self.pat.match(self.program)
        if not m:
            raise ValueError("wrong trace program, pattern doesn't match")

        self._pathname, self._uprobe, self._script = m.group(
            'pathname'), m.group('uprobe'), m.group('script')

    def dumps(self) -> str:
        if not self._uprobe:
            raise RuntimeError('"dumps" must be called after "parse"')

        return self.tmpl.format(
            pathname=self._pathname,
            uprobe=self._uprobe,
            script=self._script,
        )

    def tracee_pathname(self) -> str:
        return self._pathname


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
