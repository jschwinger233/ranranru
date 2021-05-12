from . import bcc
from . import debug
from .utils import signal as sigutils


class Trace:
    def __init__(
        self,
        *,
        python: str,
        program: str,
        debug_pathname: str,
        verbose: bool,
    ):
        self.program = program
        self.verbose = verbose
        self.python = python

        self._debug_process: debug.Process = None
        if debug_pathname:
            self._debug_process = debug.Process.from_pathname(debug_pathname)

        self._bcc_builder = bcc.Builder(program)
        self._bcc_process: bcc.Process = None

    def parse(self):
        self._bcc_builder.parse()

    def start(self):
        sigutils.block_all()

        if self._debug_process:
            self._debug_process.start()

        if self.verbose:
            print(self._bcc_builder.dumps())

        self._bcc_process = bcc.Process.from_bcc_program(
            self._bcc_builder.dumps(),
            python=self.python,
            debug_pid=self._debug_process.pid)

        if self._debug_process:
            self._debug_process.setup_bcc_symfs(
                self._bcc_builder.tracee_pathname())
        self._bcc_process.start()

    def wait(self):
        if self._bcc_process:
            self._bcc_process.wait()

        if self._debug_process:
            self._debug_process.kill(9)
            self._debug_process.wait()
