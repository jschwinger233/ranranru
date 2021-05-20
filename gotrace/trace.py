from . import bcc
from .utils import signal as sigutils


class Trace:
    def __init__(
        self,
        *,
        python: str,
        program: str,
        sym_pathname: str,
        verbose: bool,
    ):
        self.program = program
        self.verbose = verbose
        self.python = python

        self._bcc_renderer = bcc.Renderer(program, sym_pathname)

    def run(self):
        with sigutils.block_signals():
            with self._bcc_renderer.render() as bcc_program:
                if self.verbose:
                    print(bcc_program)

                bcc_process = bcc.Process.from_bcc_program(
                    bcc_program,
                    python=self.python)

                try:
                    bcc_process.spawn()

                finally:
                    bcc_process.wait()
