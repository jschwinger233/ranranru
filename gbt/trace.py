from . import bcc
from .utils import signal as sigutils


class Trace:
    def __init__(
        self,
        *,
        python: str,
        program: str,
        sym_pathname: str,
        verbose_level: int,
    ):
        self.program = program
        self.python = python
        self.verbose_level = verbose_level

        self._bcc_renderer = bcc.Renderer(program, sym_pathname)

    def run(self):
        with sigutils.block_signals():
            with self._bcc_renderer.render() as bcc_program:
                if self.verbose_level:
                    for no, l in enumerate(bcc_program.splitlines()):
                        if self.verbose_level > 1:
                            print(no, end='\t')
                        print(l)

                bcc_process = bcc.Process.from_bcc_program(bcc_program,
                                                           python=self.python)

                try:
                    bcc_process.spawn()

                finally:
                    bcc_process.proxy_signals()
