import sys
import click
import typing

from . import bcc
from . import debug
from .utils import signal as sigutils


@click.command(
    context_settings=dict(help_option_names=['-h', '--help']), )
@click.option('-d',
              '--debug-pathname',
              type=click.Path(exists=True, file_okay=True, dir_okay=False),
              required=False,
              help='corresponding non-stripped golang binary')
@click.option('-v',
              '--verbose',
              is_flag=True,
              default=False,
              show_default=True,
              help='print BCC program before executing')
@click.option(
    '-p',
    '--python',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=False,
    default=sys.executable,
    help='python interpreter to execute bcc program',
)
@click.option('-f',
              '--filename',
              type=click.Path(exists=True, file_okay=True, dir_okay=False),
              required=False,
              help='filename of program')
@click.option(
    '-e',
    '--program',
    required=False,
    help='one line of program',
)
def gotrace(
    debug_pathname: str,
    verbose: bool,
    python: str,
    filename: str,
    program: str,
):

    if not filename and not program:
        raise click.BadParameter('either trace code or file is required')

    if filename:
        with open(filename) as f:
            program += f.read()

    trace = Gotrace(
        python=python,
        program=program,
        debug_pathname=debug_pathname,
        verbose=verbose,
    )
    trace.parse()
    trace.start()
    trace.wait()


class Gotrace:
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

        self._debug_process: typing.Optional[debug.Process] = None
        if debug_pathname:
            self._debug_process = debug.Process.from_pathname(debug_pathname)

        self._bcc_builder = bcc.Builder(program)
        self._bcc_process: typing.Optional[bcc.Process] = None

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
        if not self._bcc_process:
            raise RuntimeError("'wait' must be called after 'start'")

        self._bcc_process.wait()

        if self._debug_process:
            self._debug_process.kill(9)
            self._debug_process.wait()


if __name__ == '__main__':
    gotrace()
