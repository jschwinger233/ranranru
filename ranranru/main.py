import sys
import click

from .trace import Trace


@click.command(
    context_settings=dict(help_option_names=['-h', '--help']), )
@click.option('-v',
              '--verbose',
              is_flag=True,
              default=False,
              show_default=True,
              help='print BCC program before executing')
@click.option('-vv',
              '--very-verbose',
              is_flag=True,
              default=False,
              show_default=True,
              help='print BCC program with line numbers before executing')
@click.option(
    '-p',
    '--python',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=False,
    default=sys.executable,
    help='python interpreter to execute bcc program',
)
@click.option('-f',
              '--program-filename',
              type=click.Path(exists=True, file_okay=True, dir_okay=False),
              required=False,
              help='filename of program')
@click.option(
    '-t',
    '--tracee-binary',
    required=True,
    help= 'golang binary to trace, can specify non-stripped binary by format [bin]:[sym-bin]'  # noqa
)
@click.option(
    '--dry-run',
    is_flag=True,
    default=False,
    help='don\'t execute bcc script, useful with -v',
)
@click.argument(
    'program',
    nargs=1,
    default='',
    required=False,
)
def main(
    verbose: bool,
    very_verbose: bool,
    python: str,
    tracee_binary: str,
    program_filename: str,
    dry_run: bool,
    program: str,
):

    if not program_filename and not program:
        raise click.BadParameter('either trace code or file is required')

    if program_filename:
        with open(program_filename) as f:
            program += f.read().strip()

    verbose_level = 1 if verbose else 0
    verbose_level = 2 if very_verbose else verbose_level

    tracee, tracee_sym, *_ = f'{tracee_binary}:'.split(':')

    trace = Trace(
        python=python,
        program=program,
        tracee=tracee,
        tracee_sym=tracee_sym,
        verbose_level=verbose_level,
    )
    trace.run(dry_run)


if __name__ == '__main__':
    main()
