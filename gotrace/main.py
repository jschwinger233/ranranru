import sys
import click

from .trace import Trace


@click.command(
    context_settings=dict(help_option_names=['-h', '--help']), )
@click.option('-s',
              '--sym-pathname',
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
    default='',
    help='one line of program',
)
def main(
    sym_pathname: str,
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

    trace = Trace(
        python=python,
        program=program,
        sym_pathname=sym_pathname,
        verbose=verbose,
    )
    trace.run()


if __name__ == '__main__':
    main()
