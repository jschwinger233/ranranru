import click

from . import bcc
from . import program


def handle_extra_vars(ctx, param, value) -> dict:
    if not value:
        return {}

    res = {}
    for kv in value.split(','):
        k, v = kv.split('=')
        res[k] = v
    return res


@click.command(
    context_settings=dict(help_option_names=['-h', '--help']), )
@click.option('-t',
              '--tracee-binary',
              required=True,
              help='golang binary to trace')
@click.option('-d',
              '--tracee-debug-binary',
              type=click.Path(exists=True, file_okay=True, dir_okay=False),
              required=True,
              help='golang binary with debug info')
@click.option('-f',
              '--program-filename',
              type=click.Path(exists=True, file_okay=True, dir_okay=False),
              required=False,
              help='filename of program')
@click.option(
    '-e',
    '--extra-vars',
    help='extra variables to render bcc script, usage: -e k1=v1,k2=v2',
    callback=handle_extra_vars)
@click.argument('program-text', nargs=1, default='', required=False)
def main(
    tracee_binary: str,
    tracee_debug_binary: str,
    program_filename: str,
    program_text: str,
    extra_vars: dict[str, str],
):

    if not program_filename and not program_text:
        raise click.BadParameter('either trace code or file is required')

    if program_filename:
        with open(program_filename) as f:
            program_text += f.read().strip()

    extra_vars['tracee_binary'] = tracee_binary

    trace_uprobes = program.parse(program_text)
    print(bcc.render(trace_uprobes, extra_vars))


if __name__ == '__main__':
    main()
