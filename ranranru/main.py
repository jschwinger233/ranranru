import click

from . import bcc
from . import dwarf
from . import program


def handle_extra_vars(ctx, param, value) -> dict:
    res = {"tracee_binary": ctx.params["tracee_binary"]}
    if not value:
        return res

    for kv in value.split(","):
        k, v = kv.split("=")
        res[k] = v
    return res


def handle_tracee_debug_binary(ctx, param, value) -> str:
    if value:
        return value

    return ctx.params["tracee_binary"]


def handle_program_text(ctx, param, value) -> str:
    if "program_filename" not in ctx.params and not value:
        raise click.BadParameter("either trace code or file is required")

    if "program_filename" in ctx.params:
        with open(ctx.params["program_filename"]) as f:
            value += f.read().strip()
    return value


@click.command(
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.option(
    "-t",
    "--tracee-binary",
    required=True,
    help="golang binary to trace",
)
@click.option(
    "-d",
    "--tracee-debug-binary",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="golang binary with debug info",
    callback=handle_tracee_debug_binary,
)
@click.option(
    "-f",
    "--program-filename",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=False,
    help="filename of program",
)
@click.option(
    "-e",
    "--extra-vars",
    help="extra variables to render bcc script, usage: -e k1=v1,k2=v2",
    callback=handle_extra_vars,
)
@click.option("-o", "--output", help="output filename", default="trace.bcc.py")
@click.argument(
    "program-text",
    nargs=1,
    default="",
    required=False,
    callback=handle_program_text,
)
def main(
    tracee_binary: str,  # preprocessed
    tracee_debug_binary: str,
    program_filename: str,  # preprocessed
    program_text: str,
    extra_vars: dict[str, str],
    output: str,
):

    trace_uprobes = program.parse(program_text)
    dwarf_interpreter = dwarf.Interpreter(
        tracee_debug_binary, extra_vars.pop("dwarf_path_prefix", "")
    )
    print(
        bcc.render(trace_uprobes, dwarf_interpreter, extra_vars),
        file=open(output, "w"),
    )
    print(f'generated {output}')


if __name__ == "__main__":
    main()
