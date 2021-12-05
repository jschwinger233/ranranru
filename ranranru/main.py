import sys
import click

from . import bcc
from . import dwarf
from . import program


def handle_program_text(ctx, param, value) -> str:
    if value.startswith("@"):
        with open(value[1:]) as f:
            value = f.read()
    return value


def handle_extra_vars(ctx, param, value) -> dict:
    res = {}
    if not value:
        return res
    for val in value.split(","):
        k, v = val.split("=", 1)
        res[k] = v
    return res


@click.group(
    context_settings=dict(help_option_names=["-h", "--help"]),
    invoke_without_command=True,
)
@click.pass_context
@click.option(
    "-t",
    "--target",
    help="golang binary to trace",
)
@click.option(
    "-e",
    "--extra-vars",
    callback=handle_extra_vars,
    help="extra variables to render bcc script, e.g. -e sym_pid=233,real_target=/path/to/bin",  # noqa
)
@click.option("-o", "--output", help="output filename", default="trace.bcc.py")
@click.option(
    "-p",
    "--program-text",
    nargs=1,
    default="",
    callback=handle_program_text,
)
def main(
    ctx,
    target: str,
    program_text: str,
    extra_vars: dict[str, str],
    output: str,
):
    if ctx.invoked_subcommand is not None:
        return

    extra_vars.setdefault("real_target", target)
    trace_uprobes = program.parse(program_text)
    dwarf_interpreter = dwarf.Interpreter(target)
    print(
        bcc.render(trace_uprobes, dwarf_interpreter, extra_vars),
        file=open(output, "w"),
    )
    print(f"generated {output}")


@main.group()
def pipe():
    pass


@pipe.command(help="objdump -Wi _ | rrr pipe location_address -f _ -v _")
@click.option("-f", "--function-name", required=True)
@click.option("-v", "--varname", required=True)
def location_address(function_name: str, varname: str):
    on = onon = False
    for line in sys.stdin:
        if "DW_AT_name" in line and function_name in line:
            on = True
            continue

        if on and "DW_AT_name" in line and varname in line:
            onon = True
            continue

        if onon and "DW_AT_location" in line:
            print(line.split()[-3])
            return


@pipe.command(help="objdump -Wo _ | rrr pipe location_express -l _ -a _")
@click.option(
    "-l",
    "--location-address",
    required=True,
    callback=lambda ctx, param, value: value.removeprefix("0x"),
)
@click.option(
    "-a",
    "--uprobe-address",
    required=True,
    callback=lambda ctx, param, value: int(value, 16),
)
def location_express(location_address: str, uprobe_address: int):
    on = False
    for line in sys.stdin:
        if location_address in line:
            on = True
            continue

        if on:
            _, start, end, expr = line.split(maxsplit=3)
            if int(start, 16) <= uprobe_address < int(end, 16):
                print(expr)
                return

        if on and "base address" in line:
            click.Abort("location express not found")


@pipe.command(help="objdump -Wi _ | rrr pipe function -a _")
@click.option(
    "-a",
    "--address",
    required=True,
    callback=lambda ctx, param, value: int(value, 16),
)
def function(address: int):
    on = False
    for line in sys.stdin:
        if "DW_TAG_subprogram" in line:
            on = True
            continue

        if on and "DW_AT_name" in line:
            function_name = line.split()[-1]
            continue

        if on and "DW_AT_low_pc" in line:
            low_pc = int(line.split()[-1], 16)
            continue

        if on and "DW_AT_high_pc" in line:
            high_pc = int(line.split()[-1], 16)
            if low_pc <= address < high_pc:
                print(function_name, '{:x}'.format(low_pc), sep="\n")
                return
            on = False


@pipe.command(help="objdump -WF _ | awk -v RS= '/_/' | rrr pipe cfa -a _")
@click.option(
    "-a",
    "--address",
    required=True,
    callback=lambda _, __, value: int(value, 16),
)
def cfa(address: int):
    start = False
    last_loc = last_cfa = None
    for line in sys.stdin:
        if "LOC" in line:
            start = True
            continue

        if start:
            loc, cfa, *_ = line.split()
            loc = int(loc, 16)
            if last_loc is not None and last_loc <= address < loc:
                print(last_cfa)
                return

            else:
                last_loc, last_cfa = loc, cfa
                continue


if __name__ == "__main__":
    main()
