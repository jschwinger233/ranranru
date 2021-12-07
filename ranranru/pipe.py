import sys
import click


class ClickGroupProxy:
    def __init__(self):
        self.group = None
        self.funcs = []
        self.command_args = []

    def __call__(self, func):
        self.funcs.append(func)

    def command(self, *args, **kws):
        self.command_args.append((args, kws))
        return self

    def set(self, group):
        for func, (args, kws) in zip(self.funcs, self.command_args):
            group.command(*args, **kws)(func)


group_proxy = ClickGroupProxy()


def register(group):
    group_proxy.set(group)


@group_proxy.command(
    help="objdump -Wi _ | rrr pipe location-address -f _ -v _"
)
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


@group_proxy.command(
    help="objdump -Wo _ | rrr pipe location-express -l _ -a _"
)
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


@group_proxy.command(help="objdump -Wi _ | rrr pipe function-name -a _")
@click.option(
    "-a",
    "--address",
    required=True,
    callback=lambda ctx, param, value: int(value, 16),
)
def function_name(address: int):
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
                print(function_name, "{:x}".format(low_pc), sep="\n")
                return
            on = False


@group_proxy.command(
    help="objdump -WF _ | awk -v RS= '/_/' | rrr pipe cfa -a _"
)
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
