from .utils import yield_elf_lines


def find_cfa_expr(dwarf_filename: str, low_pc: str, uprobe_addr: str) -> str:
    low_pc = low_pc.removeprefix("0x").encode()
    uprobe_addr = int(uprobe_addr, 16)
    start = False
    last_loc = last_cfa = None
    for line in yield_elf_lines(dwarf_filename, "-dwarf=frames-interp"):
        if low_pc in line and b"pc" in line:
            start = True
            continue

        if not start:
            continue

        # all below are within a DIE

        if b"LOC" in line:
            continue

        if not line:
            return

        loc, cfa, *_ = line.decode().split()
        loc = int(loc, 16)
        if last_loc is not None and last_loc <= uprobe_addr < loc:
            return last_cfa

        else:
            last_loc, last_cfa = loc, cfa
            continue
