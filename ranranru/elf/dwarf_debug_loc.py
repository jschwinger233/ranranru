from .utils import yield_elf_lines


def find_location_desc(
    dwarf_filename: str, location_addr: str, uprobe_addr: str
) -> str:
    location_addr = location_addr.removeprefix('0x').encode()
    uprobe_addr = int(uprobe_addr, 16)
    on = False
    for line in yield_elf_lines(dwarf_filename, "Wo"):
        if location_addr in line:
            on = True
            continue

        if on:
            _, start, end, expr = line.decode().split(maxsplit=3)
            if int(start, 16) <= uprobe_addr < int(end, 16):
                return expr[1:-1]
