from .utils import yield_elf_lines


def findall_filenames(dwarf_filename, suffix: str) -> {str}:
    suffix = f"{suffix}:".encode()
    filenames = []
    for line in yield_elf_lines(dwarf_filename, "WL"):
        if line.endswith(suffix):
            filenames.append(line.decode().rstrip(":"))
    return set(filenames)


def findall_stmt_address(dwarf_filename, suffix: str, lineno: str) -> str:
    suffix = f"{suffix}:".encode()
    on = False
    for line in yield_elf_lines(dwarf_filename, "WL"):
        if line.endswith(suffix):
            on = True
            continue
        elif not line:
            on = False
            continue
        elif on:
            line = line.decode()
            if " x" not in line:
                continue
            _, no, addr, *_ = line.split()
            if no == lineno:
                return str(addr)
