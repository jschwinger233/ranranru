from .utils import yield_elf_lines


def findall_addresses(dwarf_filename: str, function_name: str) -> [(str, str)]:
    addresses = []
    function_name = function_name.encode()
    for line in yield_elf_lines(dwarf_filename, "t"):
        if line.endswith(function_name):
            addr, *_, name = line.split()
            addresses.append((addr.decode(), name.decode()))
    return addresses
