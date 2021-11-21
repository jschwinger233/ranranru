import os
from elftools.elf.elffile import ELFFile


class Interpreter:
    def __init__(self, dwarf_filename: str, dwarf_path_prefix: str):
        self.dwarf_filename = dwarf_filename
        self.dwarf_path_prefix = dwarf_path_prefix

        with open(dwarf_filename, "rb") as f:
            elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                raise ValueError(
                    f"debug file doesn't have dwarf: {dwarf_filename}"
                )

            self.dwarf_info = elffile.get_dwarf_info()

    def find_address(self, breakpoint: str) -> str:
        fname, lineno = breakpoint.split(":")
        modname, basename = os.path.dirname(fname), os.path.basename(fname)
        dirname, basename, lineno = (
            f"{self.dwarf_path_prefix}{modname}".encode(),
            basename.encode(),
            int(lineno),
        )

        for CU in self.dwarf_info.iter_CUs():
            lineprog = self.dwarf_info.line_program_for_CU(CU)
            if not lineprog:
                continue
            for entry in lineprog.get_entries():
                if not entry.state:
                    continue

                same_line = entry.state.line == lineno
                same_file = (
                    lineprog["file_entry"][entry.state.file - 1].name
                    == basename  # noqa
                )
                same_dir = (
                    lineprog.header["include_directory"][
                        lineprog["file_entry"][entry.state.file - 1].dir_index
                        - 1  # noqa
                    ]
                    == dirname  # noqa
                )
                if same_line and same_file and same_dir:
                    return "0x{:x}".format(entry.state.address)

        raise ValueError(
            f"address not found: {self.dwarf_path_prefix}{breakpoint} in {self.dwarf_filename}"  # noqa
        )
