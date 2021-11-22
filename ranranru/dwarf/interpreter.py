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

    def find_address_by_filename_lineno(
        self, filename: str, lineno: int
    ) -> str:
        dirname, basename = (
            os.path.dirname(filename).encode(),
            os.path.basename(filename).encode(),
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
                    == basename
                )
                cur_dirname = lineprog.header["include_directory"][
                    lineprog["file_entry"][entry.state.file - 1].dir_index - 1
                ]
                same_dir = cur_dirname.endswith(dirname)
                if same_line and same_file and same_dir:
                    print(
                        f"[dwarf] uprobe {filename}:{lineno} matches {cur_dirname.decode()}/{basename.decode()}"  # noqa
                    )
                    return "0x{:x}".format(entry.state.address)

        raise ValueError(
            f"address not found by lineno: {self.dwarf_path_prefix}{breakpoint} in {self.dwarf_filename}"  # noqa
        )

    def find_address_by_function(self, function_name: str) -> str:
        function_name = function_name.encode()
        for CU in self.dwarf_info.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag != "DW_TAG_subprogram":
                    continue
                try:
                    cur_function_name = DIE.attributes["DW_AT_name"].value
                except KeyError:
                    continue
                if cur_function_name.endswith(function_name):
                    print(
                        f"[dwarf] uprobe {function_name.decode()} matches {cur_function_name.decode()}"  # noqa
                    )
                    return "0x{:x}".format(
                        DIE.attributes["DW_AT_low_pc"].value
                    )
        raise ValueError(
            f"address not found by function: {function_name} in {self.dwarf_filename}"  # noqa
        )
