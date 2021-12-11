import re
from . import symbol_table
from . import dwarf_debug_loc
from . import dwarf_debug_line
from . import dwarf_debug_info
from . import dwarf_debug_frame


class Interpreter:
    def __init__(self, dwarf_filename: str):
        self.dwarf_filename = dwarf_filename

    def find_address_by_filename_lineno(
        self, filename_suffix: str, lineno: str
    ) -> str:
        candidates = dwarf_debug_line.findall_filenames(
            self.dwarf_filename, filename_suffix
        )
        if len(candidates) > 1:
            raise ValueError(
                "ambiguous filename: {}".format(", ".join(candidates))
            )
        if not candidates:
            raise ValueError(f"file not found: {filename_suffix}")

        return dwarf_debug_line.findall_stmt_address(
            self.dwarf_filename, filename_suffix, lineno
        )

    def find_address_by_function_name(self, function_name: str) -> str:
        addresses = symbol_table.findall_addresses(
            self.dwarf_filename, function_name
        )
        if not addresses:
            raise ValueError(f"function not found: {function_name}")
        if len(addresses) > 1:
            raise ValueError(
                "ambiguous function name: {}".format(
                    ", ".join(n for _, n in addresses)
                )
            )

        return "0x" + addresses[0][0]

    pat_OP_reg = re.compile(r"DW_OP_reg.*?\((.*?)\)")
    pat_OP_fbreg = re.compile(r"DW_OP_fbreg:\s*(\w+)")

    def find_var_location(self, uprobe_addr: str, varname: str) -> str:
        subprogram = dwarf_debug_info.find_subprogram(
            self.dwarf_filename, uprobe_addr
        )
        location_expr = dwarf_debug_loc.find_location_expr(
            self.dwarf_filename,
            subprogram.get_param(varname).location_addr,
            uprobe_addr,
        )

        s = self.pat_OP_reg.search(location_expr)
        if s:
            reg = s.group(1)
            return "$" + {
                "rax": "ax",
                "rbx": "bx",
                "rcx": "cx",
                "rdx": "dx",
                "rsi": "si",
                "rdi": "di",
                "rbp": "bp",
                "rsp": "sp",
                "r8": "r8",
                "r9": "r9",
                "r10": "r10",
                "r11": "r11",
                "r12": "r12",
                "r13": "r13",
                "r14": "r14",
                "r15": "r15",
                "rip": "rip",
            }[reg]

        s = self.pat_OP_fbreg.search(location_expr)
        if s:
            offset = s.group(1)
            if offset.isdigit():
                offset = f"+{offset}"
            cfa = dwarf_debug_frame.find_cfa_expr(
                self.dwarf_filename, subprogram.low_pc, uprobe_addr
            ).replace("rsp", "$sp")
            return f"{cfa}{offset}*"

        raise ValueError(f"unknown dwarf op: {location_expr}")
