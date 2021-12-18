from . import symbol_table
from . import dwarf_debug_loc
from . import dwarf_debug_line
from . import dwarf_debug_info
from . import dwarf_debug_frame
from . import dwarf_location_desc


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

    def parse_var(self, uprobe_addr: str, varname: str) -> (str, str):
        subprogram = dwarf_debug_info.find_subprogram(
            self.dwarf_filename, uprobe_addr
        )
        param = subprogram.get_param(varname)
        if param.location_type == "location_list":
            desc = dwarf_debug_loc.find_location_desc(
                self.dwarf_filename,
                param.location,
                uprobe_addr,
            )
        else:
            desc = param.location

        cfa = dwarf_debug_frame.find_cfa_expr(
            self.dwarf_filename, subprogram.low_pc, uprobe_addr
        ).replace("rsp", "$sp")
        return dwarf_location_desc.parse(desc, cfa), param.type_addr

    def find_expr_location(
        self, uprobe_addr: str, varname: str, members: [str]
    ) -> str:
        loc_expr, type_addr = self.parse_var(uprobe_addr, varname)
        for member_name in members:
            t = dwarf_debug_info.find_type(self.dwarf_filename, type_addr)
            while not t.is_structure():
                if t.is_pointer():
                    loc_expr += "*"
                t = dwarf_debug_info.find_type(
                    self.dwarf_filename, t.type_addr
                )
            for i, m in enumerate(t.members):
                if m.name == member_name:
                    if ';' in loc_expr:
                        loc_expr = loc_expr.split(';')[i]
                    else:
                        loc_expr = loc_expr[:-1] + f"+{m.offset}*"
                    type_addr = m.type_addr
                    break
            else:
                raise ValueError(f"member not found: {member_name}")
        return loc_expr
