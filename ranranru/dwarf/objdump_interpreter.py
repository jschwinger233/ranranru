import re
from ..utils import bash, escape_awk_pattern


class Interpreter:
    def __init__(self, dwarf_filename: str):
        self.dwarf_filename = dwarf_filename

    def find_address_by_filename_lineno(
        self, filename: str, lineno: int
    ) -> str:
        candidates = bash(
            "objdump -WL {} | awk '/{}/ && /:/' | sort -u",
            self.dwarf_filename,
            escape_awk_pattern(filename),
        ).splitlines()
        if len(candidates) > 1:
            raise ValueError(
                "ambiguous filename: {}".format(", ".join(candidates))
            )
        if not candidates:
            raise ValueError(f"file not found: {filename}")

        return bash(
            "objdump -WL {} | awk -v RS= '/{}/' | awk '$2 ~ /{}/ && $4 ~ /x/ {{print $3; exit}}'",  # noqa
            self.dwarf_filename,
            escape_awk_pattern(filename),
            lineno,
        )

    def find_address_by_function_name(self, function_name: str) -> str:
        candidates = bash(
            "objdump -t {} | awk '/{}/ {{print $NF}}'",
            self.dwarf_filename,
            escape_awk_pattern(function_name),
        ).splitlines()
        if not candidates:
            raise ValueError(f"function not found: {function_name}")
        if len(candidates) > 1:
            raise ValueError(
                "ambiguous function name: {}".format(", ".join(candidates))
            )

        return "0x" + bash(
            "objdump -t {} | awk '/{}/ {{print $1}}'",
            self.dwarf_filename,
            escape_awk_pattern(function_name),
        )

    pat_OP_reg = re.compile(r"DW_OP_reg.*?\((.*?)\)")
    pat_OP_fbreg = re.compile(r"DW_OP_fbreg:\s*(\w+)")

    def find_var_location(self, address: str, varname: str) -> str:
        function_name, low_pc = bash(
            "objdump -Wi {} | rrr pipe function -a {}",
            self.dwarf_filename,
            address,
        ).splitlines()
        location_address = bash(
            "objdump -Wi {} | rrr pipe location-address -f '{}' -v {}",
            self.dwarf_filename,
            function_name,
            varname,
        )
        location_express = bash(
            "objdump -Wo {} | rrr pipe location-express -l {} -a {}",
            self.dwarf_filename,
            location_address,
            address,
        )

        s = self.pat_OP_reg.search(location_express)
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

        s = self.pat_OP_fbreg.search(location_express)
        if s:
            offset = s.group(1)
            if offset.isdigit():
                offset = f"+{offset}"
            cfa = bash(
                "objdump -WF {} | awk -v RS= '/{}/' | rrr pipe cfa -a {}",
                self.dwarf_filename,
                low_pc,
                address,
            ).replace("rsp", "$sp")
            return f"{cfa}{offset}*"

        raise ValueError(f"unknown dwarf op: {location_express}")
