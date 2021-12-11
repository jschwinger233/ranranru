import dataclasses
from .utils import yield_elf_lines


@dataclasses.dataclass
class Parameter:
    name: str
    type_addr: str
    location_addr: str


@dataclasses.dataclass
class Subprogram:
    name: str
    low_pc: str
    high_pc: str
    parameters: [Parameter] = dataclasses.field(default_factory=list)

    def add_param(self, param: Parameter):
        self.parameters.append(param)

    def get_param(self, varname: str) -> Parameter:
        for param in self.parameters:
            if param.name == varname:
                return param


def find_subprogram(dwarf_filename: str, uprobe_addr: str) -> Subprogram: # noqa
    uprobe_addr = int(uprobe_addr, 16)
    on_sub = on_param = False
    subprogram = None
    for line in yield_elf_lines(dwarf_filename, "Wi"):
        if b"DW_TAG_subprogram" in line:
            on_sub = True
            continue

        if not on_sub:
            continue

        # all below are within a DW_TAG_subprogram
        line = line.decode()

        if "Abbrev Number: 0" in line and subprogram:
            return subprogram

        if "DW_AT_name" in line:
            name = line.split()[-1]
            continue

        if "DW_AT_low_pc" in line:
            low_pc = int(line.split()[-1], 16)
            continue

        if "DW_AT_high_pc" in line:
            high_pc = int(line.split()[-1], 16)
            if low_pc <= uprobe_addr < high_pc:
                subprogram = Subprogram(name, f'{low_pc:x}', f'{high_pc:x}')
            else:
                on_sub = False
            continue

        if "DW_TAG_formal_parameter" in line:
            on_param = True
            continue

        if not on_param:
            continue

        # all below are within a DW_TAG_formal_parameter

        if "DW_AT_type" in line:
            param_type_addr = line.split()[-1].strip("<>")
            continue

        if "DW_AT_location" in line:
            param_location_addr = line.split()[-3]
            subprogram.add_param(
                Parameter(name, param_type_addr, param_location_addr)
            )
            on_param = False
            continue
