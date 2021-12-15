import re
import dataclasses
from .utils import yield_elf_lines

PAT_DW_AT_location = re.compile(r"DW_AT_location\s*:\s*(.*)")
PAT_DW_OP = re.compile(r"\((.*)\)")


@dataclasses.dataclass
class Parameter:
    name: str = ""
    type_addr: str = ""
    dw_at_location: str = ""

    @property
    def location_type(self) -> str:
        if "location list" in self.dw_at_location:
            return "location_list"
        else:
            return "dw_op"

    @property
    def location(self) -> str:
        if self.location_type == "location_list":
            return self.dw_at_location.split()[0]
        else:
            return PAT_DW_OP.search(self.dw_at_location).group(1)


@dataclasses.dataclass
class Subprogram:
    name: str = ""
    low_pc: str = ""
    high_pc: str = ""
    params: [Parameter] = dataclasses.field(default_factory=list)

    def get_param(self, varname: str) -> Parameter:
        for param in self.params:
            if param.name == varname:
                return param


@dataclasses.dataclass
class Member:
    name: str = ""
    offset: int = ""
    type_addr: str = ""


@dataclasses.dataclass
class Type:
    tag: str
    name: str = ""
    type_addr: str = ""
    members: [Member] = dataclasses.field(default_factory=list)

    def is_structure(self) -> bool:
        return self.tag == "DW_TAG_structure_type"

    def is_pointer(self) -> bool:
        return self.tag == "DW_TAG_pointer_type"


def find_subprogram(  # noqa
    dwarf_filename: str, uprobe_addr: str
) -> Subprogram:
    uprobe_addr = int(uprobe_addr, 16)
    on_sub = False
    subprogram = param = None
    for line in yield_elf_lines(dwarf_filename, "Wi"):
        if b"DW_TAG_subprogram" in line:
            on_sub = True
            continue

        if not on_sub:
            continue

        # all below are within a DW_TAG_subprogram
        line = line.decode()

        if "DW_TAG_" in line and not line.startswith("<2>") and subprogram:
            return subprogram

        if "DW_AT_name" in line and not param:
            name = line.split()[-1]
            continue

        if "DW_AT_low_pc" in line:
            low_pc = int(line.split()[-1], 16)
            continue

        if "DW_AT_high_pc" in line:
            high_pc = int(line.split()[-1], 16)
            if low_pc <= uprobe_addr < high_pc:
                subprogram = Subprogram(name, f"{low_pc:x}", f"{high_pc:x}")
            else:
                on_sub = False
            continue

        if not subprogram:
            continue

        if param and line.startswith(("<1>", "<2>", "<3>")):
            subprogram.params.append(param)
            param = None

        if "DW_TAG_formal_parameter" in line:
            param = Parameter()
            continue

        if not param:
            continue

        # all below are within a DW_TAG_formal_parameter

        if "DW_AT_name" in line:
            param.name = line.split()[-1]
            continue

        if "DW_AT_type" in line:
            param.type_addr = line.split()[-1].strip("<>")
            continue

        if "DW_AT_location" in line:
            param.dw_at_location = PAT_DW_AT_location.search(line).group(1)
            continue


def find_type(dwarf_filename: str, type_addr: str) -> Type:  # noqa
    type_addr = type_addr.removeprefix("0x").encode()
    t = member = None
    for line in yield_elf_lines(dwarf_filename, "Wi"):
        if type_addr in line and b"type" in line and b"DW_TAG" in line:
            tag = line.decode().split()[-1].strip("()")
            t = Type(tag)
            continue

        if not t:
            continue

        # all below are within the type
        line = line.decode()

        if "DW_TAG_" in line and not line.startswith("<2>"):
            return t

        if "DW_AT_name" in line and not member:
            t.name = line.split()[-1]
            continue

        if "DW_AT_type" in line and not member:
            t.type_addr = line.split()[-1].strip("<>")
            continue

        if member and line.startswith(("<1>", "<2>", "<3>")):
            t.members.append(member)
            member = None

        if "DW_TAG_member" in line:
            member = Member()
            continue

        if not member:
            continue

        # all below are within a member

        if "DW_AT_name" in line:
            member.name = line.split()[-1]
            continue

        if "DW_AT_data_member_location" in line:
            member.offset = int(line.split()[-1])
            continue

        if "DW_AT_type" in line:
            member.type_addr = line.split()[-1].strip("<>")
            continue
