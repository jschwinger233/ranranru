import re
import dataclasses


@dataclasses.dataclass
class Define:
    idx: int
    uprobe_idx: int
    varname: str
    express: str


@dataclasses.dataclass
class PidDefine(Define):
    pass


@dataclasses.dataclass
class TidDefine(Define):
    pass


@dataclasses.dataclass
class CommDefine(Define):
    pass


@dataclasses.dataclass
class StackDefine(Define):
    pass


@dataclasses.dataclass
class PeekDefine(Define):
    reg: str = None
    offsets: [str] = None
    cast_type: str = None

    def __post_init__(self):
        match = re.match(r"\$peek\(\(([^)]+)\)([^)]+)", self.express)
        if not match:
            raise ValueError(f"invalid peek expression: {self.express}")
        offset_exp, self.cast_type = match.group(2), match.group(1)
        self.reg, *self.offsets = re.findall(r"\w+|[-+]\d+", offset_exp)


def new_define(
    idx: int,
    uprobe_idx: int,
    var: str,
    express: str,
) -> Define:
    if express == "$pid":
        cls = PidDefine
    elif express == "$tid":
        cls = TidDefine
    elif express == "$comm":
        cls = CommDefine
    elif express == "$stack":
        cls = StackDefine
    elif express.startswith("$peek"):
        cls = PeekDefine
    else:
        raise ValueError(f"invalid define expression: {express}")
    return cls(idx, uprobe_idx, var.strip(), express.strip())


@dataclasses.dataclass
class Address:
    value: str

    def __post_init__(self):
        self.value = self.value.strip()
        if not self.type():
            raise ValueError(f"invalid uprobe address: {self.value}")

    def type(self) -> str:
        if self.value.startswith("*"):  # *0x1234
            return "address"
        elif re.match(r".+?:\d+$", self.value):  # store/etcdv3/node.go:280
            return "filename_lineno"
        elif (
            self.value
        ):  # github.com/projecteru2/core/store/etcdv3.(*Mercury).doGetNodes
            return "function"
        else:
            return ""

    def symbolize(self, dwarf_interpreter) -> str:
        if self.type() == "address":
            return self.value[1:]
        elif self.type() == "filename_lineno":
            filename, lineno = self.value.rsplit(":", 1)
            return dwarf_interpreter.find_address_by_filename_lineno(
                filename,
                int(lineno),
            )
        else:
            return dwarf_interpreter.find_address_by_function(self.value)


@dataclasses.dataclass
class Uprobe:
    idx: int
    address: Address
    defines: [Define]
    script: str


def new(idx: int, address: str, define: str, script: str) -> Uprobe:
    defines: [Define] = []
    for i, d in enumerate(define.split(",")):
        if '=' not in d:
            continue
        var, express = d.split("=", 1)
        defines.append(new_define(i, idx, var, express))
    return Uprobe(
        idx=idx,
        address=Address(address),
        defines=defines,
        script=script,
    )
