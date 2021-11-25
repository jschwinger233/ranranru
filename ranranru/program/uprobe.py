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
    operations: str = None

    # class var
    pat_expression = re.compile(r"\$peek\((.*)\)")  # $peek($sp(str))
    pat_cooked_reg = re.compile(r"^\$(\w+)")  # $sp
    pat_cooked_ops = re.compile(r"\+\d+|\*")  # +1**+2+3*
    pat_cooked_cast = re.compile(r"\((.*)\)$")

    def __post_init__(self):
        match = self.pat_expression.match(self.express)
        if not match:
            raise ValueError(f"invalid peek expression: {self.express}")
        self.operations = match.group(1)

    def type(self) -> str:
        if (
            self.pat_cooked_reg.match(self.operations)
            and self.pat_cooked_cast.match(
                self.pat_cooked_ops.sub(
                    "", self.pat_cooked_reg.sub("", self.operations)
                )
            )
        ):
            return "cooked"
        else:
            return "raw"

    def interpret(
        self, dwarf_interpreter
    ) -> [str]:  # [sp, +1, *, *, cast_type, *, cast_type]
        if self.type() == "cooked":
            return self.interpret_cooked(self.operations)
        elif self.type() == "raw":
            ...

    def interpret_cooked(self, exp: str) -> [str]:
        return (
            self.pat_cooked_reg.findall(exp)
            + self.pat_cooked_ops.findall(exp)
            + self.pat_cooked_cast.findall(exp)
        )


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

    def interpret(self, dwarf_interpreter) -> str:
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

    def __post_init__(self):
        self.script = self.script.strip()


def new(idx: int, address: str, define: str, script: str) -> Uprobe:
    defines: [Define] = []
    for i, d in enumerate(define.split(",")):
        if "=" not in d:
            continue
        var, express = d.split("=", 1)
        defines.append(new_define(i, idx, var, express))
    return Uprobe(
        idx=idx,
        address=Address(address),
        defines=defines,
        script=script,
    )
