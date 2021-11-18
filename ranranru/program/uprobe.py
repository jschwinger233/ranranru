import re
import dataclasses


@dataclasses.dataclass
class ParsedDefine:
    idx: int
    uprobe_idx: int
    varname: str
    express: str


@dataclasses.dataclass
class ParsedPid(ParsedDefine):
    pass


@dataclasses.dataclass
class ParsedTid(ParsedDefine):
    pass


@dataclasses.dataclass
class ParsedComm(ParsedDefine):
    pass


@dataclasses.dataclass
class ParsedStack(ParsedDefine):
    pass


@dataclasses.dataclass
class ParsedPeek(ParsedDefine):
    reg: str = None
    offsets: [str] = None
    cast_type: str = None

    def __post_init__(self):
        match = re.match(r"\$peek\(\((\w+)\)([^)]+)", self.express)
        if not match:
            raise ValueError(f"invalid peek expression: {self.express}")
        offset_exp, self.cast_type = match.group(2), match.group(1)
        self.reg, *self.offsets = re.findall(r"\w+|[-+]\d+", offset_exp)


def newParsedDefine(
    idx: int,
    uprobe_idx: int,
    var: str,
    express: str,
) -> ParsedDefine:
    if express == "$pid":
        cls = ParsedPid
    elif express == "$tid":
        cls = ParsedTid
    elif express == "$comm":
        cls = ParsedComm
    elif express == "$stack":
        cls = ParsedStack
    elif express.startswith("$peek"):
        cls = ParsedPeek
    else:
        raise ValueError(f"invalid define expression: {express}")
    return cls(idx, uprobe_idx, var, express)


@dataclasses.dataclass
class Uprobe:
    idx: int
    address: str
    defines: str
    script: str

    parsed_defines: [ParsedDefine] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        self.address = self.address.strip()
        self.defines = self.defines.strip()
        self.script = self.script.strip()
        for idx, define in enumerate(self.defines.split(",")):
            var, express = define.split("=", 1)
            self.parsed_defines.append(
                newParsedDefine(idx, self.idx, var.strip(), express.strip())
            )
