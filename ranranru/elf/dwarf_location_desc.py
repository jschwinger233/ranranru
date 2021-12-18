import re


PAT_OP_REG = re.compile(r"DW_OP_reg.*?\((.*?)\)")
PAT_OP_FBREG = re.compile(r"DW_OP_fbreg:\s*(\w+)")


def parse_op_reg(desc: str) -> str:
    reg = PAT_OP_REG.search(desc).group(1)
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


def parse_op_fbreg(desc: str, cfa: str) -> str:
    offset = PAT_OP_FBREG.search(desc).group(1)
    if offset.isdigit():
        offset = f"+{offset}"
    return f"{cfa}{offset}*"


def parse(desc: str, cfa: str) -> str:
    res: [str] = []
    for d in desc.split(";"):
        if "DW_OP_reg" in d:
            res.append(parse_op_reg(d))
        elif "DW_OP_fbreg" in d:
            res.append(parse_op_fbreg(d, cfa))
        elif "DW_OP_piece" in d:
            res.append(";")
        elif "DW_OP_call_frame_cfa" in d:
            res.append(cfa + "*")
        else:
            raise ValueError(f"invalid dwarf location description: {d}")
    return "".join(res)
