import re
from . import uprobe


PAT_PROGRAM = re.compile(
    r"""
    (?P<addr> [^;]+);  # e.g. 0x1103c02;
    \s*
    (?P<define> [^;]+);  # e.g. n=peek($sp+0),stack=stack();
    \s*
    \{(?P<script> .*?)(?=};)  # e.g. {print('called')};""",
    re.S | re.X,
)


def parse(program: str) -> [uprobe.Uprobe]:
    if not PAT_PROGRAM.search(program):
        raise ValueError("invalid program, pattern not match")

    uprobes: [uprobe.Uprobe] = []
    for idx, match in enumerate(PAT_PROGRAM.finditer(program)):
        uprobes.append(
            uprobe.new(idx, *match.group("addr", "define", "script"))
        )

    return uprobes
