import re
from .uprobe import Uprobe


PAT_PROGRAM = re.compile(
    r"""
    (?P<addr> [^;]+);  # e.g. 0x1103c02;
    \s*
    (?P<defines> [^;]+);  # e.g. n=peek($sp+0),stack=stack();
    \s*
    \{(?P<script> .*?)(?=};)  # e.g. {print('called')};""",
    re.S | re.X,
)


def parse(program: str) -> [Uprobe]:
    if not PAT_PROGRAM.search(program):
        raise ValueError("invalid program, pattern not match")

    uprobes: [Uprobe] = []
    for idx, match in enumerate(PAT_PROGRAM.finditer(program)):
        uprobes.append(Uprobe(idx, *match.group("addr", "defines", "script")))

    return uprobes
