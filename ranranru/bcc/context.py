import functools
import dataclasses

from .. import program


@dataclasses.dataclass
class UprobeContext:
    idx: int = None
    tracee_binary: str = ''
    address: str = ''

    c_global: str = ""
    c_data: str = ""
    c_callback: str = ""

    py_data: str = ""
    py_callback: str = ""

    def __post_init__(self):
        self.tracee_binary = self.tracee_binary.strip()
        self.address = self.address.strip()
        self.c_global = self.c_global.strip()
        self.c_data = self.c_data.strip()
        self.c_callback = self.c_callback.strip()
        self.py_data = self.py_data.strip()
        self.py_callback = self.py_callback.strip()

    def merge(self, other: "UprobeContext") -> "UprobeContext":
        self.c_global = f"{self.c_global}\n{other.c_global}"
        self.c_data = f"{self.c_data}\n{other.c_data}"
        self.c_callback = f"{self.c_callback}\n{other.c_callback}"
        self.py_data = f"{self.py_data}\n{other.py_data}"
        self.py_callback = f"{self.py_callback}\n{other.py_callback}" # noqa


class Manager:
    def __init__(self, uprobes: [program.Uprobe], extra_vars: dict):
        self.uprobes = uprobes
        self.extra_vars = extra_vars

    def dump_context(self) -> str:
        ctxes = []
        for uprobe in self.uprobes:
            ctx = UprobeContext(
                idx=uprobe.idx,
                tracee_binary=self.extra_vars["tracee_binary"],
                address=uprobe.address,
            )
            for define in uprobe.parsed_defines:
                ctx.merge(convert(define, self.extra_vars))
            ctx.py_callback += f'\n\n{uprobe.script}'
            ctxes.append(dataclasses.asdict(ctx))
        return {"uprobes": ctxes}


@functools.singledispatch
def convert(parsed_define, extra_ctx: dict) -> UprobeContext:
    pass


@convert.register
def _(pid: program.ParsedPid, ___):
    return UprobeContext(
        c_data="u32 pid;",
        c_callback="data.pid = bpf_get_current_pid_tgid() >> 32;",
        py_data='("pid", ctypes.c_uint32),',
        py_callback=f"{pid.varname} = event.pid",
    )


@convert.register
def _(tid: program.ParsedTid, ___):
    return UprobeContext(
        c_data="u32 tid;",
        c_callback="data.tid = bpf_get_current_pid_tgid() & 0xffffffff;",
        py_data='("tid", ctypes.c_uint32),',
        py_callback=f"{tid.varname} = event.tid",
    )


@convert.register
def _(comm: program.ParsedComm, ___):
    return UprobeContext(
        c_data="char comm[16];",
        c_callback="bpf_get_current_comm(&data.comm, sizeof(data.comm));",
        py_data='("comm", ctypes.c_char * 16),',
        py_callback=f"{comm.varname} = event.comm.decode()",
    )


@convert.register
def _(stack: program.ParsedStack, extra_ctx: dict):
    try:
        sym_pid = extra_ctx["sym_pid"]
    except KeyError:
        raise ValueError("sym_pid is required to render bcc script for stack")

    return UprobeContext(
        c_data="int stack_id;",
        c_global=f"BPF_STACK_TRACE(stack_trace{stack.uprobe_idx}, 128);",
        c_callback=f"data.stack_id = stack_trace{stack.uprobe_idx}.get_stackid(ctx, BPF_F_USER_STACK);",  # noqa
        py_data='("stack_id", ctypes.c_int),',
        py_callback=f"""
syms = []
for addr in b.get_table('stack_trace{stack.uprobe_idx}').walk(event.stack_id):
    sym = b.sym(addr, {sym_pid}, show_module=True, show_offset=True)
    syms.append(sym.decode())
{stack.varname} = '\\n'.join(syms)
""",
    )


@convert.register
def _(peek: program.ParsedPeek, __):
    def gen_c_data() -> str:
        return {"string": "char peek{}[128];", "int64": "u64 {};"}[
            peek.cast_type
        ].format(peek.idx)

    def gen_c_callback() -> str:
        r = []
        r.append("void")
        pointer = f"ctx->{peek.reg}"
        i = peek.idx
        for j, off in enumerate(peek.offsets[:-1]):
            r[0] += f" *a{i}{j},"
            r.append(
                f"bpf_probe_read(&a{i}{j}, sizeof(a{i}{j}), (void**)((void*){pointer}{off}));"  # noqa
            )
            pointer = f"a{i}{j}"

        r[0] = r[0].rstrip(",") + ";"
        if r[0] == "void;":
            del r[0]
        cast_type = {"string": "char*", "int64": "u64"}[peek.cast_type]
        r.append(
            f"bpf_probe_read(&data.peek{i}, sizeof(data.peek{i}), ({cast_type}*)((void*){pointer}{peek.offsets[-1]}));"  # noqa
        )
        return "\n".join(r)

    def gen_py_data() -> str:
        ctypes_field = {
            "string": "ctypes.c_char * 128",
            "int64": "ctypes.c_int64",
        }[peek.cast_type]
        return f'("peek{peek.idx}", {ctypes_field}),'

    def gen_py_callback() -> str:
        return f"{peek.varname} = event.peek{peek.idx}"

    return UprobeContext(
        c_data=gen_c_data(),
        c_callback=gen_c_callback(),
        py_data=gen_py_data(),
        py_callback=gen_py_callback(),
    )
