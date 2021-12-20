import functools
import dataclasses

from .. import elf
from .. import program


@dataclasses.dataclass
class UprobeContext:
    idx: int = None
    tracee_binary: str = ""
    address: str = ""

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

    def merge(self, other: "UprobeContext"):
        self.c_global = f"{self.c_global}\n{other.c_global}".rstrip()
        self.c_data = f"{self.c_data}\n{other.c_data}".rstrip()
        self.c_callback = f"{self.c_callback}\n{other.c_callback}".rstrip()
        self.py_data = f"{self.py_data}\n{other.py_data}".rstrip()
        self.py_callback = f"{self.py_callback}\n{other.py_callback}".rstrip()  # noqa


class Manager:
    def __init__(
        self,
        uprobes: [program.Uprobe],
        elf_interpreter: elf.Interpreter,
        extra_ctx: dict,
    ):
        self.uprobes = uprobes
        self.elf_interpreter = elf_interpreter
        self.extra_ctx = extra_ctx

    def dump_context(self) -> str:
        ctxes = []
        for uprobe in self.uprobes:
            ctx = UprobeContext(
                idx=uprobe.idx,
                tracee_binary=self.extra_ctx["real_target"],
                address=uprobe.address.interpret(self.elf_interpreter),
            )
            for define in uprobe.defines:
                ctx.merge(
                    convert(define, self.elf_interpreter, ctx, self.extra_ctx)
                )
            ctx.py_callback += f"\n\n{uprobe.script}"
            ctxes.append(dataclasses.asdict(ctx))
        return {"uprobes": ctxes}


@functools.singledispatch
def convert(
    define, interpreter, ctx: UprobeContext, extra_ctx: dict
) -> UprobeContext:
    pass


@convert.register
def _(pid: program.PidDefine, __, ___, ____):
    return UprobeContext(
        c_data="u32 pid;",
        c_callback="data.pid = bpf_get_current_pid_tgid() >> 32;",
        py_data='("pid", ctypes.c_uint32),',
        py_callback=f"{pid.varname} = event.pid",
    )


@convert.register
def _(tid: program.TidDefine, __, ___, ____):
    return UprobeContext(
        c_data="u32 tid;",
        c_callback="data.tid = bpf_get_current_pid_tgid() & 0xffffffff;",
        py_data='("tid", ctypes.c_uint32),',
        py_callback=f"{tid.varname} = event.tid",
    )


@convert.register
def _(comm: program.CommDefine, __, ___, ____):
    return UprobeContext(
        c_data="char comm[16];",
        c_callback="bpf_get_current_comm(&data.comm, sizeof(data.comm));",
        py_data='("comm", ctypes.c_char * 16),',
        py_callback=f"{comm.varname} = event.comm.decode()",
    )


@convert.register
def _(stack: program.StackDefine, __, ___, extra_ctx: dict):
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
def _(peek: program.PeekDefine, interpreter, ctx, __):
    reg, *ops, cast_type = peek.interpret(ctx.address, interpreter)

    @dataclasses.dataclass
    class Cast:
        c_data: str
        py_data: str

    casts = {
        "str": Cast("char peek{}[128];", "ctypes.c_char * 128"),
        "int64": Cast("u64 peek{};", "ctypes.c_int64"),
        "int32": Cast("u32 peek{};", "ctypes.c_int32"),
        "int8": Cast("u8 peek{};", "ctypes.c_int8"),
        "float64": Cast("double peek{};", "ctypes.c_double"),
    }

    def gen_c_data() -> str:
        return casts[cast_type].c_data.format(peek.idx)

    def gen_c_callback() -> str:
        r = ["void"]
        pointer, i = f"ctx->{reg}", peek.idx
        for j, op in enumerate(ops[:-1]):
            if op == "*":
                r[0] += f" *a{i}{j}, "
                r.append(
                    f"bpf_probe_read(&a{i}{j}, sizeof(a{i}{j}), (void*){pointer});"  # noqa
                )
                pointer = f"a{i}{j}"

            elif op.startswith(("+", "-")):
                pointer += op

        if ops and ops[-1] == "*":
            r.append(
                f"bpf_probe_read(&data.peek{i}, sizeof(data.peek{i}), (void*){pointer});"  # noqa
            )

        else:
            r.append(f"data.peek{i} = {pointer};")

        r[0] = r[0].rstrip(", ") + ";"
        if r[0] == "void;":
            del r[0]
        return "\n".join(r)

    def gen_py_data() -> str:
        ctypes_field = casts[cast_type].py_data
        return f'("peek{peek.idx}", {ctypes_field}),'

    def gen_py_callback() -> str:
        return f"{peek.varname} = event.peek{peek.idx}"

    return UprobeContext(
        c_data=gen_c_data(),
        c_callback=gen_c_callback(),
        py_data=gen_py_data(),
        py_callback=gen_py_callback(),
    )
