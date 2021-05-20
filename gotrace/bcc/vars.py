import re
import typing
import dataclasses

from .renderer import ScriptParser, ScriptVar


@ScriptParser.register_var('pid', 'pid = 0')
class PidVar(ScriptVar):
    def bcc_c_data_fields(self) -> typing.List[str]:
        return ['u32 pid;']

    def bcc_c_func_body(self) -> typing.List[str]:
        return ['data.pid = bpf_get_current_pid_tgid() >> 32;']

    def bcc_py_data_fields(self) -> typing.List[str]:
        return ['("pid", ctypes.c_uint32),']

    def bcc_py_callback_body(self) -> typing.List[str]:
        return ['pid = event.pid']


@ScriptParser.register_var('comm', "comm = ''")
class CommVar(ScriptVar):
    def bcc_c_data_fields(self) -> typing.List[str]:
        return ['char comm[16];']

    def bcc_c_func_body(self) -> typing.List[str]:
        return ['bpf_get_current_comm(&data.comm, sizeof(data.comm));']

    def bcc_py_data_fields(self) -> typing.List[str]:
        return ['("comm", ctypes.c_char * 16),']

    def bcc_py_callback_body(self) -> typing.List[str]:
        return ['comm = event.comm.decode()']


@ScriptParser.register_var('stack', "stack = ''")
class StackVar(ScriptVar):
    def bcc_c_data_fields(self) -> typing.List[str]:
        return ['int stack_id;']

    def bcc_c_global(self) -> typing.List[str]:
        return ['BPF_STACK_TRACE(stack_traces, 128);']

    def bcc_c_func_body(self) -> typing.List[str]:
        return [
            'data.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);'
        ]

    def bcc_py_data_fields(self) -> typing.List[str]:
        return ['("stack_id", ctypes.c_int),']

    def bcc_py_global(self) -> typing.List[str]:
        sym_pid = self.script_parser.sym_pid
        return f'''
def get_stack(stack_id):
    syms = []
    for addr in b.get_table('stack_traces').walk(stack_id):
        sym = b.sym(addr, {sym_pid}, show_module=True, show_offset=True)
        syms.append(sym.decode())
    return '\\n'.join(syms)
        '''.strip().split('\n')

    def bcc_py_callback_body(self) -> typing.List[str]:
        return ['stack = get_stack(event.stack_id)']


@ScriptParser.register_var('peek', '''
def peek(offsets, type):
    global var_ctx
    args = var_ctx.setdefault('peek', [])
    args.append((offsets, type))
        '''.strip())
class PeekVar(ScriptVar):
    @dataclasses.dataclass
    class PeekType:
        c_struct_field: str
        bpf_read_cast_type: str
        ctypes_struct_field: str

    pat = re.compile(r'\w+|[-+]\d+')
    typemap = {
        'string': PeekType(
            'char {}[128];',
            'char*',
            'ctypes.c_char * 128',
        ),
        'int64': PeekType(
            'u64 {};',
            'u64',
            'ctypes.c_int64',
        ),
    }

    def __init__(self, script_parser: 'ScriptParser',
                 ctx: typing.List[typing.Tuple[str, str]]):
        for offsets, type in ctx:
            if not self.pat.match(offsets):
                raise ValueError(f'invalid peek offsets: {offsets}')
            if type not in self.typemap:
                raise ValueError(f'invalid peek type: {type}')

        super().__init__(script_parser, ctx)

    def bcc_c_data_fields(self) -> typing.List[str]:
        res = []
        for i, (_, type) in enumerate(self.ctx):
            res.append(self.typemap[type].c_struct_field.format(f'peek{i}'))
        return res

    def bcc_c_func_body(self) -> typing.List[str]:
        res = []
        for i, (offsets, type) in enumerate(self.ctx):
            r = []
            r.append('void')
            reg, *offs = self.pat.findall(offsets)
            pointer = f'ctx->{reg}'
            for j, off in enumerate(offs[:-1]):
                r[0] += f' *a{i}{j},'
                r.append(
                    f'bpf_probe_read(&a{i}{j}, sizeof(a{i}{j}), (void**)((void*){pointer}{off}));'  # noqa
                )
                pointer = f'a{i}{j}'

            r[0] = r[0].rstrip(',') + ';'
            if r[0] == 'void;':
                del r[0]
            r.append(
                f'bpf_probe_read(&data.peek{i}, sizeof(data.peek{i}), ({self.typemap[type].bpf_read_cast_type}*)((void*){pointer}{offs[-1]}));'  # noqa
            )
            res += r

        return res

    def bcc_py_data_fields(self) -> typing.List[str]:
        res = []
        for i, (_, type) in enumerate(self.ctx):
            res.append(
                f'("peek{i}", {self.typemap[type].ctypes_struct_field}),')
        return res

    def bcc_py_callback_body(self) -> typing.List[str]:
        res = '''
def peek(*args):
        '''.strip(' ').rstrip('\n')
        for i, (offsets, type) in enumerate(self.ctx):
            res += f'''
    if args == ('{offsets}', '{type}'):
        return event.peek{i}
            '''.strip(' ').rstrip('\n')
        return res.strip().split('\n')
