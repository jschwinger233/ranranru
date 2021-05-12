import typing

from .builder import ScriptParser, VarContext


@ScriptParser.register_var('pid', '0')
class PidContext(VarContext):
    def bcc_c_data_fields(self) -> typing.List[str]:
        return ['u32 pid;']

    def bcc_c_func_body(self) -> typing.List[str]:
        return ['data.pid = bpf_get_current_pid_tgid() >> 32;']

    def bcc_py_data_fields(self) -> typing.List[str]:
        return ['("pid", ctypes.c_uint32),']

    def bcc_py_callback_body(self) -> typing.List[str]:
        return ['pid = event.pid']


@ScriptParser.register_var('comm', "''")
class CommContext(VarContext):
    def bcc_c_data_fields(self) -> typing.List[str]:
        return ['char comm[16];']

    def bcc_c_func_body(self) -> typing.List[str]:
        return ['bpf_get_current_comm(&data.comm, sizeof(data.comm));']

    def bcc_py_data_fields(self) -> typing.List[str]:
        return ['("comm", ctypes.c_char * 16),']

    def bcc_py_callback_body(self) -> typing.List[str]:
        return ['comm = event.comm.decode()']


@ScriptParser.register_var('stack', "''")
class StackContext(VarContext):
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
        return '''
import os
def get_stack(stack_id):
    debug_pid = int(os.getenv('DEBUG_PID'))
    syms = []
    for addr in b.get_table('stack_traces').walk(stack_id):
        sym = b.sym(addr, debug_pid, show_module=True, show_offset=True)
        syms.append(sym.decode())
    return '\\n'.join(syms)
        '''.strip().split('\n')

    def bcc_py_callback_body(self) -> typing.List[str]:
        return ['stack = get_stack(event.stack_id)']
