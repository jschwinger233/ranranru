import re
import os
import typing
import collections

import jinja2


class Builder:
    pat = re.compile(
        r'(?P<pathname>[^:]+):(?P<uprobe>\S+)\s+\{(?P<script>.*)\}', re.S)

    tmpl = jinja2.Template(
        open(os.path.join(os.path.dirname(__file__),
                          'bcc_program.py.j2')).read())

    def __init__(self, program: str):
        self.program = program
        self.debug_pid: typing.Optional[int] = None

        self._pathname: typing.Optional[str] = None
        self._uprobe: typing.Optional[str] = None
        self._script: typing.Optional[str] = None
        self._ctx: typing.Dict[str, typing.List[str]] = {}

    def parse(self):
        m = self.pat.match(self.program)
        if not m:
            raise ValueError("wrong trace program, pattern doesn't match")

        self._pathname, self._uprobe, self._script = m.group(
            'pathname'), m.group('uprobe'), m.group('script')

        script_parser = ScriptParser(self._script)
        script_parser.parse()
        self._ctx = script_parser.result_context()

    def dumps(self) -> str:
        if not self._uprobe:
            raise RuntimeError('"dumps" must be called after "parse"')

        return self.tmpl.render(
            tracee_pathname=self._pathname,
            uprobe=self._uprobe,
            script=self._script,
            **self._ctx,
        )

    def tracee_pathname(self) -> str:
        return self._pathname


class VarContext:
    def bcc_py_imports(self) -> typing.List[str]:
        return []

    def bcc_c_headers(self) -> typing.List[str]:
        return []

    def bcc_c_data_fields(self) -> typing.List[str]:
        return []

    def bcc_c_init_tables(self) -> typing.List[str]:
        return []

    def bcc_c_func_lines(self) -> typing.List[str]:
        return []

    def bcc_py_data_fields(self) -> typing.List[str]:
        return []

    def bcc_py_callback_lines(self) -> typing.List[str]:
        return []


class PidContext(VarContext):
    def bcc_c_data_fields(self) -> typing.List[str]:
        return ['u32 pid;']

    def bcc_c_func_lines(self) -> typing.List[str]:
        return ['data.pid = bpf_get_current_pid_tgid() >> 32;']

    def bcc_py_data_fields(self) -> typing.List[str]:
        return ['("pid", ctypes.c_uint32),']

    def bcc_py_callback_lines(self) -> typing.List[str]:
        return ['pid = event.pid']


class CommContext(VarContext):
    def bcc_c_data_fields(self) -> typing.List[str]:
        return ['char comm[16];']

    def bcc_c_func_lines(self) -> typing.List[str]:
        return ['bpf_get_current_comm(&data.comm, sizeof(data.comm));']

    def bcc_py_data_fields(self) -> typing.List[str]:
        return ['("comm", ctypes.c_char * 16),']

    def bcc_py_callback_lines(self) -> typing.List[str]:
        return ['comm = event.comm']


class ScriptParser:
    missing_var_allowed = {
        'pid': (0, PidContext()),
        'comm': (r"''", CommContext()),
    }
    missing_var_pat = re.compile(r"'(?P<missing_var>[^']+)")

    def __init__(self, script: str):
        self.script = script

        self._missing_vars: typing.Optional[typing.List[str]] = None

    def parse(self):
        self._missing_vars = self._parse_missing_vars(self.script)

    def result_context(self) -> typing.Dict[str, typing.List[str]]:
        ctx = collections.defaultdict(list)
        for var in self._missing_vars:
            _, var_ctx = self.missing_var_allowed[var]
            ctx['bcc_py_imports'].extend(var_ctx.bcc_py_imports())
            ctx['bcc_c_headers'].extend(var_ctx.bcc_c_headers())
            ctx['bcc_c_data_fields'].extend(var_ctx.bcc_c_data_fields())
            ctx['bcc_c_init_tables'].extend(var_ctx.bcc_c_init_tables())
            ctx['bcc_c_func_lines'].extend(var_ctx.bcc_c_func_lines())
            ctx['bcc_py_data_fields'].extend(var_ctx.bcc_py_data_fields())
            ctx['bcc_py_callback_lines'].extend(
                var_ctx.bcc_py_callback_lines())
        return dict(ctx)

    def _parse_missing_vars(self, script: str) -> typing.List[str]:
        missing_vars = []
        while True:
            try:
                exec(script, {}, {})

            except NameError as e:
                missing_var = self.missing_var_pat.search(
                    e.args[0]).group('missing_var')
                if missing_var not in self.missing_var_allowed:
                    raise ValueError(f'invalid var: {missing_var}')

                missing_vars.append(missing_var)
                placeholder, _ = self.missing_var_allowed[missing_var]
                script = f'{missing_var} = {placeholder}\n{script}'

            except:  # noqa
                raise ValueError(f'invalid python script: \n{script}')

            else:
                break

        return missing_vars
