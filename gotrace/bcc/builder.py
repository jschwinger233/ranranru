import re
import os
import typing
import contextlib
import collections

import jinja2

from . import sym


class Builder:
    pat = re.compile(
        r'(?P<pathname>[^:]+):(?P<uprobe>\S+)\s+\{(?P<script>.*)\}', re.S)

    tmpl = jinja2.Template(
        open(os.path.join(os.path.dirname(__file__),
                          'bcc_program.py.j2')).read(),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def __init__(self, program: str, sym_pathname: str):
        self._sym_pid: int = None
        self._ctx: typing.Dict[str, typing.List[str]] = {}

        m = self.pat.match(program)
        if not m:
            raise ValueError("wrong trace program, pattern doesn't match")

        self._pathname, self._uprobe, self._script = m.group(
            'pathname'), m.group('uprobe'), m.group('script')

        self.program = program
        self.sym_process = sym.Process.from_pathname(sym_pathname or  # noqa
                                                     self._pathname)

    @contextlib.contextmanager
    def setup(self):
        self._setup_symbols()
        try:
            self._parse()
            yield self._dumps()
        finally:
            self._wipeout_symbols()

    def _setup_symbols(self):
        self.sym_process.spawn()
        try:
            self.sym_process.setup_bcc_symfs(self._pathname)
        except:  # noqa
            self.sym_process.kill(9)
            self.sym_process.wait()
            raise

        self._sym_pid = self.sym_process.pid

    def _wipeout_symbols(self):
        self.sym_process.kill(9)
        self.sym_process.wait()
        self.sym_process.wipeout_bcc_symfs()

    def _parse(self):

        script_parser = ScriptParser(self._script, self._sym_pid)
        script_parser.parse()
        self._ctx = script_parser.result_context()

    def _dumps(self) -> str:
        return self.tmpl.render(
            tracee_pathname=self._pathname,
            uprobe=self._uprobe,
            script=self._script,
            **self._ctx,
        )


class VarContext:
    def __init__(self, script_parser: 'ScriptParser'):
        self.script_parser = script_parser
        super().__init__()

    def bcc_py_imports(self) -> typing.List[str]:
        return []

    def bcc_c_headers(self) -> typing.List[str]:
        return []

    def bcc_c_data_fields(self) -> typing.List[str]:
        return []

    def bcc_c_global(self) -> typing.List[str]:
        return []

    def bcc_c_func_body(self) -> typing.List[str]:
        return []

    def bcc_py_data_fields(self) -> typing.List[str]:
        return []

    def bcc_py_global(self) -> typing.List[str]:
        return []

    def bcc_py_callback_body(self) -> typing.List[str]:
        return []


class ScriptParser:
    missing_var_pat = re.compile(r"'(?P<missing_var>[^']+)")
    _registered_vars: typing.Dict[str, typing.Tuple[str, typing.Callable[
        ['ScriptParser'], VarContext]]] = {}

    @classmethod
    def register_var(cls, varname: str, placeholder: str):
        def register(context_cls):
            cls._registered_vars[varname] = (placeholder,
                                             lambda self: context_cls(self))

        return register

    def __init__(self, script: str, sym_pid: int):
        self.script = script
        self.sym_pid = sym_pid

        self._missing_vars: typing.List[str] = None

    def parse(self):
        self._missing_vars = self._parse_missing_vars(self.script)

    def result_context(self) -> typing.Dict[str, typing.List[str]]:
        ctx = collections.defaultdict(list)
        for var in self._missing_vars:
            _, var_ctx_cls = self._registered_vars[var]
            var_ctx = var_ctx_cls(self)
            ctx['bcc_py_imports'].extend(var_ctx.bcc_py_imports())
            ctx['bcc_c_headers'].extend(var_ctx.bcc_c_headers())
            ctx['bcc_c_data_fields'].extend(var_ctx.bcc_c_data_fields())
            ctx['bcc_c_global'].extend(var_ctx.bcc_c_global())
            ctx['bcc_c_func_body'].extend(var_ctx.bcc_c_func_body())
            ctx['bcc_py_data_fields'].extend(var_ctx.bcc_py_data_fields())
            ctx['bcc_py_global'].extend(var_ctx.bcc_py_global())
            ctx['bcc_py_callback_body'].extend(var_ctx.bcc_py_callback_body())
        return dict(ctx)

    def _parse_missing_vars(self, script: str) -> typing.List[str]:
        missing_vars = []
        while True:
            try:
                exec(script, {}, {})

            except NameError as e:
                missing_var = self.missing_var_pat.search(
                    e.args[0]).group('missing_var')
                if missing_var not in self._registered_vars:
                    raise ValueError(f'invalid var: {missing_var}')

                missing_vars.append(missing_var)
                placeholder, _ = self._registered_vars[missing_var]
                script = f'{missing_var} = {placeholder}\n{script}'

            except:  # noqa
                raise ValueError(f'invalid python script: \n{script}')

            else:
                break

        return missing_vars
