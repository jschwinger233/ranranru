import re
import os
import typing
import contextlib
import collections

import jinja2

from . import sym
from gotrace.utils import io as ioutils


class Renderer:
    pat_program = re.compile(
        r'''^(?P<pathname>[^:]+):(?P<uprobe>\S+)  # [bin]:[uprobe]
        \s+
        \{\s*(?P<script>.*?)\s*\}$  # { [python_script] }''', re.S | re.X)
    pat_addr = re.compile(r'^[x0-9a-z]+$')

    tmpl = jinja2.Template(
        open(os.path.join(os.path.dirname(__file__),
                          'bcc_program.py.j2')).read(),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def __init__(self, program: str, sym_pathname: str):
        self._sym_pid: int = None
        self.render_ctx: typing.Dict[str, typing.List[str]] = {}

        m = self.pat_program.match(program)
        if not m:
            raise ValueError("wrong trace program, pattern doesn't match")

        self._pathname, uprobe, self._script = m.group('pathname'), m.group(
            'uprobe'), m.group('script')
        self._uprobe_directive = f"sym='{uprobe}'"
        if self.pat_addr.match(uprobe):
            self._uprobe_directive = f'addr={uprobe}'

        self.program = program
        self.sym_process = sym.Process.from_pathname(sym_pathname or  # noqa
                                                     self._pathname)

    @contextlib.contextmanager
    def render(self):
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
        self.render_ctx = script_parser.get_render_context()

    def _dumps(self) -> str:
        return self.tmpl.render(
            tracee_pathname=self._pathname,
            uprobe_directive=self._uprobe_directive,
            script=self._script,
            **self.render_ctx,
        )


class ScriptVar:
    def __init__(self, script_parser: 'ScriptParser', ctx: typing.Any):
        self.script_parser = script_parser
        self.ctx = ctx

    @staticmethod
    def template_methods() -> typing.List[str]:
        return [meth for meth in dir(__class__) if meth.startswith('bcc_')]

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
        ['ScriptParser'], ScriptVar]]] = {}

    @classmethod
    def register_var(cls, varname: str, placeholder: str):
        def register(var_cls):
            cls._registered_vars[varname] = (placeholder, lambda self: var_cls(
                self, self._missing_vars_ctx.get(varname)))

        return register

    def __init__(self, script: str, sym_pid: int):
        self.script = script
        self.sym_pid = sym_pid

        self._missing_vars: typing.List[str] = None
        self._missing_vars_ctx: typing.Dict[str, typing.Any] = None

    def parse(self):
        self._missing_vars, self._missing_vars_ctx = self._parse_missing_vars(
            self.script)

    def get_render_context(self) -> typing.Dict[str, typing.List[str]]:
        ctx = collections.defaultdict(list)
        for varname in self._missing_vars:
            _, var_cls = self._registered_vars[varname]
            var = var_cls(self)
            for meth in var.template_methods():
                ctx[meth].extend(getattr(var, meth)())
        return dict(ctx)

    def _parse_missing_vars(
        self, script: str
    ) -> typing.Tuple[typing.List[str], typing.Dict[str, typing.Any]]:
        missing_vars = []
        while True:
            g = {'var_ctx': {}}
            try:
                with ioutils.redirect({1: '/dev/null', 2: '/dev/null'}):
                    exec(script, g, {})

            except NameError as e:
                missing_var = self.missing_var_pat.search(
                    e.args[0]).group('missing_var')
                if missing_var not in self._registered_vars:
                    raise ValueError(f'invalid var: {missing_var}')

                missing_vars.append(missing_var)
                placeholder, _ = self._registered_vars[missing_var]
                script = f'{placeholder}\n{script}'

            except:  # noqa
                raise ValueError(f'invalid python script: \n{script}')

            else:
                break

        return missing_vars, g['var_ctx']
