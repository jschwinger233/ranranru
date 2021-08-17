import re
import typing
import operator
import contextlib
import collections
import dataclasses

from . import sym


@dataclasses.dataclass
class GlobalContext:
    bcc_py_imports: typing.List[str] = dataclasses.field(default_factory=list)
    bcc_c_headers: typing.List[str] = dataclasses.field(default_factory=list)
    bcc_py_global: typing.List[str] = dataclasses.field(default_factory=list)

    def merge(self, ctx: 'GlobalContext') -> 'GlobalContext':
        new_imports = list(set(self.bcc_py_imports + ctx.bcc_py_imports))
        new_headers = list(set(self.bcc_c_headers + ctx.bcc_c_headers))
        new_py_global = list(set(self.bcc_py_global + ctx.bcc_py_global))
        return dataclasses.replace(self,
                                   bcc_py_imports=new_imports,
                                   bcc_c_headers=new_headers,
                                   bcc_py_global=new_py_global)


@dataclasses.dataclass
class TracePointContext:
    attach_pathname: str
    attach_uprobe: str
    attach_uprobe_regex: bool
    bcc_py_user_script: str

    bcc_c_data_fields: typing.List[str]
    bcc_c_global: typing.List[str]
    bcc_c_callback_body: typing.List[str]

    bcc_py_data_fields: typing.List[str]
    bcc_py_callback_body: typing.List[str]

    attach_type: str = dataclasses.field(init=False)

    def __post_init__(self):
        self.attach_type = 'addr' if re.match(r'^[x0-9a-x]+$',
                                              self.attach_uprobe) else 'sym'
        if self.attach_uprobe_regex:
            self.attach_type = 'sym_re'

        if self.attach_type == 'sym':
            self.attach_uprobe = f"'{self.attach_uprobe}'"
        if self.attach_type == 'sym_re':
            self.attach_uprobe = f"r'{self.attach_uprobe}'"


class RenderContextManager:
    def __init__(self, tracee: str, uprobe: str, script: str, *,
                 tracee_sym: str, uprobe_regex: bool):
        self.tracee = tracee
        self.uprobe = uprobe
        self.script = script
        self.uprobe_regex = uprobe_regex

        self._sym_process = sym.Process.from_pathname(tracee_sym or  # noqa
                                                      self.tracee)

    @contextlib.contextmanager
    def dump(self) -> typing.Tuple[GlobalContext, TracePointContext]:
        self._setup_symbols()
        try:
            yield self._dump()
        finally:
            self._wipeout_symbols()

    def _dump(self) -> typing.Tuple[GlobalContext, TracePointContext]:
        script_parser = UserScriptParser(self.script, self._sym_pid)
        script_ctx = script_parser.parse()
        return GlobalContext(*[
            operator.getitem(script_ctx, item)
            for item in ('bcc_py_imports', 'bcc_c_headers', 'bcc_py_global')
        ]), TracePointContext(
            self.tracee, self.uprobe, self.uprobe_regex, self.script, *[
                operator.getitem(script_ctx, item)
                for item in ('bcc_c_data_fields', 'bcc_c_global',
                             'bcc_c_callback_body', 'bcc_py_data_fields',
                             'bcc_py_callback_body')
            ])

    def _setup_symbols(self):
        self._sym_process.spawn()
        try:
            self._sym_process.setup_bcc_symfs(self.tracee)
        except:  # noqa
            self._sym_process.kill(9)
            self._sym_process.wait()
            raise

    def _wipeout_symbols(self):
        self._sym_process.kill(9)
        self._sym_process.wait()
        self._sym_process.wipeout_bcc_symfs()

    @property
    def _sym_pid(self):
        return self._sym_process.pid


class UserScriptVar:
    def __init__(self, script_parser: 'UserScriptParser', ctx: typing.Any):
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

    def bcc_c_callback_body(self) -> typing.List[str]:
        return []

    def bcc_py_data_fields(self) -> typing.List[str]:
        return []

    def bcc_py_global(self) -> typing.List[str]:
        return []

    def bcc_py_callback_body(self) -> typing.List[str]:
        return []


class UserScriptParser:
    missing_var_pat = re.compile(r"'(?P<missing_var>[^']+)")
    _registered_vars: typing.Dict[str, typing.Tuple[str, typing.Callable[
        ['UserScriptParser'], UserScriptVar]]] = {}

    @classmethod
    def register_var(cls, varname: str, placeholder: str):
        def register(var_cls):
            cls._registered_vars[varname] = (placeholder, lambda self: var_cls(
                self, self._missing_vars_ctx.get(varname)))

        return register

    def __init__(self, script: str, sym_pid: int):
        self.script = script
        self.sym_pid = sym_pid

    def parse(self) -> typing.Dict[str, typing.List[str]]:
        missing_vars, self._missing_vars_ctx = self._parse_missing_vars(
            self.script)
        ctx = collections.defaultdict(list)
        for varname in missing_vars:
            _, var_cls = self._registered_vars[varname]
            var = var_cls(self)
            for meth in var.template_methods():
                ctx[meth].extend(getattr(var, meth)())
        return ctx

    def _parse_missing_vars(
        self, script: str
    ) -> typing.Tuple[typing.List[str], typing.Dict[str, typing.Any]]:
        missing_vars = []
        while True:
            g = {'var_ctx': {}}
            try:
                with open('/dev/null', 'w') as null:
                    with contextlib.redirect_stdout(null):
                        with contextlib.redirect_stderr(null):
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
