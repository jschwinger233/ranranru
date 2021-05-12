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
                          'bcc_program.py.j2')).read(),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def __init__(self, program: str):
        self.program = program

        self._pathname: str = None
        self._uprobe: str = None
        self._script: str = None
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
    _registered_vars: typing.Dict[str, typing.Tuple[str, VarContext]] = {}

    @classmethod
    def register_var(cls, varname: str, placeholder: str):
        def register(context_cls):
            cls._registered_vars[varname] = (placeholder, context_cls())

        return register

    def __init__(self, script: str):
        self.script = script

        self._missing_vars: typing.List[str] = None

    def parse(self):
        self._missing_vars = self._parse_missing_vars(self.script)

    def result_context(self) -> typing.Dict[str, typing.List[str]]:
        ctx = collections.defaultdict(list)
        for var in self._missing_vars:
            _, var_ctx = self._registered_vars[var]
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
