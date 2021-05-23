import os
import regex
import typing
import contextlib

import jinja2

from . import render_context


class Renderer:
    pat_program = regex.compile(
        r'''(?P<bin> /\S+) # [bin], startswith '/'
        \s+
        (?P<reg_mark> /?) (?P<uprobe> \S+) (?P=reg_mark)  # /[regex]/ or [raw]
        \s+
        (?P<script> \{ (:?[^{}]|(?&script))* \} )  # { [python_script] }''',
        regex.S | regex.X)

    tmpl = jinja2.Template(
        open(os.path.join(os.path.dirname(__file__),
                          'bcc_program.py.j2')).read(),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def __init__(self, program: str, sym_pathname: str):
        self.program = program
        self.sym_pathname = sym_pathname

    @contextlib.contextmanager
    def _parse(
        self
    ) -> typing.Tuple[render_context.GlobalContext,
                      render_context.TracePointContext]:
        if not self.pat_program.search(self.program):
            raise ValueError("invalid trace program, pattern doesn't match")

        ctx_managers = []
        for match in self.pat_program.finditer(self.program):
            pathname, reg_mark, uprobe, script, *_ = match.group(
                'bin', 'reg_mark', 'uprobe', 'script')
            ctx_managers.append(
                render_context.RenderContextManager(
                    pathname,
                    uprobe,
                    script[1:-1].strip(),
                    sym_pathname=self.sym_pathname,
                    uprobe_regex=True if reg_mark else False))

        with contextlib.ExitStack() as stack:
            ctxes = [stack.enter_context(m.dump()) for m in ctx_managers]
            global_ctx, tracepoint_ctxes = render_context.GlobalContext(), []
            for g_ctx, t_ctx in ctxes:
                global_ctx = global_ctx.merge(g_ctx)
                tracepoint_ctxes.append(t_ctx)

            # yield within with only works under CPython, see pep-0533
            yield global_ctx, tracepoint_ctxes

    @contextlib.contextmanager
    def render(self):
        with self._parse() as (global_ctx, tracepoint_ctxes):
            yield self.tmpl.render(
                globals=global_ctx,
                tracepoints=tracepoint_ctxes,
            )
