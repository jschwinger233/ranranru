import os
import jinja2

from .. import dwarf
from .. import program
from . import context


def render(
    uprobes: [program.Uprobe],
    dwarf_interpreter: dwarf.Interpreter,
    extra_vars: dict,
) -> str:
    tmpl = jinja2.Template(
        open(
            os.path.join(os.path.dirname(__file__), "bcc_program.py.j2")
        ).read(),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    context_manager = context.Manager(uprobes, dwarf_interpreter, extra_vars)
    return tmpl.render(**context_manager.dump_context())
