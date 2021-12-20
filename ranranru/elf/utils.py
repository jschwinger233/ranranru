import subprocess

_cache: {(str, str): [bytes]} = {}


def yield_elf_lines(dwarf_filename: str, flags: str):
    if (lines := _cache.get((dwarf_filename, flags))):
        return lines

    _cache[(dwarf_filename, flags)] = lines = []
    proc = subprocess.Popen(
        ["objdump", f"-{flags}", dwarf_filename], stdout=subprocess.PIPE
    )
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.strip())
    proc.wait()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, " ".join(proc.args)
        )

    return lines
