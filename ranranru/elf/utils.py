import subprocess


def yield_elf_lines(dwarf_filename: str, flags: str):
    proc = subprocess.Popen(
        ["objdump", f"-{flags}", dwarf_filename], stdout=subprocess.PIPE
    )
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        yield line.strip()
    proc.wait()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, " ".join(proc.args)
        )
