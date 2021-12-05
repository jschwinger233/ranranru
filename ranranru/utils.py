import subprocess


def bash(command: str, *args: [str]) -> str:
    command = command.format(*args)
    print(command)
    process = subprocess.run(
        command,
        capture_output=True,
        shell=True,
        check=True,
        text=True,
    )
    return process.stdout.strip()


def escape_awk_pattern(pat: str) -> str:
    return (
        pat.replace("/", r"\/")
        .replace("(", r"\(")
        .replace(")", r"\)")
        .replace("*", r"\*")
    )
