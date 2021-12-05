from ..utils import bash, escape_awk_pattern


class Interpreter:
    def __init__(self, dwarf_filename: str, dwarf_path_prefix: str):
        self.dwarf_filename = dwarf_filename
        self.dwarf_path_prefix = dwarf_path_prefix

    def find_address_by_filename_lineno(
        self, filename: str, lineno: int
    ) -> str:
        candidates = bash(
            "objdump -WL {} | awk '/{}/ && /:/' | sort -u",
            self.dwarf_filename,
            escape_awk_pattern(filename),
        ).splitlines()
        if len(candidates) > 1:
            raise ValueError(
                "ambiguous filename: {}".format(", ".join(candidates))
            )
        if not candidates:
            raise ValueError(f"file not found: {filename}")

        return bash(
            "objdump -WL {} | awk -v RS= '/{}/' | awk '$2 ~ /{}/ && $4 ~ /x/ {{print $3; exit}}'",  # noqa
            self.dwarf_filename,
            escape_awk_pattern(filename),
            lineno,
        )

    def find_address_by_function_name(self, function_name: str) -> str:
        candidates = bash(
            "objdump -t {} | awk '/{}/ {{print $NF}}'",
            self.dwarf_filename,
            escape_awk_pattern(function_name),
        ).splitlines()
        if not candidates:
            raise ValueError(f"function not found: {function_name}")
        if len(candidates) > 1:
            raise ValueError(
                "ambiguous function name: {}".format(", ".join(candidates))
            )

        return '0x' + bash(
            "objdump -t {} | awk '/{}/ {{print $1}}'",
            self.dwarf_filename,
            escape_awk_pattern(function_name),
        )
