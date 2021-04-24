import os
import shutil
import ctypes
import ctypes.util

from .utils import process as procutils


class Process(procutils.Process):
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

    @classmethod
    def from_pathname(cls, debug_pathname: str):
        return cls(debug_pathname)

    def __init__(self, *args, **kws):
        super().__init__(*args, **kws)

        self._bcc_sym_pathname: str = None

    def preexec(self):
        self.libc.ptrace(0, 0, None, None)

    def wait(self):
        super().wait()
        if self._bcc_sym_pathname:
            os.remove(self._bcc_sym_pathname)

    def setup_bcc_symfs(self, tracee_pathname: str):
        bcc_symfs = '/tmp'
        self._bcc_sym_pathname = os.path.join(bcc_symfs,
                                              tracee_pathname.lstrip('/'))
        os.makedirs(os.path.dirname(self._bcc_sym_pathname), exist_ok=True)
        shutil.copyfile(self.path,
                        self._bcc_sym_pathname,
                        follow_symlinks=True)
