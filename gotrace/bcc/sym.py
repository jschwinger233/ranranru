import os
import shutil
import ctypes
import contextlib
import ctypes.util

from gotrace.utils import process as procutils


class Process(procutils.Process):
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

    @classmethod
    def from_pathname(cls, sym_pathname: str):
        self = cls(sym_pathname)
        self._bcc_sym_pathname: str = None
        return self

    def preexec(self):
        self.libc.ptrace(0, 0, None, None)

    def wait(self):
        super().wait()

    def setup_bcc_symfs(self, tracee_pathname: str):
        bcc_symfs = '/tmp'
        self._bcc_sym_pathname = os.path.join(bcc_symfs,
                                              tracee_pathname.lstrip('/'))
        os.makedirs(os.path.dirname(self._bcc_sym_pathname), exist_ok=True)
        shutil.copyfile(self.path,
                        self._bcc_sym_pathname,
                        follow_symlinks=True)

    def wipeout_bcc_symfs(self):
        with contextlib.suppress(Exception):
            os.remove(self._bcc_sym_pathname)
