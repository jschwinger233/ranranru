import os
import signal

from . import signal as sigutils


class Process:
    def __init__(self, path: str, *args: str, **env: str):
        self.path = path
        self.args = list(args)
        self.env = env

        self._pid: int = None

    def spawn(self):
        self.prefork()
        pid = os.fork()
        if pid == 0:
            sigutils.unblock_all()
            self.preexec()
            os.execvpe(self.path, [self.path] + self.args, self.env)

        self._pid = pid
        self.postfork()

    def kill(self, sig: int):
        if not self._pid:
            raise RuntimeError('process is not running')

        os.kill(self._pid, sig)

    def wait(self):
        if not self._pid:
            raise RuntimeError('process is not running')

        os.waitpid(self._pid, 0)

    def proxy_signals(self):
        while True:
            si = signal.sigwaitinfo(sigutils.all_signals())
            if si.si_signo == signal.SIGCHLD and si.si_pid == self._pid:
                self.wait()
                return
            self.kill(si.si_signo)

    @property
    def pid(self) -> int:
        if self._pid:
            return self._pid
        return 0

    def prefork(self):
        return

    def preexec(self):
        return

    def postfork(self):
        return
