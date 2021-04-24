import re
import typing
import signal

SIG_PAT = re.compile(r'SIG[A-Z]+')


def all_signals() -> typing.List[int]:
    # this is shit, I'd rather use ctypes.sigfillset(3)
    return [
        getattr(signal, attr) for attr in dir(signal) if SIG_PAT.match(attr)
    ]


def block_all():
    signal.pthread_sigmask(signal.SIG_BLOCK, all_signals())


def unblock_all():
    signal.pthread_sigmask(signal.SIG_UNBLOCK, all_signals())
