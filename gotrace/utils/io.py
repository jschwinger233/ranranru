import os
import typing
import contextlib


@contextlib.contextmanager
def redirect(mapping: typing.Dict[int, str]):
    reserved = {}
    for fd in mapping:
        reserved[fd] = os.dup(fd)

    try:
        for fd, dest in mapping.items():
            with open(dest, 'w+') as f:
                os.dup2(f.fileno(), fd)

        yield

    finally:
        for fd, rfd in reserved.items():
            os.dup2(rfd, fd)
