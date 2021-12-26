# Install ranranru

## Package

```bash
python3 -mpip install ranranru
```

Please use CPython>=3.9 to install.

## Dependence

1. [objdump(1)](https://linux.die.net/man/1/objdump) is required to be newer than v2.37, this is because older versions have some defects in dealing with `DW_CFA_def_cfa_offset_sf`. If no package availble from the official respository, I recommand you build from source: `git clone git://sourceware.org/git/binutils-gdb.git`.
2. [bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md) is NOT required to run ranranru.
