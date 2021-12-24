# ranranru Tutorial

This tutorial shows how to use ranranru to trace a real-world application.

It is assumed that ranranru, [gdb](TODO) and [bcc](https://github.com/iovisor/bcc) have been installed successfully. If not, see [install](TODO).

## 1. Setup the demo project

We are going to trace a simple project from the official Go blog, [Go Concurrency Patterns: Pipelines and cancellation](https://go.dev/blog/pipelines), and [here](https://go.dev/blog/pipelines/parallel.go) is the source file to download.

Build the binary using `go build main.go`. I strongly recommend that you upgrade the golang compiler to the latest version, which of not older than 1.18 is preferred because there are some [critical issues](https://github.com/golang/go/issues/49133) not fixed until that release. See [limitation](TODO) for more information.

Run the binary using `./main ..`, and it'll calculate and print md5 of all files under your `..` directory. Here's part of my output:

```
b3bfa8c0b10391131960566c2d5bea86  ../ranranru/program/__pycache__/uprobe.cpython-39.pyc
1e8aa824ba9f499d5347742b1ba971f3  ../ranranru/program/parse.py
46ed17b402efed8340d43db3278f929d  ../ranranru/program/uprobe.py
a9e2a5feda9b82fdf7c9da7f585128d2  ../reverse_python_shell.py
81078a2f036806f19c1b3b3b246e0959  ../setup.cfg
804cbec10f4ed3ff554dd0114233a6bc  ../setup.py
757d08095bdc85080963fddc90712191  ../status.rrr
```

## 2. Observe function arguments

Our first mission is to trace function arguments. We want to log the `path` value once the program executes the anonymous function(it's actually called [function literals](https://go.dev/ref/spec#Function_literals) as per golang spec) passed to `filepath.Walk` :



## 3. Observe function returns

## 4. Observe general variables
