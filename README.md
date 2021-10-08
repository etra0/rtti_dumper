# rtti_dumper
A very basic Multi-threaded Virtual Function Table Dumper based on RTTIs.

# Usage
It's an CLI tool, so in order to use it you must open a CMD and `cd` into the dir.
```
USAGE:
    rtti_dumper.exe [FLAGS] [OPTIONS] <PROCESS>

FLAGS:
    -h, --help       Prints help information
    -j, --json
    -V, --version    Prints version information

OPTIONS:
    -p, --proc_target <proc_target>    Name of the executable to dump. This is useful if you want to dump a DLL for
                                       example.
    -t, --threads <threads>

ARGS:
    <PROCESS>    Name of the process to dump
```
