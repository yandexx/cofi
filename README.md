## **cofi** — corruption finder

[![Build status](https://ci.appveyor.com/api/projects/status/6778kw234wjcaf9p?svg=true)](https://ci.appveyor.com/project/yandexx/cofi)

This is a simple tool that is designed to determine whether any data gets corrupted during I/O to a file.

It generates random data blocks, calculates md5 for them, writes them to a target file, afterwards reads the data back and compares md5 hashes. This procedure repeats forever until stopped manually, or until corruption gets detected.

The tool was used successfully in a production case to prove that corruption was happening.

* On Windows the WinAPI `FILE_FLAG_NO_BUFFERING` flag is used, to disallow any caching on the OS level, and additionally `FILE_FLAG_WRITE_THROUGH` during the writing stage.
* On Linux: `O_SYNC` and `O_DSYNC` flags during writing.

### Usage

```
USAGE:
    cofi.exe [OPTIONS] <blocksize> <filesize> <path>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -t, --threads <threads>    The number of concurrent workers. Each worker works with a separate file. [default: 1]

ARGS:
    <blocksize>    Block size of I/O operations. K, M, G and T suffixes are supported.
    <filesize>     Size of the file(s) to create. K, M, G and T suffixes are supported.
    <path>         Path to the file(s) to create.
```

### Example

`cofi 1M 100G d:\testfile.dat -t 4`

### Building from source

1. Install Rust https://www.rust-lang.org/
2. Run `cargo build --release` in the project folder.
