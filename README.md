## **cofi** — corruption finder

[![Build status](https://ci.appveyor.com/api/projects/status/6778kw234wjcaf9p?svg=true)](https://ci.appveyor.com/project/yandexx/cofi)

This is a simple tool that is designed to determine whether any data gets corrupted during I/O to a file.

It generates random data blocks, calculates blake3 hashes for them, writes blocks to a target file, afterwards reads the data back and compares the hashes. This procedure repeats forever until stopped manually, or until corruption gets detected.

The tool was used successfully in many production cases to prove that corruption was happening.

* On Windows the WinAPI `FILE_FLAG_NO_BUFFERING` flag is used, to disallow any caching on the OS level, and additionally `FILE_FLAG_WRITE_THROUGH` during the writing stage.
* On Linux: `O_SYNC` and `O_DSYNC` flags during writing.

### Usage

```
USAGE:
    cofi [OPTIONS] <blocksize> <filesize> <path>

ARGS:
    <blocksize>
            Block size of I/O operations. K, M, G and T suffixes are supported.

    <filesize>
            Size of the file(s) to create. K, M, G and T suffixes are supported.

    <path>
            Path to the file(s) to create.

OPTIONS:
    -t, --threads <threads>
            The number of concurrent workers. Each worker works with a separate file.
            
            [default: 1]

    -s, --sleep <sleep>
            The amount of time a worker should wait before verifying new file. Can be useful for cases where storage system has hot and cold tiers.
            
            [default: 0]

        --use-cache
            Use system caching for all I/O operations instead of unbuffered access.

    -h, --help
            Print help information

    -V, --version
            Print version information
```

### Example

`cofi 1M 100G d:\testfile.dat -t 4`

### Building from source

1. Install Rust https://www.rust-lang.org/
2. Run `cargo build --release` in the project folder.
