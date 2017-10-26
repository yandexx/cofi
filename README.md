## **cofi** — corruption finder

This is a simple tool that is designed to determine whether any data gets corrupted during I/O to a file.

It generates random data blocks, calculates md5 for them, writes them to a target file, afterwards reads the data back and compares md5 hashes. This procedure repeats forever until stopped manually, or until corruption was detected.

The tool was used successfully in a production case to prove that corruption was happening.

Windows only at the moment, as it uses the WinAPI `FILE_FLAG_NO_BUFFERING` flag to disallow any caching on the OS level, and additionally `FILE_FLAG_WRITE_THROUGH` during the writing stage.

### Usage

`cofi block_size file_size "path"`

Where **block_size** is the size of one I/O operation, and **file_size** is the target file size, to be created on **path** (which gets overwritten without notice). This is for a single iteration, which then gets repeated.

You can use **K**, **M**, **G** and **T** suffixes for convenience with **block_size** and **file_size**.

### Example

`cofi 1M 100G d:\testfile.dat`

### Building from source

1. Install Rust https://www.rust-lang.org/en-US/
2. Run `cargo build --release` in the project folder.