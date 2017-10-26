#[macro_use]
extern crate error_chain;
extern crate rand; 
extern crate md5;
extern crate winapi;

mod converter;
use converter::literal_to_bytes; 

use std::io;
use std::io::prelude::*;
use std::fs::OpenOptions;
use std::os::windows::prelude::*;
use rand::{thread_rng, Rng};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        Convert(std::num::ParseIntError);
    }
} 

fn run() -> Result<()> {
    let cmd_args: Vec<String> = std::env::args().collect(); 
    println!("cofi -- corruption finder. v{}.\r\n", env!("CARGO_PKG_VERSION"));
    if cmd_args.len() != 4 {
        println!("Usage: cofi block_size file_size \"path\"");
        println!();
        println!("Example: cofi 1M 100G d:\\testfile.dat");
        return Ok(())
    }

    let block_size = literal_to_bytes(&cmd_args[1])? as usize;
    let file_size = literal_to_bytes(&cmd_args[2])? as usize;
    let blocks_total = if file_size % block_size > 0 {
        file_size / block_size + 1
    } else {
        file_size / block_size
    };
    let path = &cmd_args[3];

    println!("Writing {} blocks of size {} bytes to file \"{}\"", blocks_total, block_size, path);

    let mut check_sums_src: Vec<md5::Digest> = Vec::with_capacity(blocks_total);    
    let mut check_sums_trg: Vec<md5::Digest> = Vec::with_capacity(blocks_total);    

    let mut iteration = 1;
    loop {
        {
            let mut pre_block: Vec<u8> = vec![0; block_size];

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .custom_flags(winapi::FILE_FLAG_NO_BUFFERING | winapi::FILE_FLAG_WRITE_THROUGH)
                .open(path)?;

            print!("Iteration {}: W... ", iteration);
            io::stdout().flush()?;
            
            for _ in 0..blocks_total {
                thread_rng().fill_bytes(&mut pre_block);
                let data_block = pre_block.clone();
                if data_block != pre_block {
                    panic!("Corruption in memory. Cloned block doesn't match the source");
                }
                let digest = md5::compute(&data_block);
                check_sums_src.push(digest);

                file.write(&data_block)?;
            }
        }

        {
            let mut data_block: Vec<u8> = vec![0; block_size];
    
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(winapi::FILE_FLAG_NO_BUFFERING)
                .open(path)?;

            print!("R... ");
            io::stdout().flush()?;

            for _ in 0..blocks_total {
                file.read(&mut data_block)?;
                let digest = md5::compute(&data_block);
                check_sums_trg.push(digest);
            }
        }

        for (i, _) in check_sums_src.iter().enumerate() {
            if *check_sums_src[i] != *check_sums_trg[i] {
                println!("MD5 mismatch in block {}!", i);
                println!("Original md5: \"{:x}\", target md5: \"{:x}\".", check_sums_src[i], check_sums_trg[i]);
                panic!("Data got corrupted.");
            }
        }
        println!("OK.");
        iteration += 1;
        check_sums_src.clear();
        check_sums_trg.clear();
    }
}

quick_main!(run);