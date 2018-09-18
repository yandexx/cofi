#[macro_use]
extern crate error_chain;
extern crate rand; 
extern crate md5;
#[cfg(target_os = "windows")]
extern crate winapi;
#[cfg(not(target_os = "windows"))]
extern crate libc;
#[macro_use]
extern crate log;
extern crate fern; 
extern crate chrono;

mod converter;
use converter::literal_to_bytes; 

use std::io;
use std::io::prelude::*;
use std::fs::OpenOptions;
#[cfg(target_os = "windows")]
use std::os::windows::prelude::*;
#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::OpenOptionsExt;
use rand::{thread_rng, Rng};
use winapi::um::winbase::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        Convert(std::num::ParseIntError);
        Log(log::SetLoggerError); 
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

    let log_file_name = format!("cofi_{}.log", chrono::Local::now().format("%Y%m%d_%H%M%S"));
    println!("Logging to {}\r\n", log_file_name);

    fern::Dispatch::new()
        .format(|out, message, record| {
        out.finish(format_args!(
            "{}[{}][{}] {}",
            chrono::Local::now().format("[%Y-%m-%d %H:%M:%S%.3f]"),
            record.target(),
            record.level(),
            message
        ))
    })
    .level(log::LevelFilter::Debug)
    .chain(fern::log_file(log_file_name)?)
    .apply()?;

    info!("cofi -- corruption finder. v{}.", env!("CARGO_PKG_VERSION"));

    let block_size = literal_to_bytes(&cmd_args[1])? as usize;
    let file_size = literal_to_bytes(&cmd_args[2])? as usize;
    let blocks_total = if file_size % block_size > 0 {
        file_size / block_size + 1
    } else {
        file_size / block_size
    };
    let path = &cmd_args[3];

    println!("Writing {} blocks of size {} bytes to file \"{}\"", blocks_total, block_size, path);
    info!("Writing {} blocks of size {} bytes to file \"{}\"", blocks_total, block_size, path);

    let mut check_sums_src: Vec<md5::Digest> = Vec::with_capacity(blocks_total);    
    let mut check_sums_trg: Vec<md5::Digest> = Vec::with_capacity(blocks_total);    

    let mut iteration = 1;
    loop {
        {
            let mut pre_block: Vec<u8> = vec![0; block_size];

            #[cfg(target_os = "windows")]
            fn open_file(path: &str) -> io::Result<std::fs::File> {
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
                    .open(path)
            }

            #[cfg(not(target_os = "windows"))]
            fn open_file(path: &str) -> io::Result<std::fs::File> {
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .custom_flags(libc::O_SYNC | libc::O_DSYNC)
                    .open(path)
            }           

            let mut file = open_file(&path)?;

            print!("Iteration {}: W... ", iteration);
            io::stdout().flush()?;
            info!("Write enter.");
            
            for _ in 0..blocks_total {
                thread_rng().fill(&mut pre_block[..]);
                let data_block = pre_block.clone();
                if data_block != pre_block {
                    error!("Corruption in memory. Cloned block doesn't match the source. Panicking.");
                    panic!("Corruption in memory. Cloned block doesn't match the source");
                }
                let digest = md5::compute(&data_block);
                check_sums_src.push(digest);

                file.write_all(&data_block)?;
            }
            info!("Write exit.");
        }

        {
            let mut data_block: Vec<u8> = vec![0; block_size];
    
            #[cfg(target_os = "windows")]
            fn open_file(path: &str) -> io::Result<std::fs::File> {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_NO_BUFFERING)
                    .open(path)
            }

            #[cfg(not(target_os = "windows"))]
            fn open_file(path: &str) -> io::Result<std::fs::File> {
                OpenOptions::new()
                    .read(true)
                    .open(path)
            }  

            let mut file = open_file(&path)?;

            print!("R... ");
            io::stdout().flush()?;
            info!("Read enter.");

            for _ in 0..blocks_total {
                file.read_exact(&mut data_block)?;
                let digest = md5::compute(&data_block);
                check_sums_trg.push(digest);
            }
            info!("Read exit.");
        }

        let mut corrupted = false;
        for (i, _) in check_sums_src.iter().enumerate() {
            if *check_sums_src[i] != *check_sums_trg[i] {
                corrupted = true;
                println!("MD5 mismatch in block {}!", i);
                println!("Original md5: \"{:x}\", current md5: \"{:x}\".", check_sums_src[i], check_sums_trg[i]);
                error!("MD5 mismatch in block {}!", i);
                error!("Original md5: \"{:x}\", current md5: \"{:x}\".", check_sums_src[i], check_sums_trg[i]);
            }
        }
        if corrupted {
            error!("Data got corrupted, panicking.");
            panic!("Data got corrupted.");
        }
        println!("OK.");
        info!("Iteration {} OK", iteration);
        iteration += 1;
        check_sums_src.clear();
        check_sums_trg.clear();
    }
}

quick_main!(run);