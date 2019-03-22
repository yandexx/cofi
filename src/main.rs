use failure::Error;
use log::{error, info};
use rand::{thread_rng, Rng};
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
#[cfg(not(target_os = "windows"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "windows")]
use std::os::windows::prelude::*;
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::thread;
use winapi::um::winbase::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH};

mod converter;
use crate::converter::literal_to_bytes;

fn main() -> Result<(), Error> {
    let cmd_args: Vec<String> = std::env::args().collect();
    println!(
        "cofi -- corruption finder. v{}.\r\n",
        env!("CARGO_PKG_VERSION")
    );
    if cmd_args.len() != 4 {
        println!("Usage: cofi block_size file_size \"path\"");
        println!();
        println!("Example: cofi 1M 100G d:\\testfile.dat");
        return Ok(());
    }

    let log_file_name = format!("cofi-{}.log", chrono::Local::now().format("%Y%m%d-%H%M%S"));
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

    println!(
        "Writing {} blocks of size {} bytes to file \"{}\"",
        blocks_total, block_size, path
    );
    info!(
        "Writing {} blocks of size {} bytes to file \"{}\"",
        blocks_total, block_size, path
    );

    let check_sums_src = Arc::new(Mutex::new(Vec::with_capacity(blocks_total)));
    let check_sums_trg = Arc::new(Mutex::new(Vec::with_capacity(blocks_total)));

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

            let (sender, receiver) = sync_channel(2);
            let check_sums_src2 = check_sums_src.clone();
            let generator_thread = thread::spawn(move || {
                for _ in 0..blocks_total {
                    thread_rng().fill(&mut pre_block[..]);
                    let data_block = pre_block.clone();
                    if data_block != pre_block {
                        error!(
                        "Corruption in memory. Cloned block doesn't match the source. Panicking."
                    );
                        panic!("Corruption in memory. Cloned block doesn't match the source");
                    }
                    let digest = md5::compute(&data_block);
                    check_sums_src2.lock().unwrap().push(digest);
                    sender.send(data_block).unwrap();
                }
            });
            for _ in 0..blocks_total {
                file.write_all(&receiver.recv()?)?;
            }
            generator_thread
                .join()
                .expect("Couldn't join on block generator thread.");
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
                OpenOptions::new().read(true).open(path)
            }

            let mut file = open_file(&path)?;

            print!("R... ");
            io::stdout().flush()?;
            info!("Read enter.");

            let (sender, receiver) = sync_channel(2);
            let check_sums_trg2 = check_sums_trg.clone();
            let summer_thread = thread::spawn(move || {
                for _ in 0..blocks_total {
                    let digest = md5::compute(receiver.recv().expect("Couldn't receive block."));
                    check_sums_trg2.lock().unwrap().push(digest);
                }
            });
            for _ in 0..blocks_total {
                file.read_exact(&mut data_block)?;
                sender.send(data_block.clone())?;
            }
            summer_thread
                .join()
                .expect("Couldn't join on MD5 summer thread.");
            info!("Read exit.");
        }

        let mut corrupted = false;
        {
            let check_sums_src = check_sums_src.lock().unwrap();
            let check_sums_trg = check_sums_trg.lock().unwrap();
            for (i, _) in check_sums_src.iter().enumerate() {
                if *check_sums_src[i] != *check_sums_trg[i] {
                    corrupted = true;
                    println!("MD5 mismatch in block {}!", i);
                    println!(
                        "Original md5: \"{:x}\", current md5: \"{:x}\".",
                        check_sums_src[i], check_sums_trg[i]
                    );
                    error!("MD5 mismatch in block {}!", i);
                    error!(
                        "Original md5: \"{:x}\", current md5: \"{:x}\".",
                        check_sums_src[i], check_sums_trg[i]
                    );
                }
            }
        }
        if corrupted {
            error!("Data got corrupted, panicking.");
            panic!("Data got corrupted.");
        }
        println!("OK.");
        info!("Iteration {} OK", iteration);
        iteration += 1;
        check_sums_src.lock().unwrap().clear();
        check_sums_trg.lock().unwrap().clear();
    }
}
