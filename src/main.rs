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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

    let mut iteration = 1;
    loop {
        {
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

            let (sender, receiver) = crossbeam_channel::bounded(4);

            let blocks_generated = Arc::new(AtomicUsize::new(0));

            let mut generator_threads = vec![];
            for _ in 0..num_cpus::get() {
                let sender = sender.clone();
                let blocks_generated = blocks_generated.clone();
                generator_threads.push(thread::spawn(move || {
                    let mut pre_block: Vec<u8> = vec![0; block_size];
                    loop {
                        thread_rng().fill(&mut pre_block[..]);
                        let data_block = pre_block.clone();
                        if data_block != pre_block {
                            error!(
                                "Corruption in memory. Cloned block doesn't match the source. Panicking."
                            );
                            panic!("Corruption in memory. Cloned block doesn't match the source.");
                        }
                        let digest = md5::compute(&data_block);
                        if blocks_generated.load(Ordering::SeqCst) < blocks_total {
                            blocks_generated.fetch_add(1, Ordering::SeqCst);
                            sender.send((data_block,digest)).unwrap();
                        } else {
                            break;
                        }
                    }
                }));
            }
            for _ in 0..blocks_total {
                let (data_block, digest) = receiver.recv()?;
                file.write_all(&data_block)?;
                check_sums_src.lock().unwrap().push(digest);
            }
            for thread in generator_threads {
                thread
                    .join()
                    .expect("Couldn't join on block generator thread.");
            }
            info!("Write exit.");
        }

        let corrupted = Arc::new(AtomicBool::new(false));
        {
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

            let (sender, receiver) = crossbeam_channel::bounded(4);

            let mut summer_threads = vec![];
            for _ in 0..num_cpus::get() {
                let corrupted = corrupted.clone();
                let receiver = receiver.clone();
                summer_threads.push(thread::spawn(move || loop {
                    if let Some((block, i, check_sum_src)) =
                        receiver.recv().expect("Couldn't receive block.")
                    {
                        let digest = md5::compute(block);
                        if check_sum_src != digest {
                            corrupted.store(true, Ordering::Relaxed);
                            println!("MD5 mismatch in block {}!", i);
                            println!(
                                "Original md5: \"{:x}\", current md5: \"{:x}\".",
                                check_sum_src, digest
                            );
                            error!("MD5 mismatch in block {}!", i);
                            error!(
                                "Original md5: \"{:x}\", current md5: \"{:x}\".",
                                check_sum_src, digest
                            );
                        }
                    } else {
                        break;
                    }
                }));
            }
            let mut data_block: Vec<u8> = vec![0; block_size];
            let check_sums_src = check_sums_src.lock().unwrap();
            for i in 0..blocks_total {
                file.read_exact(&mut data_block)?;
                sender.send(Some((data_block.clone(), i, check_sums_src[i])))?;
            }
            for _ in 0..summer_threads.len() {
                sender.send(None).unwrap();
            }
            for thread in summer_threads {
                thread
                    .join()
                    .expect("Couldn't join on a MD5 summer thread.");
            }
            info!("Read exit.");
        }

        if corrupted.load(Ordering::Relaxed) {
            error!("Data got corrupted, panicking.");
            panic!("Data got corrupted.");
        }
        println!("OK.");
        info!("Iteration {} OK.", iteration);
        iteration += 1;
        check_sums_src.lock().unwrap().clear();
    }
}
