use anyhow::{anyhow, Result};
use clap::{AppSettings, Arg, Command};
use indicatif::ProgressBar;
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
#[cfg(target_os = "windows")]
use winapi::um::winbase::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH};

mod converter;
use crate::converter::literal_to_bytes;

fn main() -> Result<()> {
    let args = setup_clap();

    let log_file_name = format!(
        "cofi_{}.log",
        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
    );
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

    info!(
        "cofi -- corruption finder. v{}. https://github.com/yandexx/cofi",
        env!("CARGO_PKG_VERSION")
    );

    let block_size = literal_to_bytes(args.value_of("blocksize").unwrap())? as usize;
    let file_size = literal_to_bytes(args.value_of("filesize").unwrap())? as usize;
    let blocks_total = if file_size % block_size > 0 {
        file_size / block_size + 1
    } else {
        file_size / block_size
    };
    let path = Arc::new(args.value_of("path").unwrap().to_string());

    let mut threads = vec![];
    let workers_total = args.value_of("threads").unwrap().parse::<u16>();
    if let Err(err) = workers_total {
        return Err(anyhow!(
            "Cannot parse worker count `{}`: {}.",
            args.value_of("threads").unwrap(),
            err
        ));
    }
    let workers_total = workers_total?;

    let use_cache = args.is_present("use-cache");
    if use_cache {
        println!("Using system caching for I/O.");
        info!("Using system caching for I/O.");
    } else {
        println!("Using unbuffered access — no system caching.");
        info!("Using unbuffered access — no system caching.");
    }

    let thread_corrupted = Arc::new(AtomicBool::new(false));
    let io_error = Arc::new(AtomicBool::new(false));

    for t in 0..workers_total {
        let path = Arc::clone(&path);
        let thread_corrupted = thread_corrupted.clone();
        let data_corrupted = Arc::new(AtomicBool::new(false));
        let io_error = io_error.clone();
        let tbuilder = thread::Builder::new().name(format!("{:02}", t));
        let thandle = tbuilder.spawn(move || -> Result<()> {
            let check_sums_src = Arc::new(Mutex::new(Vec::with_capacity(blocks_total)));
            let thread_name = thread::current().name().unwrap().to_string();
            let path: String = update_path(&path, &thread_name);
            println!(
                "[{}] Target: {} blocks of size {} bytes to file \"{}\"",
                thread_name, blocks_total, block_size, path
            );
            info!(
                "[{}] Target: {} blocks of size {} bytes to file \"{}\"",
                thread_name, blocks_total, block_size, path
            );
            let mut iteration = 1;
            loop {
                {
                    let file = create_file(&path, use_cache);
                    if let Err(err) = file {
                        io_error.store(true, Ordering::Relaxed);
                        println!("[{}] Failed to create {}: {:?}", thread_name, path, err);
                        error!("[{}] Failed to create {}: {:?}", thread_name, path, err);
                        return Err(err.into());
                    }
                    let mut file = file.unwrap();

                    info!("[{}] Write enter.", thread_name);
                    println!("[{}] Writing...", thread_name);

                    let (sender, receiver) = crossbeam_channel::bounded(4);

                    let blocks_generated = Arc::new(AtomicUsize::new(0));

                    let mut generator_threads = vec![];
                    for _ in 0..num_cpus::get() {
                        let sender = sender.clone();
                        let blocks_generated = blocks_generated.clone();
                        generator_threads.push(thread::spawn(move || -> Result<()> {
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
                                let digest = blake3::hash(&data_block);
                                if blocks_generated.load(Ordering::SeqCst) < blocks_total {
                                    blocks_generated.fetch_add(1, Ordering::SeqCst);
                                    sender.send((data_block,digest))?;
                                } else {
                                    break Ok(());
                                }
                            }
                        }));
                    }
                    let progressbar = if workers_total == 1 {
                        Some(ProgressBar::new(blocks_total as u64))
                    } else {
                        None
                    };
                    for _ in 0..blocks_total {
                        let (data_block, digest) = receiver.recv()?;
                        if let Err(err) = file.write_all(&data_block) {
                            io_error.store(true, Ordering::Relaxed);
                            println!("[{}] Failed to write block: {:?}", thread_name, err);
                            error!("[{}] Failed to write block: {:?}", thread_name, err);
                            return Err(err.into());
                        };
                        check_sums_src.lock().unwrap().push(digest);
                        if let Some(progress) = progressbar.as_ref() {
                            progress.inc(1);
                        }
                    }
                    for thread in generator_threads {
                        thread
                            .join()
                            .expect("Couldn't join on block generator thread.")?;
                    }
                    info!("[{}] Write exit.", thread_name);
                }

                {
                    let file = open_file(&path, use_cache);
                    if let Err(err) = &file {
                        io_error.store(true, Ordering::Relaxed);
                        println!("[{}] Failed to open {}: {:?}", thread_name, path, err);
                        error!("[{}] Failed to open {}: {:?}", thread_name, path, err);
                    }
                    let mut file = file?;
                    info!("[{}] Read enter.", thread_name);
                    println!("[{}] Reading...", thread_name);

                    use crossbeam_channel::{Sender,Receiver};

                    type SendBlock = (Vec<u8>, usize, blake3::Hash);
                    let (sender, receiver): (Sender<Option<SendBlock>>, Receiver<Option<SendBlock>>) = crossbeam_channel::bounded(4);

                    let mut summer_threads = vec![];
                    for _ in 0..num_cpus::get() {
                        let data_corrupted = data_corrupted.clone();
                        let receiver = receiver.clone();
                        let path = path.clone();
                        let thread_name = thread_name.clone();
                        summer_threads.push(thread::spawn(move || {
                            while let Some((block, i, check_sum_src)) =
                                receiver.recv().expect("Couldn't receive block.")
                            {
                                let digest = blake3::hash(block.as_slice());
                                if check_sum_src != digest {
                                    data_corrupted.store(true, Ordering::Relaxed);
                                    println!("[{}] CRC mismatch in block {} in {}!", thread_name, i, path);
                                    println!(
                                        "[{}] Original hash: \"{:?}\"\ncurrent hash: \"{:?}\".",
                                        thread_name, check_sum_src, digest
                                    );
                                    error!("[{}] CRC mismatch in block {} in {}!", thread_name, i, path);
                                    error!(
                                        "[{}] Original hash: \"{:?}\"\ncurrent hash: \"{:?}\".",
                                        thread_name, check_sum_src, digest
                                    );
                                }
                            }
                        }));
                    }
                    let mut data_block: Vec<u8> = vec![0; block_size];
                    let check_sums_src = check_sums_src.lock().unwrap();
                    let progressbar = if workers_total == 1 {
                        Some(ProgressBar::new(blocks_total as u64))
                    } else {
                        None
                    };
                    for (i, check_sum) in check_sums_src.iter().enumerate().take(blocks_total) {
                        if let Err(err) = file.read_exact(&mut data_block) {
                            io_error.store(true, Ordering::Relaxed);
                            println!("[{}] Failed to read block: {:?}", thread_name, err);
                            error!("[{}] Failed to read block: {:?}", thread_name, err);
                            return Err(err.into());
                        }
                        sender.send(Some((data_block.clone(), i, *check_sum)))?;
                        if let Some(progress) = progressbar.as_ref() {
                            progress.inc(1);
                        }
                    }
                    for _ in 0..summer_threads.len() {
                        sender.send(None)?;
                    }
                    for thread in summer_threads {
                        thread
                            .join()
                            .expect("Couldn't join on a CRC summer thread.");
                    }
                    info!("[{}] Read exit.", thread_name);
                }
                if io_error.load(Ordering::Relaxed) {
                    error!("[{}] I/O error in another thread, exiting.", thread_name);
                    println!("[{}] I/O error in another thread, exiting.", thread_name);
                    return Err(anyhow!("I/O error."));
                }
                if data_corrupted.load(Ordering::Relaxed) {
                    thread_corrupted.store(true, Ordering::Relaxed);
                    error!("[{}] Data got corrupted, exiting.", thread_name);
                    println!("[{}] Data got corrupted, exiting.", thread_name);
                    return Err(anyhow!("Data got corrupted."));
                }
                if thread_corrupted.load(Ordering::Relaxed) {
                    error!("[{}] Data got corrupted in another thread, exiting.", thread_name);
                    println!("[{}] Data got corrupted in another thread, exiting.", thread_name);
                    return Err(anyhow!("Data got corrupted."));
                }

                println!("[{}] Iteration {} OK.", thread_name, iteration);
                info!("[{}] Iteration {} OK.", thread_name, iteration);
                iteration += 1;
                check_sums_src.lock().unwrap().clear();
            }
        })?;
        threads.push(thandle);
    }

    for t in threads {
        let thread_name: String = t.thread().name().unwrap().to_string();
        let join_handle = t.join();
        match join_handle {
            Err(err) => println!("{:?}", err),
            Ok(thread_return) => {
                if let Err(err) = thread_return {
                    println!("[{}] Thread exited with error: {:?}", thread_name, err);
                }
            }
        };
    }

    Ok(())
}

fn setup_clap() -> clap::ArgMatches {
    Command::new("cofi")
        .term_width(0)
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vsevolod Zubarev")
        .about("cofi -- corruption finder.")
        .long_about(
"cofi -- corruption finder. The tool generates random data blocks, calculates BLAKE3 hash for them,
writes blocks to a target file, afterwards reads the data back and compares the hashes. This
procedure repeats forever until stopped manually, or until corruption gets detected.

https://github.com/yandexx/cofi")
        .setting(AppSettings::DeriveDisplayOrder)
        .after_help("EXAMPLE:\r\n    cofi 1M 100G d:\\testfile.dat -t 4")
        .arg(
            Arg::new("blocksize")
                .required(true)
                .takes_value(true)
                .help("Block size of I/O operations. K, M, G and T suffixes are supported."),
        )
        .arg(
            Arg::new("filesize")
                .required(true)
                .takes_value(true)
                .help("Size of the file(s) to create. K, M, G and T suffixes are supported."),
        )
        .arg(
            Arg::new("path")
                .required(true)
                .takes_value(true)
                .help("Path to the file(s) to create."),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .default_value("1")
                .help("The number of concurrent workers. Each worker works with a separate file."),
        )
        .arg(
            Arg::new("use-cache")
                .long("use-cache")
                .help("Use system caching for all I/O operations instead of unbuffered access."),
        )
        .get_matches()
}

fn update_path(path: &str, thread_name: &str) -> String {
    use std::ffi::OsStr;
    use std::path::PathBuf;
    let mut pathbuf = PathBuf::from(path);

    let filename = if pathbuf.is_dir() {
        OsStr::new("testfile.dat")
    } else {
        pathbuf.file_name().unwrap()
    };

    let new_filename = format!("{}-{}", thread_name, filename.to_string_lossy());

    if pathbuf.is_dir() {
        pathbuf.push(new_filename);
    } else {
        pathbuf.set_file_name(new_filename);
    }

    pathbuf.to_string_lossy().to_string()
}

// Windows
#[cfg(target_os = "windows")]
fn create_file(path: &str, use_cache: bool) -> io::Result<std::fs::File> {
    if use_cache {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
            .open(path)
    }
}
#[cfg(target_os = "windows")]
fn open_file(path: &str, use_cache: bool) -> io::Result<std::fs::File> {
    if use_cache {
        OpenOptions::new().read(true).open(path)
    } else {
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_NO_BUFFERING)
            .open(path)
    }
}

// Linux
#[cfg(not(target_os = "windows"))]
fn create_file(path: &str, use_cache: bool) -> io::Result<std::fs::File> {
    if use_cache {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .custom_flags(libc::O_SYNC | libc::O_DSYNC)
            // .custom_flags(libc::O_DIRECT)
            .open(path)
    }
}
#[cfg(not(target_os = "windows"))]
fn open_file(path: &str, use_cache: bool) -> io::Result<std::fs::File> {
    if use_cache {
        OpenOptions::new().read(true).open(path)
    } else {
        OpenOptions::new()
            .read(true)
            // .custom_flags(libc::O_DIRECT)
            .open(path)
    }
}
