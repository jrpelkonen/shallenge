use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::available_parallelism;
use std::time::{Duration, SystemTime};
use std::{env, io, thread};

fn main() {
    let num_cpus = available_parallelism().unwrap().get();
    let prefix = env::args().nth(1).unwrap_or("/dummyprefix/".to_string());
    let base64_alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();
    let lowest_hash_prefix = AtomicU64::new(u64::MAX);
    static HASH_BATCH_COUNT: AtomicUsize = AtomicUsize::new(0);
    const HASH_BATCH_SIZE: usize = 0x0ffffff;
    let finished_tuple = Arc::new((Mutex::new(false), Condvar::new()));
    let finished_tuple_main = Arc::clone(&finished_tuple);

    thread::spawn(move || {
        let started = SystemTime::now();
        let (lock, cvar) = &*finished_tuple;
        let mut finished = lock.lock().unwrap();
        loop {
            let result = cvar
                .wait_timeout(finished, Duration::from_secs(300))
                .unwrap();

            finished = result.0;
            if *finished {
                break;
            }
            let num_hashes_computed = HASH_BATCH_COUNT.load(Ordering::Relaxed) * HASH_BATCH_SIZE;
            eprintln!(
                "{} hashes computed, {}/s",
                num_hashes_computed,
                num_hashes_computed
                    / SystemTime::now().duration_since(started).unwrap().as_secs() as usize
            );
        }
    });
    base64_alphabet[0..num_cpus]
        .par_iter()
        .for_each(|thread_prefix| {
            let mut buf = Vec::with_capacity(32);
            buf.extend_from_slice(prefix.as_bytes());
            buf.push(*thread_prefix);
            let to_skip = buf.len();
            let mut hasher = Sha256::new();
            let mut hash_buf = Sha256::digest([]);
            let mut lowest_hash_prefix_local = lowest_hash_prefix.load(Ordering::Relaxed);
            for i in 0..usize::MAX {
                let mut mut_i = i;
                // if divisible by 64, extend buffer
                if i.count_ones() == i.trailing_ones() && i.trailing_ones() % 6 == 0 {
                    buf.resize(buf.len() + 1, 0);
                    mut_i = 0;
                }
                for c in buf.iter_mut().skip(to_skip) {
                    *c = base64_alphabet[mut_i & 0x3f];
                    mut_i >>= 6;
                }
                hasher.update(&buf);
                hasher.finalize_into_reset(&mut hash_buf);
                let hash_prefix = u64::from_be_bytes(hash_buf[0..8].try_into().unwrap());
                while hash_prefix < lowest_hash_prefix_local {
                    let retry = match lowest_hash_prefix.compare_exchange(
                        lowest_hash_prefix_local,
                        hash_prefix,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => false,
                        Err(l) => {
                            lowest_hash_prefix_local = l;
                            true
                        }
                    };
                    if !retry {
                        let mut lock = io::stdout().lock();
                        print!(
                            "{:?}: input:",
                            SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                        );
                        let _ = lock.write_all(&buf);
                        println!(
                            ", zero digits: {}, hash: {}",
                            hash_prefix.leading_zeros() / 4,
                            hex::encode(hash_buf)
                        );
                        break;
                    }
                }
                if i & HASH_BATCH_SIZE == HASH_BATCH_SIZE {
                    HASH_BATCH_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            }
            println!("{} all hashes computed", *thread_prefix as char);
        });
    let (lock, cvar) = &*finished_tuple_main;
    let mut finished = lock.lock().unwrap();
    *finished = true;
    cvar.notify_one();
}
