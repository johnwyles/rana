use colored::Colorize;
use std::cmp::max;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use regex::Regex;
use nostr::bip39::Mnemonic;
use nostr::prelude::*;
use rana::cli::*;
use rana::mnemonic::handle_mnemonic;
use rana::utils::{benchmark_cores, get_leading_zero_bits, print_divider, print_keys, print_qr};

const DIFFICULTY_DEFAULT: u8 = 10;
// const BECH32_PREFIX: &str = "npub1";

fn main() -> Result<()> {
    // Parse CLI arguments
    let parsed_args = CLIArgs::parse();

    // Handle mnemonic part if arguments is set
    if !parsed_args.mnemonic.is_empty() {
        handle_mnemonic(&parsed_args);
    }

    let mut difficulty: u8 = parsed_args.difficulty;
    let vanity_hex: String = parsed_args.vanity_hex;
    let mut vanity_npub_regexes: Vec<String> = Vec::new();
    let num_cores: usize = parsed_args.num_cores;
    let qr: bool = parsed_args.qr;
    let verbose_output: bool = parsed_args.verbose_output;

    for vanity_npub_reg in parsed_args.vanity_npub_regexes_raw_input.split(',') {
        if !vanity_npub_reg.is_empty() {
            vanity_npub_regexes.push(vanity_npub_reg.to_string())
        }
    }

    //-- Calculate pow difficulty and initialize
    check_args(
        difficulty,
        vanity_hex.as_str(),
        &vanity_npub_regexes,
        num_cores,
    );

    difficulty = DIFFICULTY_DEFAULT;

    println!("Started mining process with a difficulty of: {difficulty}");

    // Benchmarking of cores is using the defaulse difficulty because we have
    // disabled running calculations for all vanity searches. This has been done
    // because we are unable to form a proper calculation from an unknown user-
    // supplied regex.
    benchmark_cores(num_cores, difficulty);

    // Loop: generate public keys until desired public key is reached
    let now = Instant::now();

    println!("Mining using {num_cores} cores...");

    // thread safe variables
    let best_diff = Arc::new(AtomicU8::new(difficulty));
    let vanity_ts = Arc::new(vanity_hex);
    let vanity_npubs_reg_ts = Arc::new(vanity_npub_regexes);
    let iterations = Arc::new(AtomicU64::new(0));

    // start a thread for each core for calculations
    for _ in 0..num_cores {
        let best_diff = best_diff.clone();
        let vanity_ts = vanity_ts.clone();
        let vanity_npubs_reg_ts = vanity_npubs_reg_ts.clone();
        let passphrase = Arc::new(parsed_args.mnemonic_passphrase.clone());
        let iterations = iterations.clone();

        thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut keys;
            let mut mnemonic;

            loop {
                let mut uses_mnemonic: Option<Mnemonic> = None;
                iterations.fetch_add(1, Ordering::Relaxed);

                // Use mnemonics to generate key pair
                if parsed_args.word_count > 0 {
                    mnemonic = Keys::generate_mnemonic(parsed_args.word_count)
                        .expect("Couldn't not generate mnemonic");

                    keys = Keys::from_mnemonic(mnemonic.to_string(), Some(passphrase.to_string()))
                        .expect("Error generating keys from mnemonic");
                    uses_mnemonic = Some(mnemonic);
                } else {
                    keys = Keys::generate_without_keypair(&mut rng);
                }

                let mut leading_zeroes: u8 = 0;
                let mut vanity_npub: String = String::new();

                // check pubkey validity depending on arg settings
                let mut is_valid_pubkey: bool = false;

                if !vanity_ts.is_empty() {
                    // hex vanity search
                    is_valid_pubkey = Regex::new(
                        vanity_ts.as_str()
                    ).unwrap().is_match(
                        &keys.public_key().to_string()
                    );
                } else if !vanity_npubs_reg_ts.is_empty()  {
                    // bech32 vanity search
                    let bech_key: String = keys.public_key().to_bech32().unwrap();

                    if !vanity_npubs_reg_ts.is_empty() {
                        for cur_vanity_npub in vanity_npubs_reg_ts.iter() {
                            is_valid_pubkey = Regex::new(
                                cur_vanity_npub
                            ).unwrap().is_match(
                                &bech_key
                            );
                            
                            if is_valid_pubkey {
                                vanity_npub = cur_vanity_npub.clone();
                                break;
                            }
                        }
                    }
                } else {
                    // difficulty search
                    leading_zeroes = get_leading_zero_bits(&keys.public_key().serialize());
                    is_valid_pubkey = leading_zeroes > best_diff.load(Ordering::Relaxed);
                    if is_valid_pubkey {
                        // update difficulty only if it was set in the first place
                        if best_diff.load(Ordering::Relaxed) > 0 {
                            best_diff
                                .fetch_update(
                                    Ordering::Relaxed,
                                    Ordering::Relaxed,
                                    |_| {Some(leading_zeroes)
                                })
                                .unwrap();
                        }
                    }
                }

                // if one of the required conditions is satisfied
                let shared_output = Arc::new(Mutex::new(std::io::stdout()));
                if is_valid_pubkey {
                    let _guard = shared_output.lock().unwrap();
                    std::io::Write::flush(&mut std::io::stdout()).expect("Failed to flush stdout");
                    println!("{}", print_divider(30).bright_cyan());
                    print_keys(&keys, vanity_npub, leading_zeroes, uses_mnemonic).unwrap();
                    let iterations = iterations.load(Ordering::Relaxed);
                    let iter_string = format!("{iterations}");
                    let l = iter_string.len();
                    let f = iter_string.chars().next().unwrap();
                    println!(
                        "{} iterations (about {}x10^{} hashes) in {} seconds. Avg rate {} hashes/second",
                        iterations,
                        f,
                        l - 1,
                        now.elapsed().as_secs(),
                        iterations / max(1, now.elapsed().as_secs())
                    );
                    if qr {
                        print_qr(keys.secret_key().unwrap()).unwrap();
                    }
                    std::io::Write::flush(&mut std::io::stdout()).expect("Failed to flush stdout");
                } else if verbose_output {
                    let non_matching_key = keys.public_key().to_string();
                    print!("Non-matching public key generated: {}\r", non_matching_key.red());
                    std::io::Write::flush(&mut std::io::stdout()).expect("Failed to flush stdout");
                }
            }
        });
    }

    // put main thread to sleep
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
