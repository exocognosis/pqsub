//! `pqsub-verify` — independent third-party verifier.
//!
//! ```text
//! pqsub-verify transcript --root ROOT.pub FILE [--from N] [--anchor genesis|none|HEX] [--expect-head HEX]
//! pqsub-verify vectors FILE.json
//! ```
//! Exit status: 0 valid, 2 invalid, 1 usage / I/O error.
#![forbid(unsafe_code)]

use std::process::exit;

use pqsub_verify::{parse_anchor, parse_h32, parse_root, vectors, verify_transcript, Anchor};

fn usage() -> ! {
    eprintln!(
        "usage:\n  pqsub-verify transcript --root ROOT.pub FILE [--from N] [--anchor genesis|none|HEX] [--expect-head HEX]\n  pqsub-verify vectors FILE.json"
    );
    exit(1)
}

fn read(p: &str) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| {
        eprintln!("error: reading {p}: {e}");
        exit(1)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("vectors") => {
            let Some(p) = args.get(1) else { usage() };
            let json = String::from_utf8(read(p)).unwrap_or_else(|_| usage());
            match vectors::run(&json) {
                Ok(s) if s.failures.is_empty() => println!(
                    "ALL VECTORS PASS ({} checks, independent fips204 implementation)",
                    s.passed
                ),
                Ok(s) => {
                    for f in &s.failures {
                        eprintln!("FAIL {f}");
                    }
                    eprintln!("{} passed, {} failed", s.passed, s.failures.len());
                    exit(2);
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    exit(1);
                }
            }
        }
        Some("transcript") => {
            let (mut root, mut file, mut from, mut anchor, mut head) =
                (None, None, 0usize, None, None);
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                let mut val = || it.next().cloned().unwrap_or_else(|| usage());
                match a.as_str() {
                    "--root" => root = Some(val()),
                    "--from" => from = val().parse().unwrap_or_else(|_| usage()),
                    "--anchor" => anchor = Some(val()),
                    "--expect-head" => head = Some(val()),
                    s if !s.starts_with("--") && file.is_none() => file = Some(s.to_string()),
                    _ => usage(),
                }
            }
            let (Some(root), Some(file)) = (root, file) else {
                usage()
            };
            let result = (|| {
                let root = parse_root(&read(&root))?;
                let anchor = match anchor.as_deref() {
                    Some(a) => parse_anchor(a)?,
                    None if from == 0 => Anchor::Genesis,
                    None => Anchor::None,
                };
                let head = head.as_deref().map(parse_h32).transpose()?;
                verify_transcript(&root, &read(&file), from, anchor, head)
            })();
            match result {
                Ok(r) => {
                    for (i, (h, n)) in r.entry_hashes.iter().zip(&r.sender_names).enumerate() {
                        println!("#{:<3} ok  {:<13} {}", from + i, n, hex::encode(h));
                    }
                    println!(
                        "VALID  {} entries  anchored={}  head={}",
                        r.entry_hashes.len(),
                        r.anchored,
                        hex::encode(r.head)
                    );
                }
                Err(f) => {
                    eprintln!("INVALID [{}] {}", f.code, f.detail);
                    exit(2);
                }
            }
        }
        _ => usage(),
    }
}
