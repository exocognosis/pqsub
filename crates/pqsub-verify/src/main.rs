//! `pqsub-verify` — independent third-party verifier.
//!
//! ```text
//! pqsub-verify transcript --root ROOT.pub FILE [--from N] [--anchor genesis|none|HEX] [--expect-head HEX]
//! pqsub-verify audit --root ROOT.pub FILE [--from N] [--anchor genesis|none|HEX] [--expect-head HEX] [--require-authorized]
//! pqsub-verify vectors FILE.json
//! pqsub-verify vectors-v2 FILE.json
//! ```
//! Exit status: 0 valid, 2 invalid (or unauthorized with `--require-authorized`), 1 usage / I/O error.
#![forbid(unsafe_code)]

use std::process::exit;

use pqsub_verify::vectors::Summary;
use pqsub_verify::{
    audit_transcript, parse_anchor, parse_h32, parse_root, vectors, vectors_v2, verify_transcript,
    Anchor, Failure,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  pqsub-verify transcript --root ROOT.pub FILE [--from N] [--anchor genesis|none|HEX] [--expect-head HEX]\n  pqsub-verify audit --root ROOT.pub FILE [--from N] [--anchor genesis|none|HEX] [--expect-head HEX] [--require-authorized]\n  pqsub-verify vectors FILE.json\n  pqsub-verify vectors-v2 FILE.json"
    );
    exit(1)
}

fn read(p: &str) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| {
        eprintln!("error: reading {p}: {e}");
        exit(1)
    })
}

struct Opts {
    root: String,
    file: String,
    from: usize,
    anchor: Option<String>,
    head: Option<String>,
    require_authorized: bool,
}

fn opts(args: &[String], allow_require: bool) -> Opts {
    let (mut root, mut file, mut from, mut anchor, mut head, mut req) =
        (None, None, 0usize, None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| usage());
        match a.as_str() {
            "--root" => root = Some(val()),
            "--from" => from = val().parse().unwrap_or_else(|_| usage()),
            "--anchor" => anchor = Some(val()),
            "--expect-head" => head = Some(val()),
            "--require-authorized" if allow_require => req = true,
            s if !s.starts_with("--") && file.is_none() => file = Some(s.to_string()),
            _ => usage(),
        }
    }
    let (Some(root), Some(file)) = (root, file) else {
        usage()
    };
    Opts {
        root,
        file,
        from,
        anchor,
        head,
        require_authorized: req,
    }
}

type Inputs = (Vec<u8>, Anchor, Option<[u8; 32]>);

fn inputs(o: &Opts) -> Result<Inputs, Failure> {
    let root = parse_root(&read(&o.root))?;
    let anchor = match o.anchor.as_deref() {
        Some(a) => parse_anchor(a)?,
        None if o.from == 0 => Anchor::Genesis,
        None => Anchor::None,
    };
    let head = o.head.as_deref().map(parse_h32).transpose()?;
    Ok((root, anchor, head))
}

fn report_vectors(r: Result<Summary, String>) {
    match r {
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(cmd @ ("vectors" | "vectors-v2")) => {
            let Some(p) = args.get(1) else { usage() };
            let json = String::from_utf8(read(p)).unwrap_or_else(|_| usage());
            report_vectors(if cmd == "vectors" {
                vectors::run(&json)
            } else {
                vectors_v2::run(&json)
            });
        }
        Some("transcript") => {
            let o = opts(&args[1..], false);
            let from = o.from;
            let result = inputs(&o).and_then(|(root, anchor, head)| {
                verify_transcript(&root, &read(&o.file), from, anchor, head)
            });
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
        Some("audit") => {
            let o = opts(&args[1..], true);
            let from = o.from;
            let result = inputs(&o).and_then(|(root, anchor, head)| {
                audit_transcript(&root, &read(&o.file), from, anchor, head)
            });
            match result {
                Ok(a) => {
                    for f in &a.findings {
                        let extra = if f.code == "BLOCKED" {
                            format!("  justified={}", f.justified)
                        } else {
                            String::new()
                        };
                        println!(
                            "{:<22} entry #{:<3} call #{:<3} reason={}{}",
                            f.code,
                            from + f.index,
                            from + f.call_index,
                            f.reason,
                            extra
                        );
                    }
                    let r = &a.report;
                    println!(
                        "VALID  {} entries  anchored={}  head={}  findings={}",
                        r.entry_hashes.len(),
                        r.anchored,
                        hex::encode(r.head),
                        a.findings.len()
                    );
                    if a.all_authorized() {
                        println!("PROVED every executed call was authorized at execution time");
                    } else {
                        println!("NOT PROVED: an executed call was unauthorized");
                        if o.require_authorized {
                            exit(2);
                        }
                    }
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
