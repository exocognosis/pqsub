//! v2 differential tests: pqsub-core vs the independent verifier must produce
//! identical outcomes (error code, or the exact findings list) on mutated inputs.

use pqsub_core::{audit, PublicKey, Transcript, VerifyOptions};
use pqsub_verify::{audit_transcript, caveat_eval, cjson_valid, Anchor as VAnchor};
use serde_json::Value;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn vectors() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/vectors-v2.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn main_case(v: &Value) -> (Vec<u8>, Vec<u8>) {
    let root = hex::decode(v["root_pk"].as_str().unwrap()).unwrap();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "main_full")
        .unwrap();
    (
        root,
        hex::decode(case["transcript"].as_str().unwrap()).unwrap(),
    )
}

fn core_sig(root: &PublicKey, t: &[u8]) -> String {
    match Transcript::decode(t).and_then(|t| audit(root, &t, 0, &VerifyOptions::default())) {
        Ok(r) => format!(
            "OK {:?}",
            r.findings
                .iter()
                .map(|f| (f.code, f.index, f.call_index, f.reason, f.justified))
                .collect::<Vec<_>>()
        ),
        Err(e) => e.code().to_string(),
    }
}

fn indep_sig(root: &[u8], t: &[u8]) -> String {
    match audit_transcript(root, t, 0, VAnchor::Genesis, None) {
        Ok(r) => format!(
            "OK {:?}",
            r.findings
                .iter()
                .map(|f| (f.code, f.index, f.call_index, f.reason, f.justified))
                .collect::<Vec<_>>()
        ),
        Err(f) => f.code.to_string(),
    }
}

/// Byte range of the n-th grant's body (excluding its signature) inside a v2 transcript.
fn grant_body_range(t: &[u8], n: usize) -> std::ops::Range<usize> {
    let rd = |p: usize, k: usize| {
        t[p..p + k]
            .iter()
            .fold(0usize, |a, &b| (a << 8) | b as usize)
    };
    let mut p = 5;
    let n_ids = rd(p, 2);
    p += 2;
    for _ in 0..n_ids {
        p += 4 + rd(p, 4);
    }
    p += 2;
    for _ in 0..n {
        p += 4 + rd(p, 4);
    }
    let len = rd(p, 4);
    (p + 4)..(p + 4 + len - pqsub_core::SIGNATURE_LEN)
}

#[test]
fn every_bit_of_a_grant_body_audits_identically() {
    let v = vectors();
    let (root_b, t) = main_case(&v);
    let root = PublicKey::from_bytes(&root_b).unwrap();
    let base = core_sig(&root, &t);
    assert_eq!(base, indep_sig(&root_b, &t));
    let mut seen = std::collections::BTreeMap::new();
    for byte in grant_body_range(&t, 1) {
        for bit in 0..8 {
            let mut x = t.clone();
            x[byte] ^= 1 << bit;
            let (a, b) = (core_sig(&root, &x), indep_sig(&root_b, &x));
            assert_eq!(a, b, "byte {byte} bit {bit}");
            assert_ne!(
                a, base,
                "byte {byte} bit {bit}: flip in g1 body went unnoticed"
            );
            *seen
                .entry(
                    a.split(' ').next().unwrap_or("").to_string()
                        + if a.contains("\"EXECUTED_UNAUTHORIZED\"") {
                            "+EU"
                        } else {
                            ""
                        },
                )
                .or_insert(0) += 1;
        }
    }
    eprintln!("g1-body flip outcomes: {seen:?}");
}

#[test]
fn strided_bit_flips_and_mutations_agree() {
    let v = vectors();
    let (root_b, t) = main_case(&v);
    let root = PublicKey::from_bytes(&root_b).unwrap();
    for bit in (0..t.len() * 8).step_by(131) {
        let mut x = t.clone();
        x[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(core_sig(&root, &x), indep_sig(&root_b, &x), "bit {bit}");
    }
    let mut rng = Rng(11);
    for i in 0..300 {
        let mut x = t.clone();
        match i % 4 {
            0 => {
                let p = rng.below(x.len());
                x[p] = rng.next() as u8;
            }
            1 => x.truncate(rng.below(x.len())),
            2 => {
                let p = rng.below(x.len());
                x.insert(p, rng.next() as u8);
            }
            _ => {
                let p = rng.below(x.len());
                x.remove(p);
            }
        }
        assert_eq!(core_sig(&root, &x), indep_sig(&root_b, &x), "mutation {i}");
    }
}

#[test]
fn every_audit_vector_window_agrees_on_all_from_values() {
    let v = vectors();
    let default_root = hex::decode(v["root_pk"].as_str().unwrap()).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let t = hex::decode(c["transcript"].as_str().unwrap()).unwrap();
        let root_b = c["root_pk"]
            .as_str()
            .map_or(default_root.clone(), |h| hex::decode(h).unwrap());
        let root = PublicKey::from_bytes(&root_b).unwrap();
        let n = Transcript::decode(&t).map_or(0, |t| t.entries.len());
        for from in 0..=n + 1 {
            let a = match Transcript::decode(&t).and_then(|tr| {
                audit(
                    &root,
                    &tr,
                    from,
                    &VerifyOptions {
                        anchor: pqsub_core::Anchor::Unanchored,
                        expected_head: None,
                    },
                )
            }) {
                Ok(r) => format!(
                    "OK {:?}",
                    r.findings
                        .iter()
                        .map(|f| (f.code, f.index, f.call_index, f.reason, f.justified))
                        .collect::<Vec<_>>()
                ),
                Err(e) => e.code().to_string(),
            };
            let b = match audit_transcript(&root_b, &t, from, VAnchor::None, None) {
                Ok(r) => format!(
                    "OK {:?}",
                    r.findings
                        .iter()
                        .map(|f| (f.code, f.index, f.call_index, f.reason, f.justified))
                        .collect::<Vec<_>>()
                ),
                Err(f) => f.code.to_string(),
            };
            assert_eq!(a, b, "case {} from {from}", c["name"]);
        }
    }
}

#[test]
fn cjson_differential_fuzz() {
    let v = vectors();
    let seeds: Vec<Vec<u8>> = v["cjson"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| hex::decode(c["input"].as_str().unwrap()).unwrap())
        .collect();
    let alphabet = b"{}[]\",:\\/ -0123456789eE.tfnulrasbu\x00\x1f\x7f\xc3\xa9\xf0\x9f\x98\x80";
    let mut rng = Rng(5);
    let mut accepted = 0;
    for i in 0..60_000 {
        let mut x = seeds[rng.below(seeds.len())].clone();
        for _ in 0..1 + rng.below(3) {
            let c = alphabet[rng.below(alphabet.len())];
            match rng.below(3) {
                0 if !x.is_empty() => {
                    let p = rng.below(x.len());
                    x[p] = c;
                }
                1 => {
                    let p = rng.below(x.len() + 1);
                    x.insert(p, c);
                }
                _ if !x.is_empty() => {
                    let p = rng.below(x.len());
                    x.remove(p);
                }
                _ => {}
            }
        }
        for object in [true, false] {
            let a = pqsub_core::cjson::parse_canonical(&x, object).is_ok();
            let b = cjson_valid(&x, object);
            assert_eq!(
                a,
                b,
                "iter {i} object={object} input={:?}",
                String::from_utf8_lossy(&x)
            );
            accepted += usize::from(a);
        }
    }
    eprintln!("cjson fuzz: {accepted} acceptances out of 120000 checks");
}

#[test]
fn caveat_differential_fuzz() {
    let v = vectors();
    let rows = v["caveats"].as_array().unwrap();
    let mut rng = Rng(9);
    for i in 0..20_000 {
        let r = &rows[rng.below(rows.len())];
        let mut cav = hex::decode(r["caveat"].as_str().unwrap()).unwrap();
        let mut args = hex::decode(r["args"].as_str().unwrap()).unwrap();
        let target = if rng.below(2) == 0 {
            &mut cav
        } else {
            &mut args
        };
        if !target.is_empty() {
            let p = rng.below(target.len());
            target[p] = match rng.below(3) {
                0 => target[p] ^ (1 << rng.below(8)),
                1 => b"/.@:~0123456789aZ\\"[rng.below(18)],
                _ => rng.next() as u8,
            };
        }
        let tool = r["tool"].as_str().unwrap_or("t");
        let a = pqsub_cli_free_core_caveat(&cav, tool, &args);
        let b = caveat_eval(&cav, tool, &args);
        // Real tool calls always carry canonical args (enforced at manifest decode),
        // so only canonical-args inputs are compared.
        if pqsub_core::cjson::parse_canonical(&args, true).is_ok() {
            assert_eq!(
                a,
                b,
                "iter {i} caveat={} args={:?}",
                hex::encode(&cav),
                String::from_utf8_lossy(&args)
            );
        }
    }
}

/// Same semantics as `pqsub_cli::vectors_v2::core_caveat`, inlined to avoid a dev-dep on the CLI crate.
fn pqsub_cli_free_core_caveat(caveat: &[u8], tool: &str, args: &[u8]) -> Option<bool> {
    use pqsub_core::caveat::{Caveat, CaveatKind};
    let c = Caveat::decode(caveat).ok()?;
    let v = pqsub_core::cjson::parse_canonical(args, true).ok()?;
    if matches!(c.kind, CaveatKind::MaxCalls(_) | CaveatKind::Executor(_)) {
        return Some(true);
    }
    Some(c.holds(tool, &v, &pqsub_core::Recipient::Role("x".into()), "x"))
}

fn v2_files(dir: &std::path::Path) {
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/vectors-v2.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let pk = hex::decode(v["root_pk"].as_str().unwrap()).unwrap();
    std::fs::write(dir.join("root.pub"), [b"PQSP\x01".as_slice(), &pk].concat()).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        if ["main_full", "executed_caveat_violation"].contains(&name) {
            std::fs::write(
                dir.join(format!("{name}.pqst")),
                hex::decode(c["transcript"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
    }
    let mut bad = std::fs::read(dir.join("main_full.pqst")).unwrap();
    let n = bad.len();
    bad[n - 100] ^= 1;
    std::fs::write(dir.join("tampered.pqst"), bad).unwrap();
}

/// `(code, "#entry", "#call", "reason=N")` from printed finding lines.
fn finding_lines(out: &str) -> Vec<(String, String, String, String)> {
    out.lines()
        .filter(|l| {
            ["BLOCKED", "EXECUTED_UNAUTHORIZED", "NO_RECEIPT"]
                .iter()
                .any(|c| l.starts_with(c))
        })
        .map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            (w[0].into(), w[2].into(), w[4].into(), w[5].into())
        })
        .collect()
}

#[test]
fn verifier_binary_end_to_end() {
    let d = std::env::temp_dir().join(format!("pqsub-verify-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    v2_files(&d);
    let run = |f: &str, req: bool| {
        let mut args = vec!["audit", "--root", "root.pub", f];
        if req {
            args.push("--require-authorized");
        }
        std::process::Command::new(env!("CARGO_BIN_EXE_pqsub-verify"))
            .current_dir(&d)
            .args(&args)
            .output()
            .unwrap()
    };
    let o = run("main_full.pqst", true);
    assert_eq!(o.status.code(), Some(0));
    let root = PublicKey::from_file_bytes(&std::fs::read(d.join("root.pub")).unwrap()).unwrap();
    let t = Transcript::decode(&std::fs::read(d.join("main_full.pqst")).unwrap()).unwrap();
    let r = audit(&root, &t, 0, &VerifyOptions::default()).unwrap();
    let want: Vec<_> = r
        .findings
        .iter()
        .map(|f| {
            (
                f.code.to_string(),
                format!("#{}", f.index),
                format!("#{}", f.call_index),
                format!("reason={}", f.reason),
            )
        })
        .collect();
    assert_eq!(
        finding_lines(&String::from_utf8(o.stdout).unwrap()),
        want,
        "pqsub-verify binary vs core library"
    );
    assert_eq!(
        run("executed_caveat_violation.pqst", true).status.code(),
        Some(2)
    );
    assert_eq!(
        run("executed_caveat_violation.pqst", false).status.code(),
        Some(0)
    );
    let o = run("tampered.pqst", false);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8(o.stderr)
        .unwrap()
        .contains("INVALID [BAD_SIGNATURE]"));
    std::fs::remove_dir_all(&d).unwrap();
}
