//! Dependency-free micro-benchmarks (`pqsub bench`). Run with `--release`.

use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

use anyhow::Result;
use pqsub_core::{
    AgentKeypair, IdentityClaims, IdentityDocument, ManifestBody, ManifestKind, Recipient,
    SignedManifest, SigningMode, Transcript, VerifyOptions, CTX_MANIFEST,
};

fn time<F: FnMut() -> Result<()>>(
    out: &mut String,
    name: &str,
    iters: u32,
    mut f: F,
) -> Result<f64> {
    f()?; // warm-up
    let start = Instant::now();
    for _ in 0..iters {
        f()?;
    }
    let us = start.elapsed().as_secs_f64() * 1e6 / f64::from(iters);
    let _ = writeln!(out, "{name:<44} {us:>10.1} µs/op  ({:>8.0} op/s)", 1e6 / us);
    Ok(us)
}

/// Run the benchmark suite; returns a printable report.
///
/// # Errors
/// Cryptographic failures.
pub fn run(iters: u32) -> Result<String> {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "pqsub micro-benchmarks ({iters} iterations each, ML-DSA-65)"
    );
    let k = AgentKeypair::from_seed(&[7u8; 32])?;
    let body = ManifestBody {
        kind: ManifestKind::Handoff,
        sender: k.agent_id(),
        recipient: Recipient::Role("reviewer".into()),
        seq: 1,
        timestamp_ms: 1,
        prev: pqsub_core::Hash32::ZERO,
        intent: "review the patch and report findings".into(),
        payload_hash: Some(pqsub_core::payload_hash(b"x")),
        ext: pqsub_core::Ext::V1,
    };
    let body_bytes = body.encode()?;

    let mut s = [0u8; 32];
    time(&mut out, "keygen (from seed)", iters, || {
        s[0] = s[0].wrapping_add(1);
        black_box(AgentKeypair::from_seed(&s)?);
        Ok(())
    })?;
    time(&mut out, "sign manifest (deterministic)", iters, || {
        black_box(k.sign(&body_bytes, CTX_MANIFEST, SigningMode::Deterministic)?);
        Ok(())
    })?;
    time(&mut out, "sign manifest (hedged, OS rng)", iters, || {
        black_box(k.sign(&body_bytes, CTX_MANIFEST, SigningMode::Hedged)?);
        Ok(())
    })?;
    let sig = k.sign(&body_bytes, CTX_MANIFEST, SigningMode::Deterministic)?;
    time(
        &mut out,
        "verify signature (cached public key)",
        iters,
        || {
            black_box(k.public_key().verify(&body_bytes, CTX_MANIFEST, &sig[..]));
            Ok(())
        },
    )?;
    let pkb = *k.public_key().as_bytes();
    time(&mut out, "decode public key + verify", iters, || {
        let pk = pqsub_core::PublicKey::from_bytes(&pkb)?;
        black_box(pk.verify(&body_bytes, CTX_MANIFEST, &sig[..]));
        Ok(())
    })?;
    let m = SignedManifest::sign(body, &k, SigningMode::Deterministic)?;
    let enc = m.encode();
    time(
        &mut out,
        "manifest decode (strict, no verify)",
        iters,
        || {
            black_box(SignedManifest::decode(&enc)?);
            Ok(())
        },
    )?;

    // 100-entry trace across 4 agents.
    let root = AgentKeypair::from_seed(&[1u8; 32])?;
    let agents: Vec<AgentKeypair> = (0..4u8)
        .map(|i| AgentKeypair::from_seed(&[10 + i; 32]))
        .collect::<pqsub_core::Result<_>>()?;
    let ids = agents
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let c = IdentityClaims {
                name: format!("a{i}"),
                role: "w".into(),
                not_before_ms: 0,
                not_after_ms: u64::MAX,
            };
            IdentityDocument::issue(&root, a.public_key(), c, SigningMode::Deterministic)
        })
        .collect::<pqsub_core::Result<Vec<_>>>()?;
    let mut tb = pqsub_core::TraceBuilder::new();
    for i in 0..100u64 {
        tb.append(
            &agents[(i % 4) as usize],
            pqsub_core::EntrySpec {
                kind: ManifestKind::ActionRecord,
                recipient: Recipient::Role("log".into()),
                intent: format!("action {i}"),
                payload_hash: None,
                timestamp_ms: i,
            },
            SigningMode::Deterministic,
        )?;
    }
    let t = Transcript {
        identities: ids,
        grants: vec![],
        entries: tb.into_entries(),
    };
    let tenc = t.encode()?;
    let _ = writeln!(
        out,
        "transcript: 4 identities + 100 entries = {} bytes",
        tenc.len()
    );
    let trace_iters = (iters / 20).max(3);
    time(
        &mut out,
        "decode + verify 100-entry transcript",
        trace_iters,
        || {
            let t = Transcript::decode(&tenc)?;
            black_box(t.verify(root.public_key(), 0, &VerifyOptions::default())?);
            Ok(())
        },
    )?;
    Ok(out)
}
