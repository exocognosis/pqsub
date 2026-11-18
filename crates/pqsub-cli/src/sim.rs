//! A short multi-agent handoff simulation producing a verifiable transcript.
//!
//! Four agents (orchestrator, researcher, coder, reviewer), one root/operator
//! key. Every handoff, tool authorization and action is a signed, hash-chained
//! manifest. In deterministic mode all keys, timestamps and signatures are
//! fixed so the transcript is byte-for-byte reproducible.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use pqsub_core::{
    payload_hash, AgentKeypair, EntrySpec, FileKeyStore, IdentityClaims, IdentityDocument,
    KeyStore, ManifestKind, Recipient, SigningMode, TraceBuilder, Transcript, VerifyOptions,
};

/// Fixed epoch used in deterministic mode (2026-01-01T00:00:00Z).
pub const DEMO_T0_MS: u64 = 1_767_225_600_000;
const DAY_MS: u64 = 86_400_000;

/// Agent names and roles in the simulation.
pub const AGENTS: [(&str, &str); 4] = [
    ("orchestrator", "orchestrator"),
    ("researcher", "research"),
    ("coder", "engineering"),
    ("reviewer", "review"),
];

/// Deterministic demo seed for `name` (NOT for production use).
#[must_use]
pub fn demo_seed(name: &str) -> [u8; 32] {
    payload_hash(format!("pqsub-demo-seed/{name}").as_bytes()).0
}

/// Output of [`run`].
pub struct SimOutput {
    /// Root / operator keypair.
    pub root: AgentKeypair,
    /// The produced transcript.
    pub transcript: Transcript,
    /// Rendered text transcript including verification result.
    pub text: String,
    /// Hash of entry #2, usable as an external checkpoint for suffix verification.
    pub checkpoint: pqsub_core::Hash32,
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

/// Simulation output plus named agent keys and raw payloads.
pub type SimRun = (SimOutput, Vec<(String, AgentKeypair)>, Vec<Vec<u8>>);

/// Run the simulation in memory.
///
/// # Errors
/// Any cryptographic or encoding failure.
pub fn run(deterministic: bool) -> Result<SimRun> {
    let mode = if deterministic {
        SigningMode::Deterministic
    } else {
        SigningMode::Hedged
    };
    let t0 = if deterministic { DEMO_T0_MS } else { now_ms()? };
    let mk = |n: &str| {
        if deterministic {
            AgentKeypair::from_seed(&demo_seed(n))
        } else {
            AgentKeypair::generate()
        }
    };

    let root = mk("root")?;
    let mut keys = Vec::new();
    let mut ids = Vec::new();
    for (name, role) in AGENTS {
        let k = mk(name)?;
        let claims = IdentityClaims {
            name: name.into(),
            role: role.into(),
            not_before_ms: t0,
            not_after_ms: t0 + 30 * DAY_MS,
        };
        ids.push(IdentityDocument::issue(
            &root,
            k.public_key(),
            claims,
            mode,
        )?);
        keys.push((name.to_string(), k));
    }
    let (orch, res, coder, rev) = (&keys[0].1, &keys[1].1, &keys[2].1, &keys[3].1);

    let payloads: Vec<Vec<u8>> = vec![
        b"Task T-42: test `billing::retry::backoff_resets` is flaky (~3% of CI runs). Find root cause.".to_vec(),
        b"Root cause: retry timer is armed before the lock is released; under contention the reset races.".to_vec(),
        b"cargo test -p billing --locked -- --test-threads=1 (sandbox: no network, read-only FS outside target/)"
            .to_vec(),
        b"--- a/billing/src/retry.rs\n+++ b/billing/src/retry.rs\n@@ -88 +88 @@\n-    arm_timer(); drop(guard);\n+    drop(guard); arm_timer();\n".to_vec(),
        b"Review: change is minimal, test now passes 500/500 runs. APPROVE.".to_vec(),
        b"merge T-42 patch into main".to_vec(),
    ];
    let steps: [(&AgentKeypair, ManifestKind, Recipient, &str); 6] = [
        (
            orch,
            ManifestKind::Handoff,
            Recipient::Agent(res.agent_id()),
            "Investigate flaky test in `billing` (task T-42)",
        ),
        (
            res,
            ManifestKind::Handoff,
            Recipient::Agent(coder.agent_id()),
            "Root cause identified; implement fix",
        ),
        (
            coder,
            ManifestKind::ToolAuthorization,
            Recipient::Role("sandbox-runner".into()),
            "Run billing test suite in sandbox",
        ),
        (
            coder,
            ManifestKind::Handoff,
            Recipient::Agent(rev.agent_id()),
            "Patch ready for review (1 file, 1 hunk)",
        ),
        (
            rev,
            ManifestKind::ActionRecord,
            Recipient::Agent(orch.agent_id()),
            "Reviewed patch: APPROVE",
        ),
        (
            orch,
            ManifestKind::ToolAuthorization,
            Recipient::Role("merge-bot".into()),
            "Merge T-42 patch into main",
        ),
    ];

    let mut tb = TraceBuilder::new();
    for (i, ((key, kind, to, intent), payload)) in steps.into_iter().zip(&payloads).enumerate() {
        let spec = EntrySpec {
            kind,
            recipient: to,
            intent: intent.into(),
            payload_hash: Some(payload_hash(payload)),
            timestamp_ms: t0 + 60_000 * (i as u64 + 1),
        };
        tb.append(key, spec, mode)?;
    }
    let transcript = Transcript {
        identities: ids,
        grants: vec![],
        entries: tb.into_entries(),
    };
    let checkpoint = transcript.entries[2].entry_hash();
    let report = transcript.verify(root.public_key(), 0, &VerifyOptions::default())?;
    let text = crate::render::transcript_text(&transcript, 0, Some(&report));
    Ok((
        SimOutput {
            root,
            transcript,
            text,
            checkpoint,
        },
        keys,
        payloads,
    ))
}

/// Run the simulation and write all artifacts to `out` (must not exist or be empty).
///
/// Layout: `keys/` (0700, secret keys), `root.pub`, `identities/*.id`,
/// `payloads/*.txt`, `transcript.pqst`, `transcript.txt`, `checkpoint.txt`, `head.txt`.
///
/// # Errors
/// I/O or cryptographic failures.
pub fn run_to_dir(out: &Path, deterministic: bool) -> Result<SimOutput> {
    if out.exists() && fs::read_dir(out)?.next().is_some() {
        bail!("{} exists and is not empty", out.display());
    }
    let (sim, keys, payloads) = run(deterministic)?;
    let ks = FileKeyStore::open(out.join("keys"))?;
    ks.save("root", &sim.root)?;
    for (n, k) in &keys {
        ks.save(n, k)?;
    }
    let w = |p: PathBuf, d: &[u8]| -> Result<()> {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&p, d).with_context(|| format!("writing {}", p.display()))
    };
    w(out.join("root.pub"), &sim.root.public_key().to_file_bytes())?;
    for d in &sim.transcript.identities {
        w(
            out.join("identities")
                .join(format!("{}.id", d.claims().name)),
            &d.encode(),
        )?;
    }
    for (i, p) in payloads.iter().enumerate() {
        w(out.join("payloads").join(format!("{i}.txt")), p)?;
    }
    w(out.join("transcript.pqst"), &sim.transcript.encode()?)?;
    w(out.join("transcript.txt"), sim.text.as_bytes())?;
    w(
        out.join("checkpoint.txt"),
        format!("{}\n", sim.checkpoint).as_bytes(),
    )?;
    let head = sim
        .transcript
        .entries
        .last()
        .map(|e| e.entry_hash())
        .unwrap_or_default();
    w(out.join("head.txt"), format!("{head}\n").as_bytes())?;
    Ok(sim)
}
