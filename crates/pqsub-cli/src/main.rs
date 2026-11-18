//! `pqsub` — reference CLI for the post-quantum multi-agent substrate.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pqsub_cli::{bench, render, sim, vectors};
use pqsub_core::keystore::load_key_file;
use pqsub_core::{
    payload_hash, verify_handoff, AgentKeypair, Anchor, EntrySpec, FileKeyStore, Hash32,
    IdentityClaims, IdentityDocument, KeyStore, ManifestBody, ManifestKind, PublicKey, Recipient,
    SignedManifest, SigningMode, TraceBuilder, Transcript, VerifyOptions,
};

#[derive(Parser)]
#[command(
    name = "pqsub",
    version,
    about = "Post-quantum (ML-DSA-65) identities, signed handoffs and verifiable traces for agents"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Handoff,
    ToolAuth,
    Action,
}

impl From<Kind> for ManifestKind {
    fn from(k: Kind) -> Self {
        match k {
            Kind::Handoff => ManifestKind::Handoff,
            Kind::ToolAuth => ManifestKind::ToolAuthorization,
            Kind::Action => ManifestKind::ActionRecord,
        }
    }
}

#[derive(clap::Args)]
struct EntryArgs {
    /// Manifest kind.
    #[arg(long, value_enum, default_value = "handoff")]
    kind: Kind,
    /// Recipient agent (path to its identity document).
    #[arg(long, conflicts_with = "to_role")]
    to_agent: Option<PathBuf>,
    /// Recipient role.
    #[arg(long)]
    to_role: Option<String>,
    /// Intent / action summary.
    #[arg(long)]
    intent: String,
    /// File whose domain-separated SHA3-256 digest is bound into the manifest.
    #[arg(long)]
    payload: Option<PathBuf>,
    /// Timestamp in unix ms (default: now).
    #[arg(long)]
    ts: Option<u64>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the root/operator key in a key directory and export its public key.
    RootInit {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long, default_value = "root")]
        name: String,
        /// Where to write the root public key (the trust anchor to distribute).
        #[arg(long)]
        pub_out: PathBuf,
    },
    /// Generate an agent key and issue its identity document signed by the root key.
    AgentNew {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long, default_value = "root")]
        root_name: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        role: String,
        #[arg(long, default_value_t = 30)]
        valid_days: u64,
        /// Output identity document path.
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a standalone manifest (handoff / tool authorization / action record).
    Sign {
        /// Path to the sender's secret key file.
        #[arg(long)]
        key: PathBuf,
        #[command(flatten)]
        entry: EntryArgs,
        #[arg(long, default_value_t = 0)]
        seq: u64,
        /// Previous entry hash (hex); default zero.
        #[arg(long)]
        prev: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a standalone manifest against the sender's identity and the trust anchor.
    Verify {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        manifest: PathBuf,
        /// Optionally check a payload file against the manifest's payload hash.
        #[arg(long)]
        payload: Option<PathBuf>,
    },
    /// Append a signed entry to a transcript (created if absent). The existing
    /// transcript is verified against the root before appending.
    Append {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        transcript: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Sender identity document (added to the transcript if not present).
        #[arg(long)]
        identity: PathBuf,
        #[command(flatten)]
        entry: EntryArgs,
    },
    /// Verify a transcript (or a suffix) against an out-of-band trust anchor.
    VerifyTrace {
        #[arg(long)]
        root: PathBuf,
        transcript: PathBuf,
        /// Verify only entries[from..].
        #[arg(long, default_value_t = 0)]
        from: usize,
        /// `genesis`, `none`, or a 64-hex checkpoint hash. Default: genesis if from=0, else none.
        #[arg(long)]
        anchor: Option<String>,
        /// Expected head hash (detects tail truncation).
        #[arg(long)]
        expect_head: Option<String>,
        /// Print the full transcript.
        #[arg(long)]
        show: bool,
    },
    /// Print any pqsub artifact in human-readable form (does not verify).
    Inspect { file: PathBuf },
    /// Print the payload digest of a file.
    Hash { file: PathBuf },
    /// Run a 4-agent handoff simulation and write a verifiable transcript.
    Simulate {
        #[arg(long)]
        out: PathBuf,
        /// Fixed keys/timestamps/signatures (reproducible output; demo only).
        #[arg(long)]
        deterministic: bool,
    },
    /// Regenerate deterministic test vectors.
    GenVectors {
        #[arg(long, default_value = "test-vectors/vectors.json")]
        out: PathBuf,
    },
    /// Micro-benchmarks (use --release).
    Bench {
        #[arg(long, default_value_t = 200)]
        iters: u32,
    },
}

fn read(p: &Path) -> Result<Vec<u8>> {
    fs::read(p).with_context(|| format!("reading {}", p.display()))
}

fn write_new(p: &Path, d: &[u8]) -> Result<()> {
    if p.exists() {
        bail!("{} already exists", p.display());
    }
    fs::write(p, d).with_context(|| format!("writing {}", p.display()))
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn load_root(p: &Path) -> Result<PublicKey> {
    PublicKey::from_file_bytes(&read(p)?).context("parsing root public key")
}

fn load_identity(p: &Path) -> Result<IdentityDocument> {
    IdentityDocument::decode(&read(p)?).with_context(|| format!("parsing identity {}", p.display()))
}

fn entry_spec(e: &EntryArgs) -> Result<EntrySpec> {
    let recipient = match (&e.to_agent, &e.to_role) {
        (Some(p), None) => Recipient::Agent(load_identity(p)?.agent_id()),
        (None, Some(r)) => Recipient::Role(r.clone()),
        _ => bail!("exactly one of --to-agent / --to-role is required"),
    };
    Ok(EntrySpec {
        kind: e.kind.into(),
        recipient,
        intent: e.intent.clone(),
        payload_hash: e
            .payload
            .as_deref()
            .map(read)
            .transpose()?
            .map(|d| payload_hash(&d)),
        timestamp_ms: match e.ts {
            Some(t) => t,
            None => now_ms()?,
        },
    })
}

fn parse_anchor(a: Option<&str>, from: usize) -> Result<Anchor> {
    Ok(match a {
        None if from == 0 => Anchor::Genesis,
        None | Some("none") => Anchor::Unanchored,
        Some("genesis") => Anchor::Genesis,
        Some(h) => Anchor::Hash(Hash32::from_hex(h)?),
    })
}

fn inspect(bytes: &[u8]) -> Result<String> {
    Ok(match bytes.get(..4).unwrap_or_default() {
        b"PQST" => render::transcript_text(&Transcript::decode(bytes)?, 0, None),
        b"PQSM" => {
            let t = Transcript {
                identities: vec![],
                entries: vec![SignedManifest::decode(bytes)?],
            };
            render::transcript_text(&t, 0, None)
        }
        b"PQSI" => {
            let d = IdentityDocument::decode(bytes)?;
            let c = d.claims();
            format!(
                "identity document (unverified)\n  name      {}\n  role      {}\n  agent_id  {}\n  issuer_id {}\n  valid     [{}, {}] ms\n",
                c.name,
                c.role,
                d.agent_id(),
                d.issuer_id(),
                c.not_before_ms,
                c.not_after_ms
            )
        }
        b"PQSP" => format!(
            "ML-DSA-65 public key\n  agent_id {}\n",
            PublicKey::from_file_bytes(bytes)?.agent_id()
        ),
        b"PQSK" => "SECRET KEY FILE (contents not printed)\n".to_string(),
        _ => bail!("unknown file type"),
    })
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::RootInit {
            keys,
            name,
            pub_out,
        } => {
            let ks = FileKeyStore::open(&keys)?;
            let k = AgentKeypair::generate()?;
            ks.save(&name, &k)?;
            write_new(&pub_out, &k.public_key().to_file_bytes())?;
            println!(
                "root key  {}\nroot id   {}\npublic    {}",
                ks.path_for(&name)?.display(),
                k.agent_id(),
                pub_out.display()
            );
        }
        Cmd::AgentNew {
            keys,
            root_name,
            name,
            role,
            valid_days,
            out,
        } => {
            let ks = FileKeyStore::open(&keys)?;
            let root = ks.load(&root_name)?;
            let k = AgentKeypair::generate()?;
            let now = now_ms()?;
            let claims = IdentityClaims {
                name: name.clone(),
                role,
                not_before_ms: now,
                not_after_ms: now.saturating_add(valid_days.saturating_mul(86_400_000)),
            };
            let doc = IdentityDocument::issue(&root, k.public_key(), claims, SigningMode::Hedged)?;
            write_new(&out, &doc.encode())?;
            ks.save(&name, &k)?;
            println!(
                "agent     {name}\nagent id  {}\nkey       {}\nidentity  {}",
                k.agent_id(),
                ks.path_for(&name)?.display(),
                out.display()
            );
        }
        Cmd::Sign {
            key,
            entry,
            seq,
            prev,
            out,
        } => {
            let k = load_key_file(&key)?;
            let s = entry_spec(&entry)?;
            let body = ManifestBody {
                kind: s.kind,
                sender: k.agent_id(),
                recipient: s.recipient,
                seq,
                timestamp_ms: s.timestamp_ms,
                prev: prev
                    .as_deref()
                    .map(Hash32::from_hex)
                    .transpose()?
                    .unwrap_or_default(),
                intent: s.intent,
                payload_hash: s.payload_hash,
            };
            let m = SignedManifest::sign(body, &k, SigningMode::Hedged)?;
            let enc = m.encode();
            write_new(&out, &enc)?;
            println!(
                "signed    {} ({} bytes)\nentry     {}",
                out.display(),
                enc.len(),
                m.entry_hash()
            );
        }
        Cmd::Verify {
            root,
            identity,
            manifest,
            payload,
        } => {
            let root = load_root(&root)?;
            let id = load_identity(&identity)?;
            let m = SignedManifest::decode(&read(&manifest)?)?;
            if let Err(e) = verify_handoff(&root, &id, &m) {
                eprintln!("INVALID [{}] {e}", e.code());
                std::process::exit(2);
            }
            if let Some(p) = payload {
                let h = payload_hash(&read(&p)?);
                if m.body().payload_hash.map(|x| x.ct_eq(&h)) != Some(true) {
                    eprintln!(
                        "INVALID [PAYLOAD_MISMATCH] payload does not match manifest payload hash"
                    );
                    std::process::exit(2);
                }
            }
            println!(
                "VALID  sender={} ({})  intent={:?}",
                id.claims().name,
                id.agent_id(),
                m.body().intent
            );
        }
        Cmd::Append {
            root,
            transcript,
            key,
            identity,
            entry,
        } => {
            let root = load_root(&root)?;
            let k = load_key_file(&key)?;
            let id = load_identity(&identity)?;
            id.verify(&root)?;
            if !id.agent_id().ct_eq(&k.agent_id()) {
                bail!("identity document does not belong to this key");
            }
            let mut t = if transcript.exists() {
                Transcript::decode(&read(&transcript)?)?
            } else {
                Transcript::default()
            };
            t.verify(&root, 0, &VerifyOptions::default())
                .context("existing transcript invalid")?;
            if !t.identities.iter().any(|d| d.agent_id() == id.agent_id()) {
                t.identities.push(id);
            }
            let mut tb = TraceBuilder::resume(std::mem::take(&mut t.entries));
            let m = tb.append(&k, entry_spec(&entry)?, SigningMode::Hedged)?;
            let (h, seq) = (m.entry_hash(), m.body().seq);
            t.entries = tb.into_entries();
            let tmp = transcript.with_extension("tmp");
            fs::write(&tmp, t.encode()?)?;
            fs::rename(&tmp, &transcript)?;
            println!(
                "appended  #{} seq={seq}\nhead      {h}",
                t.entries.len() - 1
            );
        }
        Cmd::VerifyTrace {
            root,
            transcript,
            from,
            anchor,
            expect_head,
            show,
        } => {
            let root = load_root(&root)?;
            let t = Transcript::decode(&read(&transcript)?)?;
            let opts = VerifyOptions {
                anchor: parse_anchor(anchor.as_deref(), from)?,
                expected_head: expect_head.as_deref().map(Hash32::from_hex).transpose()?,
            };
            match t.verify(&root, from, &opts) {
                Ok(r) if show => print!("{}", render::transcript_text(&t, from, Some(&r))),
                Ok(r) => {
                    for e in &r.entries {
                        println!(
                            "#{:<3} ok  {:<13} {:<18} seq={:<3} {}",
                            from + e.index,
                            e.sender_name,
                            e.kind.as_str(),
                            e.seq,
                            e.entry_hash
                        );
                    }
                    println!(
                        "VALID  {} entries  anchored={}  head={}",
                        r.entries.len(),
                        r.anchored,
                        r.head
                    );
                }
                Err(e) => {
                    eprintln!("INVALID [{}] {e}", e.code());
                    std::process::exit(2);
                }
            }
        }
        Cmd::Inspect { file } => print!("{}", inspect(&read(&file)?)?),
        Cmd::Hash { file } => println!("{}", payload_hash(&read(&file)?)),
        Cmd::Simulate { out, deterministic } => {
            let s = sim::run_to_dir(&out, deterministic)?;
            print!("{}", s.text);
            println!("checkpoint (hash of entry #2): {}", s.checkpoint);
            println!("artifacts written to {}", out.display());
        }
        Cmd::GenVectors { out } => {
            let v = vectors::generate()?;
            fs::write(&out, vectors::to_json(&v)?)?;
            println!(
                "wrote {} cases, {} keygen, {} signature vectors to {}",
                v.cases.len(),
                v.keygen.len(),
                v.signatures.len(),
                out.display()
            );
        }
        Cmd::Bench { iters } => print!("{}", bench::run(iters)?),
    }
    Ok(())
}
