//! Deterministic test-vector generation (`test-vectors/vectors.json`).
//!
//! Each case states its *intended* outcome; the generator checks `pqsub-core`
//! agrees before emitting it, and `pqsub-verify` must agree independently.

use anyhow::{bail, Result};
use pqsub_core::{
    payload_hash, verify_entries, AgentKeypair, Anchor, EntrySpec, Hash32, IdentityClaims,
    IdentityDocument, ManifestBody, ManifestKind, PublicKey, Recipient, SignedManifest,
    SigningMode, TraceBuilder, VerifyOptions, CTX_MANIFEST, SIGNATURE_LEN,
};
use serde::{Deserialize, Serialize};

const DET: SigningMode = SigningMode::Deterministic;
const T0: u64 = 1_767_225_600_000;

/// Top-level vector file.
#[derive(Serialize, Deserialize, Debug)]
pub struct Vectors {
    /// Format tag.
    pub format: String,
    /// Default trust anchor (raw 1952-byte ML-DSA-65 public key, hex).
    pub root_pk: String,
    /// Key generation vectors (FIPS 204 KeyGen from seed).
    pub keygen: Vec<KeygenVec>,
    /// Signature vectors (FIPS 204 Sign with explicit rnd).
    pub signatures: Vec<SigVec>,
    /// Transcript verification cases.
    pub cases: Vec<Case>,
}

/// `seed -> (pk, agent_id)`.
#[derive(Serialize, Deserialize, Debug)]
pub struct KeygenVec {
    /// ξ.
    pub seed: String,
    /// Encoded public key.
    pub public_key: String,
    /// Derived agent id.
    pub agent_id: String,
}

/// `(seed, rnd, ctx, msg) -> signature`.
#[derive(Serialize, Deserialize, Debug)]
pub struct SigVec {
    /// ξ.
    pub seed: String,
    /// Per-signature randomness (zero = deterministic variant).
    pub rnd: String,
    /// Context string.
    pub ctx: String,
    /// Message.
    pub msg: String,
    /// Expected encoded signature.
    pub signature: String,
}

/// One transcript verification case.
#[derive(Serialize, Deserialize, Debug)]
pub struct Case {
    /// Identifier.
    pub name: String,
    /// What is being tested.
    pub description: String,
    /// Optional trust-anchor override (hex raw pk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_pk: Option<String>,
    /// Transcript bytes (hex).
    pub transcript: String,
    /// Verify `entries[from..]`.
    pub from: usize,
    /// `"genesis"`, `"none"` or a 64-hex entry hash.
    pub anchor: String,
    /// Optional expected head (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
    /// Expected outcome.
    pub expect: Expect,
}

/// Expected outcome.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Expect {
    /// Whether verification succeeds.
    pub ok: bool,
    /// Error code on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Head hash on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Entry hashes of the verified window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry_hashes: Vec<String>,
    /// Sender agent ids of the verified window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_ids: Vec<String>,
}

/// Parse a case's anchor string.
///
/// # Errors
/// Bad hex.
pub fn parse_anchor(s: &str) -> Result<Anchor> {
    Ok(match s {
        "genesis" => Anchor::Genesis,
        "none" => Anchor::Unanchored,
        h => Anchor::Hash(Hash32::from_hex(h)?),
    })
}

/// Run `pqsub-core` on a case and produce the observed [`Expect`].
///
/// # Errors
/// Only on malformed case fields (hex); verification failures are reported in the result.
pub fn core_outcome(default_root: &str, c: &Case) -> Result<Expect> {
    let root_hex = c.root_pk.as_deref().unwrap_or(default_root);
    let root = PublicKey::from_bytes(&hex::decode(root_hex)?)?;
    let bytes = hex::decode(&c.transcript)?;
    let opts = VerifyOptions {
        anchor: parse_anchor(&c.anchor)?,
        expected_head: c
            .expected_head
            .as_deref()
            .map(Hash32::from_hex)
            .transpose()?,
    };
    let res = pqsub_core::Transcript::decode(&bytes).and_then(|t| {
        let w = t
            .entries
            .get(c.from..)
            .ok_or(pqsub_core::Error::Decode("from beyond end"))?;
        verify_entries(&root, &t.identities, w, &opts)
    });
    Ok(match res {
        Ok(r) => Expect {
            ok: true,
            error: None,
            head: Some(r.head.to_hex()),
            entry_hashes: r.entries.iter().map(|e| e.entry_hash.to_hex()).collect(),
            agent_ids: r.entries.iter().map(|e| e.sender.to_hex()).collect(),
        },
        Err(e) => Expect {
            ok: false,
            error: Some(e.code().into()),
            head: None,
            entry_hashes: vec![],
            agent_ids: vec![],
        },
    })
}

fn seed(name: &str) -> [u8; 32] {
    payload_hash(format!("pqsub-vector-seed/{name}").as_bytes()).0
}

fn container(ids: &[Vec<u8>], ents: &[Vec<u8>]) -> Vec<u8> {
    let mut v = b"PQST\x01".to_vec();
    v.extend_from_slice(&(ids.len() as u16).to_be_bytes());
    for d in ids {
        v.extend_from_slice(&(d.len() as u32).to_be_bytes());
        v.extend_from_slice(d);
    }
    v.extend_from_slice(&(ents.len() as u32).to_be_bytes());
    for e in ents {
        v.extend_from_slice(&(e.len() as u32).to_be_bytes());
        v.extend_from_slice(e);
    }
    v
}

fn find(hay: &[u8], needle: &[u8]) -> Result<usize> {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .ok_or_else(|| anyhow::anyhow!("needle not found"))
}

fn flip(mut v: Vec<u8>, byte: usize, bit: u8) -> Vec<u8> {
    v[byte] ^= 1 << bit;
    v
}

/// Generate the full vector set deterministically.
///
/// # Errors
/// If `pqsub-core` disagrees with a case's intended outcome, or on crypto errors.
#[allow(clippy::too_many_lines)]
pub fn generate() -> Result<Vectors> {
    let root = AgentKeypair::from_seed(&seed("root"))?;
    let other_root = AgentKeypair::from_seed(&seed("other-root"))?;
    let names = ["agent0", "agent1", "agent2"];
    let agents: Vec<AgentKeypair> = names
        .iter()
        .map(|n| AgentKeypair::from_seed(&seed(n)))
        .collect::<pqsub_core::Result<_>>()?;
    let claims = |n: &str, nb: u64, na: u64| IdentityClaims {
        name: n.into(),
        role: "worker".into(),
        not_before_ms: nb,
        not_after_ms: na,
    };
    let ids: Vec<IdentityDocument> = agents
        .iter()
        .zip(names)
        .map(|(a, n)| {
            IdentityDocument::issue(&root, a.public_key(), claims(n, T0, T0 + 86_400_000), DET)
        })
        .collect::<pqsub_core::Result<_>>()?;

    let mut tb = TraceBuilder::new();
    for i in 0..6u64 {
        let a = &agents[(i % 3) as usize];
        let recipient = if i % 2 == 0 {
            Recipient::Agent(agents[((i + 1) % 3) as usize].agent_id())
        } else {
            Recipient::Role("tool-runner".into())
        };
        let kind = [
            ManifestKind::Handoff,
            ManifestKind::ToolAuthorization,
            ManifestKind::ActionRecord,
        ][(i % 3) as usize];
        tb.append(
            a,
            EntrySpec {
                kind,
                recipient,
                intent: format!("step {i}: do the thing"),
                payload_hash: if i == 4 {
                    None
                } else {
                    Some(payload_hash(format!("payload {i}").as_bytes()))
                },
                timestamp_ms: T0 + 1000 * (i + 1),
            },
            DET,
        )?;
    }
    let entries = tb.into_entries();
    let head = entries[5].entry_hash();
    let id_enc: Vec<Vec<u8>> = ids.iter().map(IdentityDocument::encode).collect();
    let en: Vec<Vec<u8>> = entries.iter().map(SignedManifest::encode).collect();
    let full = container(&id_enc, &en);

    let mut specs: Vec<(Case, Option<&str>)> = Vec::new();
    let mut add = |name: &str,
                   desc: &str,
                   transcript: Vec<u8>,
                   from: usize,
                   anchor: String,
                   eh: Option<Hash32>,
                   root_pk: Option<&PublicKey>,
                   want: Option<&'static str>| {
        specs.push((
            Case {
                name: name.into(),
                description: desc.into(),
                root_pk: root_pk.map(|p| hex::encode(p.as_bytes())),
                transcript: hex::encode(transcript),
                from,
                anchor,
                expected_head: eh.map(|h| h.to_hex()),
                expect: Expect {
                    ok: want.is_none(),
                    error: None,
                    head: None,
                    entry_hashes: vec![],
                    agent_ids: vec![],
                },
            },
            want,
        ));
    };
    let g = || "genesis".to_string();

    add(
        "valid_full",
        "complete 6-entry trace from genesis with expected head",
        full.clone(),
        0,
        g(),
        Some(head),
        None,
        None,
    );
    add(
        "valid_suffix_anchored",
        "entries[3..] anchored at checkpoint hash(entry 2)",
        full.clone(),
        3,
        entries[2].entry_hash().to_hex(),
        Some(head),
        None,
        None,
    );
    add(
        "valid_suffix_unanchored",
        "entries[3..] with no external anchor",
        full.clone(),
        3,
        "none".into(),
        None,
        None,
        None,
    );
    add(
        "valid_empty",
        "empty transcript",
        container(&[], &[]),
        0,
        g(),
        None,
        None,
        None,
    );

    let sig_byte = en[1].len() - 100;
    let mut e = en.clone();
    e[1] = flip(e[1].clone(), sig_byte, 3);
    add(
        "tamper_signature_bit",
        "single bit flipped inside entry 1 signature",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("BAD_SIGNATURE"),
    );

    let mut e = en.clone();
    let p = find(&e[1], b"step 1")?;
    e[1] = flip(e[1].clone(), p + 5, 0); // '1' -> '0'
    add(
        "tamper_intent_bit",
        "single bit flipped in entry 1 intent text",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("BAD_SIGNATURE"),
    );

    let mut e = en.clone();
    let b3 = entries[3].body();
    let seq_ts: Vec<u8> = b3
        .seq
        .to_be_bytes()
        .into_iter()
        .chain(b3.timestamp_ms.to_be_bytes())
        .collect();
    let seq_pos = find(&e[3], &seq_ts)?;
    e[3] = flip(e[3].clone(), seq_pos + 7, 1);
    add(
        "tamper_seq_bit",
        "single bit flipped in entry 3 sequence number",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("BAD_SIGNATURE"),
    );

    let mut d = id_enc.clone();
    let p = find(&d[0], b"agent0")?;
    d[0] = flip(d[0].clone(), p, 0);
    add(
        "tamper_identity_name",
        "bit flipped in identity 0 name",
        container(&d, &en),
        0,
        g(),
        None,
        None,
        Some("IDENTITY_INVALID"),
    );

    add(
        "wrong_root",
        "identities verified against a different trust anchor",
        full.clone(),
        0,
        g(),
        None,
        Some(other_root.public_key()),
        Some("IDENTITY_INVALID"),
    );

    let mut e = en.clone();
    e.swap(2, 3);
    add(
        "reordered",
        "entries 2 and 3 swapped",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("CHAIN_BROKEN"),
    );

    let mut e = en.clone();
    e.remove(3);
    add(
        "dropped_middle",
        "entry 3 removed",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("CHAIN_BROKEN"),
    );

    add(
        "truncated_tail",
        "last entry removed; verifier knows the real head",
        container(&id_enc, &en[..5]),
        0,
        g(),
        Some(head),
        None,
        Some("HEAD_MISMATCH"),
    );
    add(
        "suffix_wrong_anchor",
        "entries[3..] against checkpoint hash(entry 1)",
        full.clone(),
        3,
        entries[1].entry_hash().to_hex(),
        None,
        None,
        Some("CHAIN_BROKEN"),
    );
    add(
        "suffix_as_genesis",
        "entries[3..] claimed to start at genesis",
        full.clone(),
        3,
        g(),
        None,
        None,
        Some("CHAIN_BROKEN"),
    );

    let mut x = full.clone();
    x.push(0);
    add(
        "trailing_byte",
        "one extra byte after the container",
        x,
        0,
        g(),
        None,
        None,
        Some("DECODE"),
    );
    let mut x = full.clone();
    x[4] = 2;
    add(
        "bad_container_version",
        "container version 2",
        x,
        0,
        g(),
        None,
        None,
        Some("DECODE"),
    );

    let mut e = en.clone();
    let flag = e[0].len() - SIGNATURE_LEN - 33;
    e[0][flag] = 2;
    add(
        "bad_payload_flag",
        "payload flag byte = 2 (non-canonical)",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("DECODE"),
    );

    let mut e = en.clone();
    e[0][5] = 4;
    add(
        "unknown_kind",
        "manifest kind byte = 4",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("DECODE"),
    );

    add(
        "unknown_sender",
        "identity for agent2 missing",
        container(&id_enc[..2], &en),
        0,
        g(),
        None,
        None,
        Some("UNKNOWN_SENDER"),
    );

    let mut d = id_enc.clone();
    d.push(
        IdentityDocument::issue(
            &root,
            agents[0].public_key(),
            claims("agent0-dup", T0, T0 + 1),
            DET,
        )?
        .encode(),
    );
    add(
        "duplicate_identity",
        "two identity documents for agent0",
        container(&d, &en),
        0,
        g(),
        None,
        None,
        Some("DUPLICATE_IDENTITY"),
    );

    let mut d = id_enc.clone();
    d[0] = IdentityDocument::issue(
        &root,
        agents[0].public_key(),
        claims("agent0", T0, T0 + 500),
        DET,
    )?
    .encode();
    add(
        "expired_identity",
        "agent0 identity expires before its first entry",
        container(&d, &en),
        0,
        g(),
        None,
        None,
        Some("IDENTITY_EXPIRED"),
    );

    let mut d = id_enc.clone();
    d[0] = IdentityDocument::issue_with_agent_id(
        &root,
        agents[1].agent_id(),
        agents[0].public_key(),
        claims("agent0", T0, T0 + 86_400_000),
        DET,
    )?
    .encode();
    add(
        "identity_id_mismatch",
        "root-signed identity whose agent_id != H(pk)",
        container(&d, &en),
        0,
        g(),
        None,
        None,
        Some("IDENTITY_INVALID"),
    );

    let replay = ManifestBody {
        kind: ManifestKind::ActionRecord,
        sender: agents[0].agent_id(),
        recipient: Recipient::Role("tool-runner".into()),
        seq: 0,
        timestamp_ms: T0 + 10_000,
        prev: head,
        intent: "step 0: do the thing".into(),
        payload_hash: None,
        ext: pqsub_core::Ext::V1,
    };
    let mut e = en.clone();
    e.push(SignedManifest::sign(replay, &agents[0], DET)?.encode());
    add(
        "seq_replay",
        "agent0 re-uses seq 0 in a correctly chained, validly signed entry",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("SEQ_REPLAY"),
    );

    let mut e = en.clone();
    e[2] = en[1].clone();
    add(
        "duplicated_entry",
        "entry 1 replayed in place of entry 2",
        container(&id_enc, &e),
        0,
        g(),
        None,
        None,
        Some("CHAIN_BROKEN"),
    );

    add(
        "from_beyond_end",
        "window start beyond the last entry",
        full.clone(),
        7,
        "none".into(),
        None,
        None,
        Some("DECODE"),
    );

    // Compute and check outcomes.
    let root_hex = hex::encode(root.public_key().as_bytes());
    let mut cases = Vec::new();
    for (mut c, want) in specs {
        let got = core_outcome(&root_hex, &c)?;
        if got.ok != want.is_none() || got.error.as_deref() != want {
            bail!(
                "case {}: intended {:?}, pqsub-core produced {:?}",
                c.name,
                want,
                got
            );
        }
        c.expect = got;
        cases.push(c);
    }

    let keygen = std::iter::once((&root, "root"))
        .chain(agents.iter().zip(names))
        .map(|(k, n)| KeygenVec {
            seed: hex::encode(seed(n)),
            public_key: hex::encode(k.public_key().as_bytes()),
            agent_id: k.agent_id().to_hex(),
        })
        .collect();
    let mut signatures = Vec::new();
    for (i, rnd) in [[0u8; 32], [0x42u8; 32]].iter().enumerate() {
        let msg = entries[i].body_bytes();
        let sig = agents[i].sign_with_rnd(msg, CTX_MANIFEST, rnd)?;
        signatures.push(SigVec {
            seed: hex::encode(seed(names[i])),
            rnd: hex::encode(rnd),
            ctx: hex::encode(CTX_MANIFEST),
            msg: hex::encode(msg),
            signature: hex::encode(&sig[..]),
        });
    }

    Ok(Vectors {
        format: "pqsub-test-vectors/v1".into(),
        root_pk: root_hex,
        keygen,
        signatures,
        cases,
    })
}

/// Serialize vectors as pretty JSON with a trailing newline.
///
/// # Errors
/// Serialization failure.
pub fn to_json(v: &Vectors) -> Result<String> {
    Ok(serde_json::to_string_pretty(v)? + "\n")
}
