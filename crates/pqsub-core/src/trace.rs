//! Append-only hash-chained traces of signed manifests, and their verification.
//!
//! Transcript container (v1, big-endian):
//! ```text
//! "PQST" | 0x01
//! | u16 n_identities (0..=1024) | { u32 len (1..=16384) | identity_document }*
//! | u32 n_entries (0..=1048576) | { u32 len (1..=16384) | signed_manifest }*
//! ```
//! The trust anchor (root public key) is deliberately **not** part of the
//! transcript: verifiers must obtain it out of band.

use std::collections::HashMap;

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::{AgentId, Hash32};
use crate::identity::IdentityDocument;
use crate::keys::{AgentKeypair, PublicKey, SigningMode};
use crate::manifest::{ManifestBody, ManifestKind, Recipient, SignedManifest, CTX_MANIFEST};

const MAGIC: &[u8; 4] = b"PQST";
const VERSION: u8 = 1;
/// Max identity documents per transcript.
pub const MAX_IDENTITIES: usize = 1024;
/// Max entries per transcript.
pub const MAX_ENTRIES: usize = 1 << 20;
/// Max encoded size of a single identity document or manifest.
pub const MAX_ITEM_LEN: usize = 16 * 1024;

/// What the first verified entry's `prev` must equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// Full trace: first `prev` must be all-zero.
    Genesis,
    /// Suffix: first `prev` must equal this entry hash (e.g. a checkpoint).
    Hash(Hash32),
    /// Suffix with no external anchor: the first `prev` is not checked. The
    /// report marks the result as unanchored (truncation of the prefix is
    /// undetectable).
    Unanchored,
}

/// Options for [`verify_entries`].
#[derive(Clone, Copy, Debug)]
pub struct VerifyOptions {
    /// Anchor for the first entry.
    pub anchor: Anchor,
    /// If set, the last entry's hash must equal this (detects tail truncation).
    pub expected_head: Option<Hash32>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            anchor: Anchor::Genesis,
            expected_head: None,
        }
    }
}

/// Per-entry verification result.
#[derive(Clone, Debug)]
pub struct EntryReport {
    /// Index within the verified window.
    pub index: usize,
    /// Entry hash.
    pub entry_hash: Hash32,
    /// Sender id.
    pub sender: AgentId,
    /// Sender's display name (from its verified identity).
    pub sender_name: String,
    /// Kind.
    pub kind: ManifestKind,
    /// Sequence number.
    pub seq: u64,
}

/// Successful trace verification result.
#[derive(Clone, Debug)]
pub struct TraceReport {
    /// Per-entry details.
    pub entries: Vec<EntryReport>,
    /// Hash of the last entry (or the anchor if empty).
    pub head: Hash32,
    /// Whether the window was tied to genesis or an external anchor.
    pub anchored: bool,
}

/// Verify a window of trace entries against a trust anchor.
///
/// Check order (mirrored exactly by `pqsub-verify`):
/// 1. each identity document in order: [`IdentityDocument::verify`] →
///    `IDENTITY_INVALID`; then duplicate agent id → `DUPLICATE_IDENTITY`
/// 2. each entry `i` in order:
///    a. `prev` equals anchor / previous entry hash → `CHAIN_BROKEN`
///    b. sender has a verified identity → `UNKNOWN_SENDER`
///    c. ML-DSA signature under sender key → `BAD_SIGNATURE`
///    d. timestamp within sender validity window → `IDENTITY_EXPIRED`
///    e. per-sender `seq` strictly increasing within the window → `SEQ_REPLAY`
/// 3. optional expected head → `HEAD_MISMATCH`
///
/// # Errors
/// The first failing check.
pub fn verify_entries(
    root: &PublicKey,
    identities: &[IdentityDocument],
    entries: &[SignedManifest],
    opts: &VerifyOptions,
) -> Result<TraceReport> {
    let mut known: HashMap<AgentId, &IdentityDocument> = HashMap::new();
    for doc in identities {
        doc.verify(root)?;
        if known.insert(doc.agent_id(), doc).is_some() {
            return Err(Error::DuplicateIdentity(doc.agent_id()));
        }
    }

    let (mut expected_prev, anchored) = match opts.anchor {
        Anchor::Genesis => (Some(Hash32::ZERO), true),
        Anchor::Hash(h) => (Some(h), true),
        Anchor::Unanchored => (None, false),
    };
    let mut last_seq: HashMap<AgentId, u64> = HashMap::new();
    let mut out = Vec::with_capacity(entries.len());

    for (index, e) in entries.iter().enumerate() {
        let b = e.body();
        if let Some(p) = expected_prev {
            if !b.prev.ct_eq(&p) {
                return Err(Error::ChainBroken { index });
            }
        }
        let doc = known.get(&b.sender).ok_or(Error::UnknownSender {
            index,
            sender: b.sender,
        })?;
        if !doc
            .public_key()
            .verify(e.body_bytes(), CTX_MANIFEST, &e.signature()[..])
        {
            return Err(Error::BadSignature { index });
        }
        if !doc.is_valid_at(b.timestamp_ms) {
            return Err(Error::IdentityExpired { index });
        }
        if let Some(prev_seq) = last_seq.get(&b.sender) {
            if b.seq <= *prev_seq {
                return Err(Error::SeqReplay { index });
            }
        }
        last_seq.insert(b.sender, b.seq);
        let h = e.entry_hash();
        out.push(EntryReport {
            index,
            entry_hash: h,
            sender: b.sender,
            sender_name: doc.claims().name.clone(),
            kind: b.kind,
            seq: b.seq,
        });
        expected_prev = Some(h);
    }

    let head = expected_prev.unwrap_or(Hash32::ZERO);
    if let Some(want) = opts.expected_head {
        if !head.ct_eq(&want) {
            return Err(Error::HeadMismatch);
        }
    }
    Ok(TraceReport {
        entries: out,
        head,
        anchored,
    })
}

/// A self-contained, portable bundle of identity documents and trace entries.
#[derive(Clone, Debug, Default)]
pub struct Transcript {
    /// Identity documents for every sender.
    pub identities: Vec<IdentityDocument>,
    /// Trace entries in order.
    pub entries: Vec<SignedManifest>,
}

impl Transcript {
    /// Canonical encoding.
    ///
    /// # Errors
    /// [`Error::InvalidField`] if limits are exceeded.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.identities.len() > MAX_IDENTITIES {
            return Err(Error::InvalidField("too many identities"));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(Error::InvalidField("too many entries"));
        }
        let mut w = Writer::new();
        w.bytes(MAGIC);
        w.u8(VERSION);
        w.u16(self.identities.len() as u16);
        for d in &self.identities {
            put_item(&mut w, &d.encode())?;
        }
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            put_item(&mut w, &e.encode())?;
        }
        Ok(w.into_vec())
    }

    /// Strictly decode (does not verify).
    ///
    /// # Errors
    /// [`Error::Decode`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.magic(MAGIC, VERSION)?;
        let n_ids = r.u16()? as usize;
        if n_ids > MAX_IDENTITIES {
            return Err(Error::Decode("too many identities"));
        }
        let mut identities = Vec::new();
        for _ in 0..n_ids {
            identities.push(IdentityDocument::decode(get_item(&mut r)?)?);
        }
        let n_entries = r.u32()? as usize;
        if n_entries > MAX_ENTRIES {
            return Err(Error::Decode("too many entries"));
        }
        let mut entries = Vec::new();
        for _ in 0..n_entries {
            entries.push(SignedManifest::decode(get_item(&mut r)?)?);
        }
        r.finish()?;
        Ok(Self {
            identities,
            entries,
        })
    }

    /// Verify the whole transcript (or the window `entries[from..]`).
    ///
    /// # Errors
    /// See [`verify_entries`].
    pub fn verify(
        &self,
        root: &PublicKey,
        from: usize,
        opts: &VerifyOptions,
    ) -> Result<TraceReport> {
        let window = self
            .entries
            .get(from..)
            .ok_or(Error::Decode("from beyond end"))?;
        verify_entries(root, &self.identities, window, opts)
    }
}

fn put_item(w: &mut Writer, item: &[u8]) -> Result<()> {
    if item.is_empty() || item.len() > MAX_ITEM_LEN {
        return Err(Error::InvalidField("item length"));
    }
    w.u32(item.len() as u32);
    w.bytes(item);
    Ok(())
}

fn get_item<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let len = r.u32()? as usize;
    if len == 0 || len > MAX_ITEM_LEN {
        return Err(Error::Decode("item length out of range"));
    }
    r.take(len)
}

/// Builds a trace by appending signed entries, managing `prev` and `seq`.
#[derive(Debug, Default)]
pub struct TraceBuilder {
    entries: Vec<SignedManifest>,
    head: Hash32,
    next_seq: HashMap<AgentId, u64>,
}

/// Parameters for one appended entry.
#[derive(Clone, Debug)]
pub struct EntrySpec {
    /// Kind.
    pub kind: ManifestKind,
    /// Recipient.
    pub recipient: Recipient,
    /// Intent summary.
    pub intent: String,
    /// Optional payload digest.
    pub payload_hash: Option<Hash32>,
    /// Timestamp (unix ms).
    pub timestamp_ms: u64,
}

impl TraceBuilder {
    /// Start a new trace at genesis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resume from existing entries (which the caller should already have
    /// verified). Restores `head` and per-sender sequence counters.
    #[must_use]
    pub fn resume(entries: Vec<SignedManifest>) -> Self {
        let mut s = Self::new();
        for e in &entries {
            let b = e.body();
            let n = s.next_seq.entry(b.sender).or_insert(0);
            *n = (*n).max(b.seq.saturating_add(1));
            s.head = e.entry_hash();
        }
        s.entries = entries;
        s
    }

    /// Sign and append an entry from `key`.
    ///
    /// # Errors
    /// Encoding or signing errors.
    pub fn append(
        &mut self,
        key: &AgentKeypair,
        spec: EntrySpec,
        mode: SigningMode,
    ) -> Result<&SignedManifest> {
        let sender = key.agent_id();
        let seq = self.next_seq.get(&sender).copied().unwrap_or(0);
        let body = ManifestBody {
            kind: spec.kind,
            sender,
            recipient: spec.recipient,
            seq,
            timestamp_ms: spec.timestamp_ms,
            prev: self.head,
            intent: spec.intent,
            payload_hash: spec.payload_hash,
        };
        let m = SignedManifest::sign(body, key, mode)?;
        self.head = m.entry_hash();
        self.next_seq.insert(sender, seq.saturating_add(1));
        self.entries.push(m);
        self.entries
            .last()
            .ok_or(Error::InvalidField("empty trace"))
    }

    /// Current head hash (zero at genesis).
    #[must_use]
    pub fn head(&self) -> Hash32 {
        self.head
    }
    /// Entries so far.
    #[must_use]
    pub fn entries(&self) -> &[SignedManifest] {
        &self.entries
    }
    /// Consume into entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<SignedManifest> {
        self.entries
    }
}
