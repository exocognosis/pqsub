//! # pqsub-verify — independent verifier
//!
//! A from-spec re-implementation of pqsub transcript verification
//! (`docs/DESIGN.md`). It shares **no code** with `pqsub-core` and uses a
//! different ML-DSA implementation (`fips204` by IntegrityChain instead of
//! RustCrypto `ml-dsa`), so agreement between the two on the test vectors is
//! evidence that the format spec — not one implementation's quirks — defines
//! validity.
//!
//! The verifier reports the same stable error codes, in the same check order,
//! as `pqsub-core`.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

/// ML-DSA-65 public key length.
pub const PK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
pub const SIG_LEN: usize = 3309;
const CTX_IDENTITY: &[u8] = b"pqsub/v1/identity";
const CTX_MANIFEST: &[u8] = b"pqsub/v1/manifest";
const CTX_MANIFEST_V2: &[u8] = b"pqsub/v2/manifest";
pub(crate) const CTX_GRANT: &[u8] = b"pqsub/v2/grant";
pub(crate) const D_GRANT_ID: &[u8] = b"pqsub/v2/grant-id";
const MAX_GRANTS: usize = 4096;
const MAX_CHAIN: u8 = 8;
pub(crate) const D_AGENT_ID: &[u8] = b"pqsub/v1/agent-id";
const D_ENTRY: &[u8] = b"pqsub/v1/entry";
const MAX_IDENTITIES: usize = 1024;
const MAX_ENTRIES: usize = 1 << 20;
const MAX_ITEM_LEN: usize = 16 * 1024;
const MAX_LABEL: usize = 64;
const MAX_INTENT: usize = 1024;

pub(crate) type H32 = [u8; 32];

/// A verification failure with a stable code (identical to `pqsub-core` codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Stable code, e.g. `"BAD_SIGNATURE"`.
    pub code: &'static str,
    /// Human-readable detail.
    pub detail: String,
}

pub(crate) fn fail<T>(code: &'static str, detail: impl Into<String>) -> Result<T, Failure> {
    Err(Failure {
        code,
        detail: detail.into(),
    })
}

/// Anchor for the first verified entry.
#[derive(Debug, Clone, Copy)]
pub enum Anchor {
    /// First `prev` must be zero.
    Genesis,
    /// First `prev` must equal this hash.
    Hash(H32),
    /// First `prev` unchecked.
    None,
}

/// Successful verification result.
#[derive(Debug, Clone)]
pub struct Report {
    /// Hash of the last verified entry (or anchor / zero).
    pub head: H32,
    /// Entry hashes of the window.
    pub entry_hashes: Vec<H32>,
    /// Sender agent ids of the window.
    pub senders: Vec<H32>,
    /// Sender names of the window.
    pub sender_names: Vec<String>,
    /// Whether the window is anchored.
    pub anchored: bool,
}

/// `SHA3-256(u8 len(d) || d || data)`.
#[must_use]
pub fn hd(domain: &[u8], data: &[u8]) -> H32 {
    let mut h = Sha3_256::new();
    h.update([domain.len() as u8]);
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

pub(crate) fn ct(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// ML-DSA-65 verification via `fips204`. Returns false on any malformed input.
#[must_use]
pub fn mldsa_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (<[u8; PK_LEN]>::try_from(pk), <[u8; SIG_LEN]>::try_from(sig)) else {
        return false;
    };
    let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk) else {
        return false;
    };
    pk.verify(msg, &sig, ctx)
}

// ------------------------------------------------------------------ parsing

pub(crate) struct Cur<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) p: usize,
}

impl<'a> Cur<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Failure> {
        let end = self.p.checked_add(n).filter(|&e| e <= self.b.len());
        match end {
            Some(e) => {
                let s = &self.b[self.p..e];
                self.p = e;
                Ok(s)
            }
            None => fail("DECODE", "truncated"),
        }
    }
    pub(crate) fn h32(&mut self) -> Result<H32, Failure> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
    pub(crate) fn be(&mut self, n: usize) -> Result<u64, Failure> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |acc, &x| (acc << 8) | u64::from(x)))
    }
    pub(crate) fn header(&mut self, magic: &[u8; 4]) -> Result<(), Failure> {
        self.header_versions(magic, 1, 1).map(|_| ())
    }
    /// Magic followed by a version byte in `lo..=hi`; returns the version.
    pub(crate) fn header_versions(
        &mut self,
        magic: &[u8; 4],
        lo: u8,
        hi: u8,
    ) -> Result<u8, Failure> {
        if self.take(4)? != magic {
            return fail("DECODE", "magic");
        }
        let v = self.u8()?;
        if v < lo || v > hi {
            return fail("DECODE", "version");
        }
        Ok(v)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, Failure> {
        let s = self.take(1)?;
        match s.first() {
            Some(&x) => Ok(x),
            None => fail("DECODE", "truncated"),
        }
    }
    /// Length-prefixed UTF-8 string with length in `min..=max`.
    pub(crate) fn str_range(
        &mut self,
        len_bytes: usize,
        min: usize,
        max: usize,
    ) -> Result<String, Failure> {
        let n = self.be(len_bytes)?;
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        if n < min || n > max {
            return fail("DECODE", "string length");
        }
        match std::str::from_utf8(self.take(n)?) {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => fail("DECODE", "utf-8"),
        }
    }
    pub(crate) fn text(&mut self, len_bytes: usize, max: usize) -> Result<String, Failure> {
        let n = self.be(len_bytes)? as usize;
        if n == 0 || n > max {
            return fail("DECODE", "string length");
        }
        match std::str::from_utf8(self.take(n)?) {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => fail("DECODE", "utf-8"),
        }
    }
    pub(crate) fn end(&self) -> Result<(), Failure> {
        if self.p == self.b.len() {
            Ok(())
        } else {
            fail("DECODE", "trailing bytes")
        }
    }
}

pub(crate) struct Ident<'a> {
    body: &'a [u8],
    pub(crate) agent_id: H32,
    pub(crate) pk: &'a [u8],
    name: String,
    pub(crate) role: String,
    nb: u64,
    na: u64,
    issuer: H32,
    sig: &'a [u8],
}

fn parse_ident(b: &[u8]) -> Result<Ident<'_>, Failure> {
    let mut c = Cur { b, p: 0 };
    c.header(b"PQSI")?;
    let agent_id = c.h32()?;
    let pk = c.take(PK_LEN)?;
    let name = c.text(1, MAX_LABEL)?;
    let role = c.text(1, MAX_LABEL)?;
    let nb = c.be(8)?;
    let na = c.be(8)?;
    if nb > na {
        return fail("DECODE", "validity window");
    }
    let issuer = c.h32()?;
    let body_end = c.p;
    let sig = c.take(SIG_LEN)?;
    c.end()?;
    Ok(Ident {
        body: &b[..body_end],
        agent_id,
        pk,
        name,
        role,
        nb,
        na,
        issuer,
        sig,
    })
}

/// Manifest recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recipient {
    Agent(H32),
    Role(String),
}

/// Kind-specific v2 manifest fields.
pub(crate) enum Ext {
    /// Kinds 1..=3.
    None,
    /// Kind 4: tool call.
    Call {
        tool: String,
        args: cjson::Value,
        chain: Vec<H32>,
    },
    /// Kind 5: receipt.
    Receipt {
        call_ref: H32,
        status: u8,
        reason: u8,
    },
}

pub(crate) struct Entry<'a> {
    body: &'a [u8],
    version: u8,
    pub(crate) sender: H32,
    pub(crate) recipient: Recipient,
    seq: u64,
    pub(crate) ts: u64,
    prev: H32,
    sig: &'a [u8],
    pub(crate) ext: Ext,
}

fn parse_entry(b: &[u8], allow_v2: bool) -> Result<Entry<'_>, Failure> {
    let mut c = Cur { b, p: 0 };
    let version = c.header_versions(b"PQSM", 1, if allow_v2 { 2 } else { 1 })?;
    let kind = c.u8()?;
    let max_kind = if version == 1 { 3 } else { 5 };
    if !(1..=max_kind).contains(&kind) {
        return fail("DECODE", "kind");
    }
    let sender = c.h32()?;
    let recipient = match c.u8()? {
        1 => Recipient::Agent(c.h32()?),
        2 => Recipient::Role(c.text(1, MAX_LABEL)?),
        _ => return fail("DECODE", "recipient tag"),
    };
    let seq = c.be(8)?;
    let ts = c.be(8)?;
    let prev = c.h32()?;
    c.text(2, MAX_INTENT)?;
    match c.u8()? {
        0 => {}
        1 => {
            c.h32()?;
        }
        _ => return fail("DECODE", "payload flag"),
    }
    let ext = match kind {
        4 => {
            let tool = caveat::tool_name(&mut c)?;
            let n = c.be(2)? as usize;
            let raw = c.take(n)?;
            let Some(args) = cjson::parse(raw, true) else {
                return fail("DECODE", "args are not canonical JSON");
            };
            let n = c.u8()?;
            if !(1..=MAX_CHAIN).contains(&n) {
                return fail("DECODE", "grant chain length");
            }
            let mut chain = Vec::with_capacity(usize::from(n));
            for _ in 0..n {
                chain.push(c.h32()?);
            }
            Ext::Call { tool, args, chain }
        }
        5 => {
            let call_ref = c.h32()?;
            let status = c.u8()?;
            let reason = c.u8()?;
            let result_hash = c.h32()?;
            let ok = match status {
                0 | 1 => reason == 0,
                2 => (2..=8).contains(&reason) && result_hash == [0u8; 32],
                _ => false,
            };
            if !ok {
                return fail("DECODE", "receipt fields");
            }
            Ext::Receipt {
                call_ref,
                status,
                reason,
            }
        }
        _ => Ext::None,
    };
    let body_end = c.p;
    let sig = c.take(SIG_LEN)?;
    c.end()?;
    Ok(Entry {
        body: &b[..body_end],
        version,
        sender,
        recipient,
        seq,
        ts,
        prev,
        sig,
        ext,
    })
}

fn item<'a>(c: &mut Cur<'a>) -> Result<&'a [u8], Failure> {
    let n = c.be(4)? as usize;
    if n == 0 || n > MAX_ITEM_LEN {
        return fail("DECODE", "item length");
    }
    c.take(n)
}

/// Accept either a `PQSP` public-key file or a raw 1952-byte key.
///
/// # Errors
/// `DECODE` on anything else.
pub fn parse_root(b: &[u8]) -> Result<Vec<u8>, Failure> {
    if b.len() == PK_LEN {
        return Ok(b.to_vec());
    }
    let mut c = Cur { b, p: 0 };
    c.header(b"PQSP")?;
    let pk = c.take(PK_LEN)?.to_vec();
    c.end()?;
    Ok(pk)
}

// ------------------------------------------------------------------ verification

/// Verified-identity map, grant map and window of a verified transcript.
pub(crate) struct Parsed<'a> {
    pub(crate) idents: HashMap<H32, &'a Ident<'a>>,
    pub(crate) grants: HashMap<H32, &'a grant::Grant<'a>>,
    pub(crate) window: &'a [Entry<'a>],
}

/// Strictly decoded transcript container (DESIGN §3 step 1, V2 §14.7).
pub(crate) struct Decoded<'a> {
    ids: Vec<Ident<'a>>,
    grants: Vec<grant::Grant<'a>>,
    entries: Vec<Entry<'a>>,
}

pub(crate) fn decode_transcript(transcript: &[u8]) -> Result<Decoded<'_>, Failure> {
    let mut c = Cur {
        b: transcript,
        p: 0,
    };
    let version = c.header_versions(b"PQST", 1, 2)?;
    let n_ids = c.be(2)? as usize;
    if n_ids > MAX_IDENTITIES {
        return fail("DECODE", "too many identities");
    }
    let mut ids = Vec::new();
    for _ in 0..n_ids {
        ids.push(parse_ident(item(&mut c)?)?);
    }
    let mut grants = Vec::new();
    if version == 2 {
        let n_grants = c.be(2)? as usize;
        if n_grants > MAX_GRANTS {
            return fail("DECODE", "too many grants");
        }
        let mut seen = HashSet::new();
        for _ in 0..n_grants {
            let g = grant::parse_grant(item(&mut c)?)?;
            if !seen.insert(g.id) {
                return fail("DECODE", "duplicate grant");
            }
            grants.push(g);
        }
    }
    let n_entries = c.be(4)? as usize;
    if n_entries > MAX_ENTRIES {
        return fail("DECODE", "too many entries");
    }
    let mut entries = Vec::new();
    for _ in 0..n_entries {
        entries.push(parse_entry(item(&mut c)?, version == 2)?);
    }
    c.end()?;
    if version == 2 && grants.is_empty() && entries.iter().all(|e| e.version == 1) {
        return fail("DECODE", "non-canonical v2 transcript (encode as v1)");
    }
    Ok(Decoded {
        ids,
        grants,
        entries,
    })
}

/// v1 trace verification (DESIGN §3) over a decoded transcript.
pub(crate) fn verify_decoded<'a>(
    root_pk: &[u8],
    d: &'a Decoded<'a>,
    from: usize,
    anchor: Anchor,
    expected_head: Option<H32>,
) -> Result<(Report, Parsed<'a>), Failure> {
    let Some(window) = d.entries.get(from..) else {
        return fail("DECODE", "from beyond end");
    };

    // 2. Identities.
    let root_id = hd(D_AGENT_ID, root_pk);
    let mut known: HashMap<H32, &Ident<'_>> = HashMap::new();
    for d in &d.ids {
        if !ct(&d.issuer, &root_id) {
            return fail(
                "IDENTITY_INVALID",
                format!("{}: issuer is not the trust anchor", d.name),
            );
        }
        if !mldsa_verify(root_pk, d.body, CTX_IDENTITY, d.sig) {
            return fail(
                "IDENTITY_INVALID",
                format!("{}: bad issuer signature", d.name),
            );
        }
        if !ct(&d.agent_id, &hd(D_AGENT_ID, d.pk)) {
            return fail(
                "IDENTITY_INVALID",
                format!("{}: agent id does not match public key", d.name),
            );
        }
        if known.insert(d.agent_id, d).is_some() {
            return fail("DUPLICATE_IDENTITY", hex::encode(d.agent_id));
        }
    }

    // 3. Entries.
    let (mut expect_prev, anchored) = match anchor {
        Anchor::Genesis => (Some([0u8; 32]), true),
        Anchor::Hash(h) => (Some(h), true),
        Anchor::None => (None, false),
    };
    let mut last_seq: HashMap<H32, u64> = HashMap::new();
    let mut rep = Report {
        head: [0; 32],
        entry_hashes: vec![],
        senders: vec![],
        sender_names: vec![],
        anchored,
    };
    for (i, e) in window.iter().enumerate() {
        if let Some(p) = expect_prev {
            if !ct(&e.prev, &p) {
                return fail("CHAIN_BROKEN", format!("entry {i}"));
            }
        }
        let Some(d) = known.get(&e.sender) else {
            return fail(
                "UNKNOWN_SENDER",
                format!("entry {i}: {}", hex::encode(e.sender)),
            );
        };
        let ctx = if e.version == 1 {
            CTX_MANIFEST
        } else {
            CTX_MANIFEST_V2
        };
        if !mldsa_verify(d.pk, e.body, ctx, e.sig) {
            return fail("BAD_SIGNATURE", format!("entry {i}"));
        }
        if e.ts < d.nb || e.ts > d.na {
            return fail("IDENTITY_EXPIRED", format!("entry {i}"));
        }
        if last_seq.get(&e.sender).is_some_and(|&s| e.seq <= s) {
            return fail("SEQ_REPLAY", format!("entry {i}"));
        }
        last_seq.insert(e.sender, e.seq);
        let h = hd(D_ENTRY, e.body);
        rep.entry_hashes.push(h);
        rep.senders.push(e.sender);
        rep.sender_names.push(d.name.clone());
        expect_prev = Some(h);
    }
    rep.head = expect_prev.unwrap_or([0u8; 32]);
    if let Some(want) = expected_head {
        if !ct(&rep.head, &want) {
            return fail("HEAD_MISMATCH", "head differs from expected");
        }
    }
    let grants = d.grants.iter().map(|g| (g.id, g)).collect();
    Ok((
        rep,
        Parsed {
            idents: known,
            grants,
            window,
        },
    ))
}

pub(crate) fn check_root_len(root_pk: &[u8]) -> Result<(), Failure> {
    if root_pk.len() != PK_LEN {
        return fail("DECODE", "root public key length");
    }
    Ok(())
}

/// Verify transcript bytes (v1 or v2 container) against `root_pk` (raw 1952
/// bytes). Only the v1 trace checks run (v2 manifests use the v2 context);
/// v2 authorization is checked by [`audit_transcript`].
///
/// # Errors
/// The first failure, with a code matching `pqsub-core`.
pub fn verify_transcript(
    root_pk: &[u8],
    transcript: &[u8],
    from: usize,
    anchor: Anchor,
    expected_head: Option<H32>,
) -> Result<Report, Failure> {
    check_root_len(root_pk)?;
    let d = decode_transcript(transcript)?;
    verify_decoded(root_pk, &d, from, anchor, expected_head).map(|(r, _)| r)
}

/// Parse an anchor string: `genesis`, `none`, or 64 hex chars.
///
/// # Errors
/// `DECODE` on bad hex.
pub fn parse_anchor(s: &str) -> Result<Anchor, Failure> {
    match s {
        "genesis" => Ok(Anchor::Genesis),
        "none" => Ok(Anchor::None),
        h => parse_h32(h).map(Anchor::Hash),
    }
}

/// Parse a 32-byte hex value.
///
/// # Errors
/// `DECODE` on bad hex.
pub fn parse_h32(h: &str) -> Result<H32, Failure> {
    match hex::decode(h.trim())
        .ok()
        .and_then(|v| <H32>::try_from(v).ok())
    {
        Some(a) => Ok(a),
        None => fail("DECODE", "expected 64 hex chars"),
    }
}

pub mod audit;
pub mod caveat;
pub mod cjson;
pub(crate) mod grant;
pub mod vectors;
pub mod vectors_v2;

pub use audit::{audit_transcript, AuditReport, Finding};
pub use caveat::caveat_eval;
pub use cjson::cjson_valid;
