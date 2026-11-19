//! Signed handoff / tool-authorization / action / tool-call / receipt manifests.
//!
//! v1 wire format (big-endian):
//! ```text
//! body = "PQSM" | ver u8 | kind u8 | sender[32]
//!      | recipient: 0x01 | agent_id[32]  |  0x02 | u8 len | role (utf-8, 1..=64)
//!      | seq u64 | timestamp_ms u64 | prev[32]
//!      | u16 len | intent (utf-8, 1..=1024)
//!      | payload: 0x00 | 0x01 | payload_hash[32]
//!      [v2 only, kind 4] | u8 n tool | u16 n cjson-args | u8 n (1..=8) grant_id[32]*
//!      [v2 only, kind 5] | call_ref[32] | status u8 | reason u8 | result_hash[32]
//!      [v2 only, kind 6] | target grant_id[32]                     (v2.1, §14.13)
//! manifest = body | signature[3309]
//!   ctx = "pqsub/v1/manifest" (ver 1) | "pqsub/v2/manifest" (ver 2)
//! entry_hash = SHA3-256(u8 len(d) | d | body),  d = "pqsub/v1/entry"
//! ```

use crate::caveat::valid_tool_name;
use crate::cjson;
use crate::codec::{check_str, Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::{domain_hash, AgentId, Hash32, DOMAIN_ENTRY};
use crate::identity::{IdentityDocument, MAX_LABEL_LEN};
use crate::keys::{AgentKeypair, PublicKey, SignatureBytes, SigningMode, SIGNATURE_LEN};

/// ML-DSA context string for v1 manifests.
pub const CTX_MANIFEST: &[u8] = b"pqsub/v1/manifest";
/// ML-DSA context string for v2 manifests.
pub const CTX_MANIFEST_V2: &[u8] = b"pqsub/v2/manifest";
const MAGIC: &[u8; 4] = b"PQSM";
/// Max byte length of the intent summary.
pub const MAX_INTENT_LEN: usize = 1024;
/// Max grants in a tool call's authority chain.
pub const MAX_CHAIN: usize = 8;

/// What a manifest represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ManifestKind {
    /// Delegation of a task to another agent.
    Handoff = 1,
    /// Authorization for a tool call / side-effecting action (v1 style, unenforced).
    ToolAuthorization = 2,
    /// Record of an action the sender performed.
    ActionRecord = 3,
    /// v2: a structured tool call carrying its authority chain.
    ToolCall = 4,
    /// v2: an executor-signed receipt for a tool call.
    Receipt = 5,
    /// v2.1: revocation of a grant (§14.13).
    Revocation = 6,
}

impl ManifestKind {
    fn from_u8(v: u8, version: u8) -> Result<Self> {
        match (v, version) {
            (1, _) => Ok(Self::Handoff),
            (2, _) => Ok(Self::ToolAuthorization),
            (3, _) => Ok(Self::ActionRecord),
            (4, 2) => Ok(Self::ToolCall),
            (5, 2) => Ok(Self::Receipt),
            (6, 2) => Ok(Self::Revocation),
            _ => Err(Error::Decode("unknown manifest kind")),
        }
    }
    /// Short label.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Handoff => "handoff",
            Self::ToolAuthorization => "tool-authorization",
            Self::ActionRecord => "action-record",
            Self::ToolCall => "tool-call",
            Self::Receipt => "receipt",
            Self::Revocation => "revocation",
        }
    }
}

/// Addressee of a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recipient {
    /// A specific agent.
    Agent(AgentId),
    /// Any agent holding a role (e.g. `"tool-runner"`).
    Role(String),
}

/// A structured tool call (kind 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    /// Tool name (`[a-z0-9_.-]{1,64}`).
    pub tool: String,
    /// Canonical cjson arguments (top-level object).
    pub args: Vec<u8>,
    /// Grant ids from root grant to leaf grant.
    pub chain: Vec<Hash32>,
}

/// Outcome recorded in a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptStatus {
    /// Executed successfully.
    ExecutedOk = 0,
    /// Executed; the tool reported an error.
    ExecutedError = 1,
    /// Refused by the gate.
    Refused = 2,
}

/// An executor receipt (kind 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Entry hash of the tool-call entry.
    pub call_ref: Hash32,
    /// Outcome.
    pub status: ReceiptStatus,
    /// 0 if executed; gate denial number (2..=9) if refused.
    pub reason: u8,
    /// Payload hash of the tool result (zero if refused).
    pub result_hash: Hash32,
}

/// Format-version-specific extension of a manifest body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ext {
    /// v1 manifest (kinds 1–3).
    V1,
    /// v2 manifest without extension fields (kinds 1–3).
    V2,
    /// v2 tool call (kind 4).
    ToolCall(ToolCall),
    /// v2 receipt (kind 5).
    Receipt(Receipt),
    /// v2.1 revocation (kind 6): the revoked grant id.
    Revocation(Hash32),
}

/// The signed content of a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestBody {
    /// Manifest kind (must agree with `ext`).
    pub kind: ManifestKind,
    /// Sender agent id (must equal the signer's key id).
    pub sender: AgentId,
    /// Recipient agent or role.
    pub recipient: Recipient,
    /// Per-sender sequence number (strictly increasing within a trace).
    pub seq: u64,
    /// Sender-asserted wall-clock time, unix ms.
    pub timestamp_ms: u64,
    /// Entry hash of the previous trace entry, or zero for genesis / standalone.
    pub prev: Hash32,
    /// Human/LLM-readable summary of the intent or action.
    pub intent: String,
    /// Optional digest of an out-of-band payload (see [`crate::payload_hash`]).
    pub payload_hash: Option<Hash32>,
    /// Version / kind-specific fields.
    pub ext: Ext,
}

fn validate_ext(kind: ManifestKind, ext: &Ext) -> core::result::Result<(), &'static str> {
    let basic = matches!(
        kind,
        ManifestKind::Handoff | ManifestKind::ToolAuthorization | ManifestKind::ActionRecord
    );
    match ext {
        Ext::V1 | Ext::V2 if basic => Ok(()),
        Ext::ToolCall(c) if kind == ManifestKind::ToolCall => {
            if !valid_tool_name(&c.tool) {
                return Err("tool name");
            }
            if !(1..=MAX_CHAIN).contains(&c.chain.len()) {
                return Err("grant chain length");
            }
            cjson::parse_canonical(&c.args, true)
                .map(|_| ())
                .map_err(|_| "tool args are not canonical cjson")
        }
        Ext::Receipt(r) if kind == ManifestKind::Receipt => match r.status {
            ReceiptStatus::ExecutedOk | ReceiptStatus::ExecutedError if r.reason == 0 => Ok(()),
            ReceiptStatus::Refused
                if (2..=9).contains(&r.reason) && r.result_hash == Hash32::ZERO =>
            {
                Ok(())
            }
            _ => Err("receipt status/reason/result inconsistent"),
        },
        Ext::Revocation(_) if kind == ManifestKind::Revocation => Ok(()),
        _ => Err("manifest kind does not match its extension"),
    }
}

impl ManifestBody {
    /// Wire format version (1 or 2).
    #[must_use]
    pub fn version(&self) -> u8 {
        if self.ext == Ext::V1 {
            1
        } else {
            2
        }
    }

    /// ML-DSA context string for this body's version.
    #[must_use]
    pub fn ctx(&self) -> &'static [u8] {
        if self.version() == 1 {
            CTX_MANIFEST
        } else {
            CTX_MANIFEST_V2
        }
    }

    /// Canonical body encoding.
    ///
    /// # Errors
    /// [`Error::InvalidField`] if a field is out of range.
    pub fn encode(&self) -> Result<Vec<u8>> {
        check_str(&self.intent, 1, MAX_INTENT_LEN, "intent length")?;
        validate_ext(self.kind, &self.ext).map_err(Error::InvalidField)?;
        let mut w = Writer::new();
        w.bytes(MAGIC);
        w.u8(self.version());
        w.u8(self.kind as u8);
        w.bytes(&self.sender.0);
        match &self.recipient {
            Recipient::Agent(id) => {
                w.u8(1);
                w.bytes(&id.0);
            }
            Recipient::Role(role) => {
                check_str(role, 1, MAX_LABEL_LEN, "recipient role length")?;
                w.u8(2);
                w.str_u8(role);
            }
        }
        w.u64(self.seq);
        w.u64(self.timestamp_ms);
        w.bytes(&self.prev.0);
        w.str_u16(&self.intent);
        match &self.payload_hash {
            None => w.u8(0),
            Some(h) => {
                w.u8(1);
                w.bytes(&h.0);
            }
        }
        match &self.ext {
            Ext::V1 | Ext::V2 => {}
            Ext::ToolCall(c) => {
                w.str_u8(&c.tool);
                w.u16(c.args.len() as u16);
                w.bytes(&c.args);
                w.u8(c.chain.len() as u8);
                for g in &c.chain {
                    w.bytes(&g.0);
                }
            }
            Ext::Receipt(r) => {
                w.bytes(&r.call_ref.0);
                w.u8(r.status as u8);
                w.u8(r.reason);
                w.bytes(&r.result_hash.0);
            }
            Ext::Revocation(g) => w.bytes(&g.0),
        }
        Ok(w.into_vec())
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        if &r.array::<4>()? != MAGIC {
            return Err(Error::Decode("bad magic"));
        }
        let version = r.u8()?;
        if version != 1 && version != 2 {
            return Err(Error::Decode("unsupported version"));
        }
        let kind = ManifestKind::from_u8(r.u8()?, version)?;
        let sender = AgentId(r.array()?);
        let recipient = match r.u8()? {
            1 => Recipient::Agent(AgentId(r.array()?)),
            2 => Recipient::Role(r.str_u8(1, MAX_LABEL_LEN)?),
            _ => return Err(Error::Decode("unknown recipient tag")),
        };
        let seq = r.u64()?;
        let timestamp_ms = r.u64()?;
        let prev = Hash32(r.array()?);
        let intent = r.str_u16(1, MAX_INTENT_LEN)?;
        let payload_hash = match r.u8()? {
            0 => None,
            1 => Some(Hash32(r.array()?)),
            _ => return Err(Error::Decode("invalid payload flag")),
        };
        let ext = match (version, kind) {
            (1, _) => Ext::V1,
            (_, ManifestKind::ToolCall) => {
                let tool = r.str_u8(1, 64)?;
                let n = r.u16()? as usize;
                let args = r.take(n)?.to_vec();
                let k = r.u8()? as usize;
                let chain = (0..k)
                    .map(|_| r.array().map(Hash32))
                    .collect::<Result<Vec<_>>>()?;
                Ext::ToolCall(ToolCall { tool, args, chain })
            }
            (_, ManifestKind::Receipt) => {
                let call_ref = Hash32(r.array()?);
                let status = match r.u8()? {
                    0 => ReceiptStatus::ExecutedOk,
                    1 => ReceiptStatus::ExecutedError,
                    2 => ReceiptStatus::Refused,
                    _ => return Err(Error::Decode("receipt status")),
                };
                let reason = r.u8()?;
                let result_hash = Hash32(r.array()?);
                Ext::Receipt(Receipt {
                    call_ref,
                    status,
                    reason,
                    result_hash,
                })
            }
            (_, ManifestKind::Revocation) => Ext::Revocation(Hash32(r.array()?)),
            _ => Ext::V2,
        };
        validate_ext(kind, &ext).map_err(Error::Decode)?;
        Ok(Self {
            kind,
            sender,
            recipient,
            seq,
            timestamp_ms,
            prev,
            intent,
            payload_hash,
            ext,
        })
    }
}

/// A manifest body plus the sender's ML-DSA-65 signature.
#[derive(Clone, Debug)]
pub struct SignedManifest {
    body: ManifestBody,
    body_bytes: Vec<u8>,
    signature: SignatureBytes,
}

impl SignedManifest {
    /// Sign `body` with `key`. Fails with [`Error::SenderMismatch`] unless
    /// `body.sender == key.agent_id()`.
    ///
    /// # Errors
    /// Encoding, sender-mismatch or signing errors.
    pub fn sign(body: ManifestBody, key: &AgentKeypair, mode: SigningMode) -> Result<Self> {
        if !body.sender.ct_eq(&key.agent_id()) {
            return Err(Error::SenderMismatch);
        }
        let body_bytes = body.encode()?;
        let signature = key.sign(&body_bytes, body.ctx(), mode)?;
        Ok(Self {
            body,
            body_bytes,
            signature,
        })
    }

    /// Canonical encoding: `body || signature`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.body_bytes.len() + SIGNATURE_LEN);
        v.extend_from_slice(&self.body_bytes);
        v.extend_from_slice(&self.signature[..]);
        v
    }

    /// Strictly decode (does **not** verify the signature).
    ///
    /// # Errors
    /// [`Error::Decode`] on any non-canonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let body = ManifestBody::decode_from(&mut r)?;
        let body_len = r.position();
        let sig: [u8; SIGNATURE_LEN] = r.array()?;
        r.finish()?;
        let body_bytes = bytes[..body_len].to_vec();
        // Defence in depth: the strict parser should already guarantee this.
        if body.encode().ok().as_deref() != Some(&body_bytes[..]) {
            return Err(Error::Decode("non-canonical body"));
        }
        Ok(Self {
            body,
            body_bytes,
            signature: Box::new(sig),
        })
    }

    /// Verify the signature over the exact received body bytes under `pk`
    /// (which must be the sender's key).
    ///
    /// # Errors
    /// [`Error::SenderMismatch`] or [`Error::BadSignature`] (index 0).
    pub fn verify_signature(&self, pk: &PublicKey) -> Result<()> {
        if !self.body.sender.ct_eq(&pk.agent_id()) {
            return Err(Error::SenderMismatch);
        }
        if !self.signature_valid_under(pk) {
            return Err(Error::BadSignature { index: 0 });
        }
        Ok(())
    }

    /// Raw signature check under `pk` with the version-appropriate context.
    #[must_use]
    pub fn signature_valid_under(&self, pk: &PublicKey) -> bool {
        pk.verify(&self.body_bytes, self.body.ctx(), &self.signature[..])
    }

    /// `H("pqsub/v1/entry", body)`: the value the next trace entry puts in `prev`.
    #[must_use]
    pub fn entry_hash(&self) -> Hash32 {
        Hash32(domain_hash(DOMAIN_ENTRY, &self.body_bytes))
    }

    /// Parsed body.
    #[must_use]
    pub fn body(&self) -> &ManifestBody {
        &self.body
    }
    /// Exact signed body bytes.
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }
    /// Signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
    /// Tool call fields, if kind 4.
    #[must_use]
    pub fn tool_call(&self) -> Option<&ToolCall> {
        match &self.body.ext {
            Ext::ToolCall(c) => Some(c),
            _ => None,
        }
    }
    /// Receipt fields, if kind 5.
    #[must_use]
    pub fn receipt(&self) -> Option<&Receipt> {
        match &self.body.ext {
            Ext::Receipt(r) => Some(r),
            _ => None,
        }
    }
    /// Revoked grant id, if kind 6 (§14.13).
    #[must_use]
    pub fn revocation(&self) -> Option<Hash32> {
        match &self.body.ext {
            Ext::Revocation(g) => Some(*g),
            _ => None,
        }
    }
}

/// Verify a standalone handoff: identity against `root`, then the manifest
/// against that identity.
///
/// Check order: identity ([`IdentityDocument::verify`]) → sender matches
/// identity (`UNKNOWN_SENDER`) → signature (`BAD_SIGNATURE`) → timestamp within
/// identity validity (`IDENTITY_EXPIRED`).
///
/// # Errors
/// The first failing check.
pub fn verify_handoff(
    root: &PublicKey,
    identity: &IdentityDocument,
    m: &SignedManifest,
) -> Result<()> {
    identity.verify(root)?;
    if !m.body.sender.ct_eq(&identity.agent_id()) {
        return Err(Error::UnknownSender {
            index: 0,
            sender: m.body.sender,
        });
    }
    if !m.signature_valid_under(identity.public_key()) {
        return Err(Error::BadSignature { index: 0 });
    }
    if !identity.is_valid_at(m.body.timestamp_ms) {
        return Err(Error::IdentityExpired { index: 0 });
    }
    Ok(())
}
