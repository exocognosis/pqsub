//! Signed handoff / tool-authorization / action manifests.
//!
//! Wire format (v1, big-endian):
//! ```text
//! body = "PQSM" | 0x01 | kind u8 (1=handoff, 2=tool-authorization, 3=action-record)
//!      | sender[32]
//!      | recipient: 0x01 | agent_id[32]
//!      |          | 0x02 | u8 len | role (utf-8, 1..=64)
//!      | seq u64 | timestamp_ms u64 | prev[32]
//!      | u16 len | intent (utf-8, 1..=1024)
//!      | payload: 0x00 | 0x01 | payload_hash[32]
//! manifest = body | signature[3309]   ML-DSA-65, ctx = "pqsub/v1/manifest", msg = body
//! entry_hash = SHA3-256(u8 len(d) | d | body),  d = "pqsub/v1/entry"
//! ```

use crate::codec::{check_str, Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::{domain_hash, AgentId, Hash32, DOMAIN_ENTRY};
use crate::identity::{IdentityDocument, MAX_LABEL_LEN};
use crate::keys::{AgentKeypair, PublicKey, SignatureBytes, SigningMode, SIGNATURE_LEN};

/// ML-DSA context string for manifests.
pub const CTX_MANIFEST: &[u8] = b"pqsub/v1/manifest";
const MAGIC: &[u8; 4] = b"PQSM";
const VERSION: u8 = 1;
/// Max byte length of the intent summary.
pub const MAX_INTENT_LEN: usize = 1024;

/// What a manifest represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ManifestKind {
    /// Delegation of a task to another agent.
    Handoff = 1,
    /// Authorization for a tool call / side-effecting action.
    ToolAuthorization = 2,
    /// Record of an action the sender performed.
    ActionRecord = 3,
}

impl ManifestKind {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Handoff),
            2 => Ok(Self::ToolAuthorization),
            3 => Ok(Self::ActionRecord),
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

/// The signed content of a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestBody {
    /// Manifest kind.
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
}

impl ManifestBody {
    /// Canonical body encoding.
    ///
    /// # Errors
    /// [`Error::InvalidField`] if a string is out of range.
    pub fn encode(&self) -> Result<Vec<u8>> {
        check_str(&self.intent, 1, MAX_INTENT_LEN, "intent length")?;
        let mut w = Writer::new();
        w.bytes(MAGIC);
        w.u8(VERSION);
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
        Ok(w.into_vec())
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        r.magic(MAGIC, VERSION)?;
        let kind = ManifestKind::from_u8(r.u8()?)?;
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
        Ok(Self {
            kind,
            sender,
            recipient,
            seq,
            timestamp_ms,
            prev,
            intent,
            payload_hash,
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
        let signature = key.sign(&body_bytes, CTX_MANIFEST, mode)?;
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
    /// [`Error::SenderMismatch`] if `pk` is not the sender's key,
    /// [`Error::BadSignature`] (index 0) if the signature is invalid.
    pub fn verify_signature(&self, pk: &PublicKey) -> Result<()> {
        if !self.body.sender.ct_eq(&pk.agent_id()) {
            return Err(Error::SenderMismatch);
        }
        if !pk.verify(&self.body_bytes, CTX_MANIFEST, &self.signature[..]) {
            return Err(Error::BadSignature { index: 0 });
        }
        Ok(())
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
    if !identity
        .public_key()
        .verify(&m.body_bytes, CTX_MANIFEST, &m.signature[..])
    {
        return Err(Error::BadSignature { index: 0 });
    }
    if !identity.is_valid_at(m.body.timestamp_ms) {
        return Err(Error::IdentityExpired { index: 0 });
    }
    Ok(())
}
