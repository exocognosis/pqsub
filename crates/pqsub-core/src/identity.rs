//! Agent identity documents, issued (signed) by a root / operator key.
//!
//! Wire format (v1, big-endian):
//! ```text
//! body = "PQSI" | 0x01 | agent_id[32] | public_key[1952]
//!      | u8 len | name (utf-8, 1..=64) | u8 len | role (utf-8, 1..=64)
//!      | not_before_ms u64 | not_after_ms u64        (not_before <= not_after)
//!      | issuer_id[32]
//! doc  = body | signature[3309]   ML-DSA-65, ctx = "pqsub/v1/identity", msg = body
//! ```

use crate::codec::{check_str, Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::AgentId;
use crate::keys::{
    AgentKeypair, PublicKey, SignatureBytes, SigningMode, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

/// ML-DSA context string for identity documents.
pub const CTX_IDENTITY: &[u8] = b"pqsub/v1/identity";
const MAGIC: &[u8; 4] = b"PQSI";
const VERSION: u8 = 1;
/// Max byte length of `name` and `role`.
pub const MAX_LABEL_LEN: usize = 64;

/// Human-meaningful claims bound to a key by the issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityClaims {
    /// Display name, e.g. `"planner"`.
    pub name: String,
    /// Role, e.g. `"orchestrator"`.
    pub role: String,
    /// Start of validity (unix ms, inclusive).
    pub not_before_ms: u64,
    /// End of validity (unix ms, inclusive).
    pub not_after_ms: u64,
}

impl IdentityClaims {
    fn validate(&self) -> Result<()> {
        check_str(&self.name, 1, MAX_LABEL_LEN, "name length")?;
        check_str(&self.role, 1, MAX_LABEL_LEN, "role length")?;
        if self.not_before_ms > self.not_after_ms {
            return Err(Error::InvalidField("not_before > not_after"));
        }
        Ok(())
    }
}

/// A signed identity document binding an [`AgentId`] + public key to claims.
#[derive(Clone, Debug)]
pub struct IdentityDocument {
    body: Vec<u8>,
    agent_id: AgentId,
    public_key: PublicKey,
    claims: IdentityClaims,
    issuer_id: AgentId,
    signature: SignatureBytes,
}

impl IdentityDocument {
    /// Issue (sign) an identity for `subject` using the root/operator key `issuer`.
    ///
    /// # Errors
    /// [`Error::InvalidField`] for out-of-range claims; signing errors.
    pub fn issue(
        issuer: &AgentKeypair,
        subject: &PublicKey,
        claims: IdentityClaims,
        mode: SigningMode,
    ) -> Result<Self> {
        Self::issue_with_agent_id(issuer, subject.agent_id(), subject, claims, mode)
    }

    /// Like [`Self::issue`] but with an arbitrary `agent_id`. Only for building
    /// negative test vectors (a document whose id does not match its key).
    ///
    /// # Errors
    /// As [`Self::issue`].
    #[doc(hidden)]
    pub fn issue_with_agent_id(
        issuer: &AgentKeypair,
        agent_id: AgentId,
        subject: &PublicKey,
        claims: IdentityClaims,
        mode: SigningMode,
    ) -> Result<Self> {
        claims.validate()?;
        let issuer_id = issuer.agent_id();
        let mut w = Writer::new();
        w.bytes(MAGIC);
        w.u8(VERSION);
        w.bytes(&agent_id.0);
        w.bytes(subject.as_bytes());
        w.str_u8(&claims.name);
        w.str_u8(&claims.role);
        w.u64(claims.not_before_ms);
        w.u64(claims.not_after_ms);
        w.bytes(&issuer_id.0);
        let body = w.into_vec();
        let signature = issuer.sign(&body, CTX_IDENTITY, mode)?;
        Ok(Self {
            body,
            agent_id,
            public_key: subject.clone(),
            claims,
            issuer_id,
            signature,
        })
    }

    /// Canonical encoding: `body || signature`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.body.len() + SIGNATURE_LEN);
        v.extend_from_slice(&self.body);
        v.extend_from_slice(&self.signature[..]);
        v
    }

    /// Strictly decode a document (does **not** verify it; call [`Self::verify`]).
    ///
    /// # Errors
    /// [`Error::Decode`] on any non-canonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.magic(MAGIC, VERSION)?;
        let agent_id = AgentId(r.array()?);
        let pk_bytes = r.take(PUBLIC_KEY_LEN)?;
        let name = r.str_u8(1, MAX_LABEL_LEN)?;
        let role = r.str_u8(1, MAX_LABEL_LEN)?;
        let not_before_ms = r.u64()?;
        let not_after_ms = r.u64()?;
        if not_before_ms > not_after_ms {
            return Err(Error::Decode("not_before > not_after"));
        }
        let issuer_id = AgentId(r.array()?);
        let body_len = r.position();
        let sig: [u8; SIGNATURE_LEN] = r.array()?;
        r.finish()?;
        let public_key = PublicKey::from_bytes(pk_bytes)?;
        Ok(Self {
            body: bytes[..body_len].to_vec(),
            agent_id,
            public_key,
            claims: IdentityClaims {
                name,
                role,
                not_before_ms,
                not_after_ms,
            },
            issuer_id,
            signature: Box::new(sig),
        })
    }

    /// Verify this document against the trust anchor `root`.
    ///
    /// Check order (mirrored by `pqsub-verify`):
    /// 1. `issuer_id == AgentId(root)`
    /// 2. ML-DSA signature over the body under `root`, ctx `pqsub/v1/identity`
    /// 3. `agent_id == AgentId(public_key)`
    ///
    /// # Errors
    /// [`Error::IdentityInvalid`].
    pub fn verify(&self, root: &PublicKey) -> Result<()> {
        if !self.issuer_id.ct_eq(&root.agent_id()) {
            return Err(Error::IdentityInvalid("issuer is not the trust anchor"));
        }
        if !root.verify(&self.body, CTX_IDENTITY, &self.signature[..]) {
            return Err(Error::IdentityInvalid("bad issuer signature"));
        }
        if !self.agent_id.ct_eq(&self.public_key.agent_id()) {
            return Err(Error::IdentityInvalid("agent id does not match public key"));
        }
        Ok(())
    }

    /// Whether `ts_ms` lies within `[not_before_ms, not_after_ms]`.
    #[must_use]
    pub fn is_valid_at(&self, ts_ms: u64) -> bool {
        self.claims.not_before_ms <= ts_ms && ts_ms <= self.claims.not_after_ms
    }

    /// Claimed agent id.
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }
    /// Subject public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    /// Claims.
    #[must_use]
    pub fn claims(&self) -> &IdentityClaims {
        &self.claims
    }
    /// Issuer agent id.
    #[must_use]
    pub fn issuer_id(&self) -> AgentId {
        self.issuer_id
    }
}
