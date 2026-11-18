//! Delegation grants (V2_DESIGN §4.1, §14.5).
//!
//! ```text
//! body = "PQSG" | 0x01 | issuer[32] | audience[32] | parent[32]
//!      | not_before_ms u64 | not_after_ms u64 | depth u8 | nonce[16]
//!      | u8 n (0..=32) | caveat*
//! grant = body | sig[3309]   ML-DSA-65(issuer, body, ctx "pqsub/v2/grant")
//! grant_id = H("pqsub/v2/grant-id", body)
//! ```

use crate::caveat::{Caveat, CaveatKind};
use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::{domain_hash, AgentId, Hash32};
use crate::keys::{AgentKeypair, PublicKey, SignatureBytes, SigningMode, SIGNATURE_LEN};

/// ML-DSA context string for grants.
pub const CTX_GRANT: &[u8] = b"pqsub/v2/grant";
/// Hash domain for grant ids.
pub const DOMAIN_GRANT_ID: &[u8] = b"pqsub/v2/grant-id";
const MAGIC: &[u8; 4] = b"PQSG";
const VERSION: u8 = 1;
/// Max caveats per grant.
pub const MAX_CAVEATS: usize = 32;

/// The content of a grant (everything except the issuer, which is the signer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantSpec {
    /// Delegatee.
    pub audience: AgentId,
    /// Parent grant id, or zero for a root grant.
    pub parent: Hash32,
    /// Validity start (unix ms, inclusive).
    pub not_before_ms: u64,
    /// Validity end (unix ms, inclusive).
    pub not_after_ms: u64,
    /// Remaining re-delegation depth.
    pub depth: u8,
    /// Uniqueness nonce.
    pub nonce: [u8; 16],
    /// Restrictions.
    pub caveats: Vec<Caveat>,
}

fn validate(spec: &GrantSpec) -> core::result::Result<(), &'static str> {
    if spec.not_before_ms > spec.not_after_ms {
        return Err("grant not_before > not_after");
    }
    if spec.caveats.len() > MAX_CAVEATS {
        return Err("too many caveats");
    }
    let has = |f: fn(&CaveatKind) -> bool| spec.caveats.iter().any(|c| f(&c.kind));
    if has(|k| matches!(k, CaveatKind::MaxCalls(_)))
        && !has(|k| matches!(k, CaveatKind::Executor(_)))
    {
        return Err("MaxCalls requires an Executor caveat in the same grant");
    }
    Ok(())
}

/// A signed delegation grant.
#[derive(Clone, Debug)]
pub struct Grant {
    body: Vec<u8>,
    issuer: AgentId,
    spec: GrantSpec,
    signature: SignatureBytes,
    id: Hash32,
}

impl Grant {
    /// Issue (sign) a grant.
    ///
    /// # Errors
    /// [`Error::InvalidField`] or signing errors.
    pub fn issue(issuer: &AgentKeypair, spec: GrantSpec, mode: SigningMode) -> Result<Self> {
        validate(&spec).map_err(Error::InvalidField)?;
        let mut w = Writer::new();
        w.bytes(MAGIC);
        w.u8(VERSION);
        w.bytes(&issuer.agent_id().0);
        w.bytes(&spec.audience.0);
        w.bytes(&spec.parent.0);
        w.u64(spec.not_before_ms);
        w.u64(spec.not_after_ms);
        w.u8(spec.depth);
        w.bytes(&spec.nonce);
        w.u8(spec.caveats.len() as u8);
        for c in &spec.caveats {
            c.write(&mut w)?;
        }
        let body = w.into_vec();
        let signature = issuer.sign(&body, CTX_GRANT, mode)?;
        let id = Hash32(domain_hash(DOMAIN_GRANT_ID, &body));
        Ok(Self {
            body,
            issuer: issuer.agent_id(),
            spec,
            signature,
            id,
        })
    }

    /// Canonical encoding `body || signature`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.body.clone();
        v.extend_from_slice(&self.signature[..]);
        v
    }

    /// Strict decode (does not verify the signature).
    ///
    /// # Errors
    /// [`Error::Decode`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.magic(MAGIC, VERSION)?;
        let issuer = AgentId(r.array()?);
        let audience = AgentId(r.array()?);
        let parent = Hash32(r.array()?);
        let not_before_ms = r.u64()?;
        let not_after_ms = r.u64()?;
        let depth = r.u8()?;
        let nonce: [u8; 16] = r.array()?;
        let n = r.u8()? as usize;
        if n > MAX_CAVEATS {
            return Err(Error::Decode("too many caveats"));
        }
        let caveats = (0..n)
            .map(|_| Caveat::read(&mut r))
            .collect::<Result<Vec<_>>>()?;
        let body_len = r.position();
        let sig: [u8; SIGNATURE_LEN] = r.array()?;
        r.finish()?;
        let spec = GrantSpec {
            audience,
            parent,
            not_before_ms,
            not_after_ms,
            depth,
            nonce,
            caveats,
        };
        validate(&spec).map_err(Error::Decode)?;
        let body = bytes[..body_len].to_vec();
        let id = Hash32(domain_hash(DOMAIN_GRANT_ID, &body));
        Ok(Self {
            body,
            issuer,
            spec,
            signature: Box::new(sig),
            id,
        })
    }

    /// Verify the signature under `pk` (which must be the issuer's key).
    #[must_use]
    pub fn verify_signature(&self, pk: &PublicKey) -> bool {
        pk.agent_id().ct_eq(&self.issuer) && pk.verify(&self.body, CTX_GRANT, &self.signature[..])
    }

    /// Whether `t_ms` is within the validity window.
    #[must_use]
    pub fn is_valid_at(&self, t_ms: u64) -> bool {
        self.spec.not_before_ms <= t_ms && t_ms <= self.spec.not_after_ms
    }

    /// Grant id.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        self.id
    }
    /// Issuer agent id.
    #[must_use]
    pub fn issuer(&self) -> AgentId {
        self.issuer
    }
    /// Content.
    #[must_use]
    pub fn spec(&self) -> &GrantSpec {
        &self.spec
    }
}
