//! Domain-separated SHA3-256 hashing and the 32-byte identifier types.

use core::fmt;
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Domain tag for deriving an [`AgentId`] from a public key.
pub const DOMAIN_AGENT_ID: &[u8] = b"pqsub/v1/agent-id";
/// Domain tag for trace entry hashes.
pub const DOMAIN_ENTRY: &[u8] = b"pqsub/v1/entry";
/// Domain tag for payload digests.
pub const DOMAIN_PAYLOAD: &[u8] = b"pqsub/v1/payload";

/// `SHA3-256( u8(len(domain)) || domain || data )`.
#[must_use]
pub fn domain_hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    // Domains are compile-time constants well under 255 bytes.
    h.update([domain.len() as u8]);
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

macro_rules! id32 {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// All-zero value.
            pub const ZERO: Self = Self([0u8; 32]);

            /// Constant-time equality (use on all verification paths).
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> bool {
                bool::from(self.0.ct_eq(&other.0))
            }

            /// Lowercase hex encoding.
            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse from exactly 64 hex characters.
            ///
            /// # Errors
            /// [`Error::Decode`] on bad hex or wrong length.
            pub fn from_hex(s: &str) -> Result<Self> {
                let v = hex::decode(s.trim()).map_err(|_| Error::Decode("invalid hex"))?;
                let a: [u8; 32] = v.try_into().map_err(|_| Error::Decode("expected 32 bytes"))?;
                Ok(Self(a))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), &self.to_hex()[..16])
            }
        }
    };
}

id32!(
    /// A 32-byte SHA3-256 digest.
    Hash32
);
id32!(
    /// Agent identifier: `H("pqsub/v1/agent-id", ml_dsa_65_public_key)`.
    AgentId
);

/// Digest of an arbitrary payload for inclusion in a manifest.
#[must_use]
pub fn payload_hash(payload: &[u8]) -> Hash32 {
    Hash32(domain_hash(DOMAIN_PAYLOAD, payload))
}
