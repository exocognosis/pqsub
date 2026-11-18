//! # pqsub-core
//!
//! A minimal post-quantum cryptographic substrate for multi-agent systems:
//!
//! * **Identity** — ML-DSA-65 (FIPS 204) keypairs; [`AgentId`] = SHA3-256 of the
//!   public key; [`IdentityDocument`]s signed by a root/operator key.
//! * **Signed handoffs** — compact canonical [`SignedManifest`]s (handoff,
//!   tool authorization, action record).
//! * **Verifiable traces** — hash-chained manifests ([`TraceBuilder`]) bundled
//!   in a [`Transcript`] and checked by [`verify_entries`] against an
//!   externally supplied trust anchor.
//!
//! All encodings are canonical (exactly one valid byte string per value) and
//! documented in `docs/DESIGN.md`; `pqsub-verify` re-implements verification
//! independently on top of a different ML-DSA implementation.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod authz;
pub mod caveat;
pub mod cjson;
mod codec;
pub mod error;
pub mod grant;
pub mod hash;
pub mod identity;
pub mod keys;
pub mod keystore;
pub mod manifest;
pub mod trace;

pub use authz::{
    audit, check_authorization, receipt_ext, AuditReport, Denial, Finding, Gate, Outcome,
};
pub use caveat::{Caveat, CaveatKind, Scope};
pub use error::{Error, Result};
pub use grant::{Grant, GrantSpec, CTX_GRANT};
pub use hash::{payload_hash, AgentId, Hash32};
pub use identity::{IdentityClaims, IdentityDocument, CTX_IDENTITY};
pub use keys::{AgentKeypair, PublicKey, SigningMode, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN};
pub use keystore::{FileKeyStore, KeyStore, MemoryKeyStore};
pub use manifest::{
    verify_handoff, Ext, ManifestBody, ManifestKind, Receipt, ReceiptStatus, Recipient,
    SignedManifest, ToolCall, CTX_MANIFEST, CTX_MANIFEST_V2,
};
pub use trace::{
    verify_entries, Anchor, EntrySpec, TraceBuilder, TraceReport, Transcript, VerifyOptions,
};
