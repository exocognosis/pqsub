//! Error type shared by every operation in the crate.
//!
//! Each verification failure maps to a stable machine-readable [`Error::code`].
//! The independent verifier (`pqsub-verify`) emits the same codes in the same
//! check order, which lets the two implementations be compared exactly.

use crate::hash::AgentId;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors produced by `pqsub-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Bytes are not a canonical encoding of the expected structure.
    #[error("decode error: {0}")]
    Decode(&'static str),
    /// A value supplied when *constructing* a structure violates a format limit.
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    /// An identity document failed verification against the trust anchor.
    #[error("identity document invalid: {0}")]
    IdentityInvalid(&'static str),
    /// Two identity documents claim the same agent id.
    #[error("duplicate identity document for agent {0}")]
    DuplicateIdentity(AgentId),
    /// A manifest's sender has no verified identity document.
    #[error("entry {index}: unknown sender {sender}")]
    UnknownSender {
        /// Entry index within the verified window.
        index: usize,
        /// The claimed sender.
        sender: AgentId,
    },
    /// ML-DSA signature verification failed.
    #[error("entry {index}: signature verification failed")]
    BadSignature {
        /// Entry index within the verified window.
        index: usize,
    },
    /// The `prev` field does not match the hash of the preceding entry / anchor.
    #[error("entry {index}: hash chain broken (prev mismatch)")]
    ChainBroken {
        /// Entry index within the verified window.
        index: usize,
    },
    /// Manifest timestamp falls outside the sender identity's validity window.
    #[error("entry {index}: timestamp outside sender identity validity window")]
    IdentityExpired {
        /// Entry index within the verified window.
        index: usize,
    },
    /// A sender's sequence number did not strictly increase.
    #[error("entry {index}: sequence number not strictly increasing for sender")]
    SeqReplay {
        /// Entry index within the verified window.
        index: usize,
    },
    /// The final entry hash differs from the expected head.
    #[error("trace head mismatch")]
    HeadMismatch,
    /// Attempted to sign a manifest with a key that is not the declared sender.
    #[error("signing key does not belong to manifest sender")]
    SenderMismatch,
    /// The underlying ML-DSA signer reported an error.
    #[error("signing failed")]
    Signing,
    /// OS randomness was unavailable.
    #[error("randomness unavailable")]
    Rng,
    /// A key file is readable by group/other, or otherwise unsafe.
    #[error("unsafe key file: {0}")]
    KeyFile(String),
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Stable machine-readable error code (shared with `pqsub-verify`).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Error::Decode(_) => "DECODE",
            Error::InvalidField(_) => "INVALID_FIELD",
            Error::IdentityInvalid(_) => "IDENTITY_INVALID",
            Error::DuplicateIdentity(_) => "DUPLICATE_IDENTITY",
            Error::UnknownSender { .. } => "UNKNOWN_SENDER",
            Error::BadSignature { .. } => "BAD_SIGNATURE",
            Error::ChainBroken { .. } => "CHAIN_BROKEN",
            Error::IdentityExpired { .. } => "IDENTITY_EXPIRED",
            Error::SeqReplay { .. } => "SEQ_REPLAY",
            Error::HeadMismatch => "HEAD_MISMATCH",
            Error::SenderMismatch => "SENDER_MISMATCH",
            Error::Signing => "SIGNING",
            Error::Rng => "RNG",
            Error::KeyFile(_) => "KEY_FILE",
            Error::Io(_) => "IO",
        }
    }
}
