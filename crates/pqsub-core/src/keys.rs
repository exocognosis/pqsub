//! ML-DSA-65 (FIPS 204) key material, signing and verification.
//!
//! Secret keys are held as the 32-byte FIPS 204 seed `ξ` (wrapped in
//! [`Zeroizing`]); the expanded key is re-derived deterministically
//! (`ML-DSA.KeyGen_internal`, Algorithm 6).

use core::fmt;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey, B32,
};
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::{domain_hash, AgentId, DOMAIN_AGENT_ID};

/// Encoded ML-DSA-65 public key length (FIPS 204 Table 2).
pub const PUBLIC_KEY_LEN: usize = 1952;
/// Encoded ML-DSA-65 signature length (FIPS 204 Table 2).
pub const SIGNATURE_LEN: usize = 3309;
/// FIPS 204 key-generation seed length.
pub const SEED_LEN: usize = 32;

/// Fixed-size signature bytes (boxed to keep moves cheap).
pub type SignatureBytes = Box<[u8; SIGNATURE_LEN]>;

const PUBKEY_FILE_MAGIC: &[u8; 4] = b"PQSP";
const FORMAT_VERSION: u8 = 1;

/// How the per-signature randomness `rnd` (FIPS 204 Alg. 2) is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningMode {
    /// `rnd` drawn from the OS CSPRNG (FIPS 204 default; recommended in
    /// production for fault / side-channel resilience).
    Hedged,
    /// `rnd = 0^32` (FIPS 204 optional deterministic variant). Used for
    /// reproducible tests and test vectors.
    Deterministic,
}

/// An ML-DSA-65 public (verifying) key with its derived [`AgentId`].
#[derive(Clone)]
pub struct PublicKey {
    bytes: Box<[u8; PUBLIC_KEY_LEN]>,
    // Decoded once; holds the expanded matrix A so repeated verifies are cheap.
    vk: Box<VerifyingKey<MlDsa65>>,
    id: AgentId,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}
impl Eq for PublicKey {}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey(agent_id={})", self.id)
    }
}

impl PublicKey {
    /// Parse a raw 1952-byte encoded ML-DSA-65 public key.
    ///
    /// # Errors
    /// [`Error::Decode`] if the length is wrong.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; PUBLIC_KEY_LEN] = b
            .try_into()
            .map_err(|_| Error::Decode("public key length"))?;
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(&arr[..])
            .map_err(|_| Error::Decode("public key length"))?;
        let vk = VerifyingKey::<MlDsa65>::decode(&enc);
        let id = AgentId(domain_hash(DOMAIN_AGENT_ID, &arr));
        Ok(Self {
            bytes: Box::new(arr),
            vk: Box::new(vk),
            id,
        })
    }

    /// Raw encoded key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// `AgentId = H("pqsub/v1/agent-id", pk)`.
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        self.id
    }

    /// Verify an ML-DSA-65 signature (pure ML-DSA with context string `ctx`).
    /// Returns `false` for wrong-length or malformed signatures.
    #[must_use]
    pub fn verify(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SIGNATURE_LEN || ctx.len() > 255 {
            return false;
        }
        let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(sig) else {
            return false;
        };
        let Some(s) = Signature::<MlDsa65>::decode(&enc) else {
            return false;
        };
        self.vk.verify_with_context(msg, ctx, &s)
    }

    /// Serialize as a standalone public-key file: `"PQSP" | 0x01 | pk`.
    #[must_use]
    pub fn to_file_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(PUBKEY_FILE_MAGIC);
        w.u8(FORMAT_VERSION);
        w.bytes(&self.bytes[..]);
        w.into_vec()
    }

    /// Parse a standalone public-key file.
    ///
    /// # Errors
    /// [`Error::Decode`] on bad magic/version/length.
    pub fn from_file_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        r.magic(PUBKEY_FILE_MAGIC, FORMAT_VERSION)?;
        let pk = r.take(PUBLIC_KEY_LEN)?;
        r.finish()?;
        Self::from_bytes(pk)
    }
}

/// An agent's ML-DSA-65 signing keypair.
pub struct AgentKeypair {
    seed: Zeroizing<[u8; SEED_LEN]>,
    sk: Box<SigningKey<MlDsa65>>,
    pk: PublicKey,
}

impl fmt::Debug for AgentKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AgentKeypair(agent_id={}, secret=<redacted>)",
            self.pk.id
        )
    }
}

impl AgentKeypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if randomness is unavailable.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::fill(&mut seed[..]).map_err(|_| Error::Rng)?;
        Self::from_seed(&seed)
    }

    /// Deterministically derive a keypair from a FIPS 204 seed `ξ`.
    ///
    /// # Errors
    /// [`Error::Decode`] only if the derived public key cannot be re-parsed
    /// (should be impossible).
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self> {
        let xi = Zeroizing::new(Seed::from(*seed));
        let sk = Box::new(SigningKey::<MlDsa65>::from_seed(&xi));
        let enc = sk.expanded_key().verifying_key().encode();
        let pk = PublicKey::from_bytes(enc.as_slice())?;
        Ok(Self {
            seed: Zeroizing::new(*seed),
            sk,
            pk,
        })
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }

    /// Shorthand for `public_key().agent_id()`.
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        self.pk.id
    }

    /// Secret seed (crate-internal: only the key store may persist it).
    pub(crate) fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Sign `msg` with context string `ctx` (pure ML-DSA, FIPS 204 Alg. 2).
    ///
    /// # Errors
    /// [`Error::Rng`] (hedged mode) or [`Error::Signing`].
    pub fn sign(&self, msg: &[u8], ctx: &[u8], mode: SigningMode) -> Result<SignatureBytes> {
        match mode {
            SigningMode::Deterministic => {
                let s = self
                    .sk
                    .expanded_key()
                    .sign_deterministic(msg, ctx)
                    .map_err(|_| Error::Signing)?;
                sig_to_bytes(&s)
            }
            SigningMode::Hedged => {
                let mut rnd = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut rnd[..]).map_err(|_| Error::Rng)?;
                self.sign_with_rnd(msg, ctx, &rnd)
            }
        }
    }

    /// Sign with caller-supplied `rnd` (FIPS 204 Alg. 2 with explicit
    /// randomness). Exposed for reproducible testing of the hedged path.
    ///
    /// Builds `M' = 0x00 || len(ctx) || ctx || M` and calls `ML-DSA.Sign_internal`.
    ///
    /// # Errors
    /// [`Error::Signing`] if `ctx` exceeds 255 bytes.
    #[doc(hidden)]
    pub fn sign_with_rnd(&self, msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Result<SignatureBytes> {
        let ctx_len = u8::try_from(ctx.len()).map_err(|_| Error::Signing)?;
        let prefix = [0u8, ctx_len];
        let r = B32::from(*rnd);
        let s = self
            .sk
            .expanded_key()
            .sign_internal(&[&prefix, ctx, msg], &r);
        sig_to_bytes(&s)
    }
}

fn sig_to_bytes(s: &Signature<MlDsa65>) -> Result<SignatureBytes> {
    let enc = s.encode();
    let mut out = Box::new([0u8; SIGNATURE_LEN]);
    if enc.len() != SIGNATURE_LEN {
        return Err(Error::Signing);
    }
    out.copy_from_slice(enc.as_slice());
    Ok(out)
}
