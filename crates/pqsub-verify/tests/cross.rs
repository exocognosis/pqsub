//! Cross-implementation tests: pqsub-core (RustCrypto ml-dsa) vs pqsub-verify (fips204).

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use pqsub_core::*;
use pqsub_verify::{verify_transcript, Anchor as VAnchor};

const DET: SigningMode = SigningMode::Deterministic;
const T0: u64 = 1_000_000;

/// Tiny deterministic PRNG (splitmix64) so tests are reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn core_code(root: &PublicKey, bytes: &[u8]) -> &'static str {
    match Transcript::decode(bytes).and_then(|t| t.verify(root, 0, &VerifyOptions::default())) {
        Ok(_) => "OK",
        Err(e) => e.code(),
    }
}

fn indep_code(root: &PublicKey, bytes: &[u8]) -> &'static str {
    match verify_transcript(root.as_bytes(), bytes, 0, VAnchor::Genesis, None) {
        Ok(_) => "OK",
        Err(f) => f.code,
    }
}

fn small_transcript(n_entries: u64) -> (AgentKeypair, Vec<u8>) {
    let root = AgentKeypair::from_seed(&[1; 32]).unwrap();
    let a = AgentKeypair::from_seed(&[2; 32]).unwrap();
    let c = IdentityClaims {
        name: "a".into(),
        role: "r".into(),
        not_before_ms: T0,
        not_after_ms: T0 + 1000,
    };
    let id = IdentityDocument::issue(&root, a.public_key(), c, DET).unwrap();
    let mut tb = TraceBuilder::new();
    for i in 0..n_entries {
        let spec = EntrySpec {
            kind: ManifestKind::Handoff,
            recipient: Recipient::Role("b".into()),
            intent: format!("go {i}"),
            payload_hash: Some(payload_hash(b"p")),
            timestamp_ms: T0 + i,
        };
        tb.append(&a, spec, DET).unwrap();
    }
    let t = Transcript {
        identities: vec![id],
        entries: tb.into_entries(),
    };
    (root, t.encode().unwrap())
}

#[test]
fn shared_vectors_pass_independently() {
    let json = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/vectors.json"
    ))
    .unwrap();
    let s = pqsub_verify::vectors::run(&json).unwrap();
    assert!(s.failures.is_empty(), "{:?}", s.failures);
    assert!(s.passed >= 30);
}

#[test]
fn keygen_and_signatures_byte_identical_across_implementations() {
    let mut rng = Rng(42);
    for _ in 0..16 {
        let mut seed = [0u8; 32];
        let mut rnd = [0u8; 32];
        seed.iter_mut()
            .chain(rnd.iter_mut())
            .for_each(|b| *b = rng.next() as u8);
        let ours = AgentKeypair::from_seed(&seed).unwrap();
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
        assert_eq!(&pk.clone().into_bytes(), ours.public_key().as_bytes());
        let msg = rng.next().to_be_bytes();
        let a = ours.sign_with_rnd(&msg, CTX_MANIFEST, &rnd).unwrap();
        let b = sk.try_sign_with_seed(&rnd, &msg, CTX_MANIFEST).unwrap();
        assert_eq!(a[..], b[..]);
        let d = ours.sign(&msg, CTX_MANIFEST, DET).unwrap();
        assert_eq!(
            d[..],
            sk.try_sign_with_seed(&[0; 32], &msg, CTX_MANIFEST).unwrap()[..]
        );
    }
}

#[test]
fn hedged_signatures_cross_verify() {
    let ours = AgentKeypair::generate().unwrap();
    let pk = ml_dsa_65::PublicKey::try_from_bytes(*ours.public_key().as_bytes()).unwrap();
    let s = ours.sign(b"m", CTX_IDENTITY, SigningMode::Hedged).unwrap();
    assert!(pk.verify(b"m", &s, CTX_IDENTITY));
    assert!(!pk.verify(b"m", &s, CTX_MANIFEST));
    let (pk2, sk2) = ml_dsa_65::KG::keygen_from_seed(&[9; 32]);
    let s2 = sk2
        .try_sign_with_seed(&[3; 32], b"x", CTX_MANIFEST)
        .unwrap();
    let ours2 = PublicKey::from_bytes(&pk2.into_bytes()).unwrap();
    assert!(ours2.verify(b"x", CTX_MANIFEST, &s2));
}

#[test]
fn every_bit_flip_in_entry_rejected_identically_by_both() {
    // Exhaustive over the manifest region of a 1-identity, 1-entry transcript;
    // strided over the identity/container region.
    let (root, enc) = small_transcript(1);
    let root_pk = root.public_key();
    assert_eq!(core_code(root_pk, &enc), "OK");
    assert_eq!(indep_code(root_pk, &enc), "OK");
    let id_len = u32::from_be_bytes(enc[7..11].try_into().unwrap()) as usize;
    let entry_start = 11 + id_len + 4 + 4;
    let bits: Vec<usize> = (0..entry_start * 8)
        .step_by(29)
        .chain(entry_start * 8..enc.len() * 8)
        .collect();
    let mut by_code = std::collections::BTreeMap::new();
    for bit in bits {
        let mut t = enc.clone();
        t[bit / 8] ^= 1 << (bit % 8);
        let (a, b) = (core_code(root_pk, &t), indep_code(root_pk, &t));
        assert_ne!(a, "OK", "bit {bit} accepted by core");
        assert_eq!(a, b, "bit {bit}: core={a} independent={b}");
        *by_code.entry(a).or_insert(0usize) += 1;
    }
    eprintln!("bit-flip outcome distribution: {by_code:?}");
}

#[test]
fn random_mutations_agree() {
    let (root, enc) = small_transcript(3);
    let root_pk = root.public_key();
    let mut rng = Rng(7);
    for i in 0..400 {
        let mut t = enc.clone();
        match i % 4 {
            0 => {
                let p = rng.below(t.len());
                t[p] = rng.next() as u8;
            }
            1 => t.truncate(rng.below(t.len())),
            2 => {
                let p = rng.below(t.len());
                t.insert(p, rng.next() as u8);
            }
            _ => {
                let p = rng.below(t.len());
                t.remove(p);
            }
        }
        let (a, b) = (core_code(root_pk, &t), indep_code(root_pk, &t));
        assert_eq!(a, b, "mutation {i}: core={a} independent={b}");
    }
}
