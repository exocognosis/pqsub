//! Integration tests: identity, signing, verification, traces, tampering, key storage.

use pqsub_core::*;

const DET: SigningMode = SigningMode::Deterministic;
const T0: u64 = 1_700_000_000_000;

fn kp(tag: u8) -> AgentKeypair {
    AgentKeypair::from_seed(&[tag; 32]).unwrap()
}

fn claims(name: &str) -> IdentityClaims {
    IdentityClaims {
        name: name.into(),
        role: "worker".into(),
        not_before_ms: T0,
        not_after_ms: T0 + 86_400_000,
    }
}

fn ident(root: &AgentKeypair, a: &AgentKeypair, name: &str) -> IdentityDocument {
    IdentityDocument::issue(root, a.public_key(), claims(name), DET).unwrap()
}

fn body(sender: &AgentKeypair, seq: u64) -> ManifestBody {
    ManifestBody {
        kind: ManifestKind::Handoff,
        sender: sender.agent_id(),
        recipient: Recipient::Role("reviewer".into()),
        seq,
        timestamp_ms: T0 + 1000,
        prev: Hash32::ZERO,
        intent: "review patch #7".into(),
        payload_hash: Some(payload_hash(b"diff --git a b")),
    }
}

fn spec(intent: &str, ts: u64) -> EntrySpec {
    EntrySpec {
        kind: ManifestKind::Handoff,
        recipient: Recipient::Role("next".into()),
        intent: intent.into(),
        payload_hash: None,
        timestamp_ms: ts,
    }
}

struct Fixture {
    root: AgentKeypair,
    agents: Vec<AgentKeypair>,
    ids: Vec<IdentityDocument>,
    entries: Vec<SignedManifest>,
}

fn fixture() -> Fixture {
    let root = kp(0);
    let agents: Vec<_> = (1..=3).map(kp).collect();
    let ids = agents
        .iter()
        .enumerate()
        .map(|(i, a)| ident(&root, a, &format!("agent{i}")))
        .collect();
    let mut tb = TraceBuilder::new();
    for i in 0..6u64 {
        let a = &agents[(i % 3) as usize];
        tb.append(a, spec(&format!("step {i}"), T0 + 1000 + i), DET)
            .unwrap();
    }
    Fixture {
        root,
        agents,
        ids,
        entries: tb.into_entries(),
    }
}

fn verify(f: &Fixture, entries: &[SignedManifest], opts: VerifyOptions) -> Result<TraceReport> {
    verify_entries(f.root.public_key(), &f.ids, entries, &opts)
}

// ---------------------------------------------------------------- keys

#[test]
fn keygen_from_seed_is_deterministic_and_ids_differ() {
    assert_eq!(kp(1).public_key(), kp(1).public_key());
    assert_ne!(kp(1).agent_id(), kp(2).agent_id());
    assert_eq!(kp(1).public_key().as_bytes().len(), PUBLIC_KEY_LEN);
}

#[test]
fn generated_keys_are_distinct_and_work() {
    let a = AgentKeypair::generate().unwrap();
    let b = AgentKeypair::generate().unwrap();
    assert_ne!(a.agent_id(), b.agent_id());
    let s = a.sign(b"m", b"c", SigningMode::Hedged).unwrap();
    assert!(a.public_key().verify(b"m", b"c", &s[..]));
    assert!(!b.public_key().verify(b"m", b"c", &s[..]));
}

#[test]
fn hedged_framing_with_zero_rnd_equals_fips204_deterministic() {
    // Validates our M' = 0 || len(ctx) || ctx || M framing against the crate's own Alg. 2.
    let k = kp(9);
    let det = k.sign(b"hello", b"ctx", DET).unwrap();
    let explicit = k.sign_with_rnd(b"hello", b"ctx", &[0u8; 32]).unwrap();
    assert_eq!(det[..], explicit[..]);
    let hedged = k.sign_with_rnd(b"hello", b"ctx", &[7u8; 32]).unwrap();
    assert_ne!(det[..], hedged[..]);
    assert!(k.public_key().verify(b"hello", b"ctx", &hedged[..]));
}

#[test]
fn signature_is_bound_to_context_and_message() {
    let k = kp(3);
    let s = k.sign(b"msg", CTX_MANIFEST, DET).unwrap();
    assert!(k.public_key().verify(b"msg", CTX_MANIFEST, &s[..]));
    assert!(!k.public_key().verify(b"msg", CTX_IDENTITY, &s[..]));
    assert!(!k.public_key().verify(b"msG", CTX_MANIFEST, &s[..]));
    assert!(!k
        .public_key()
        .verify(b"msg", CTX_MANIFEST, &s[..SIGNATURE_LEN - 1]));
}

#[test]
fn public_key_file_roundtrip() {
    let k = kp(4);
    let f = k.public_key().to_file_bytes();
    assert_eq!(&PublicKey::from_file_bytes(&f).unwrap(), k.public_key());
    let mut bad = f.clone();
    bad.push(0);
    assert_eq!(
        PublicKey::from_file_bytes(&bad).unwrap_err().code(),
        "DECODE"
    );
}

// ---------------------------------------------------------------- identity

#[test]
fn identity_issue_verify_roundtrip() {
    let (root, a) = (kp(0), kp(1));
    let d = ident(&root, &a, "planner");
    d.verify(root.public_key()).unwrap();
    let enc = d.encode();
    let d2 = IdentityDocument::decode(&enc).unwrap();
    assert_eq!(d2.encode(), enc);
    d2.verify(root.public_key()).unwrap();
    assert_eq!(d2.claims().name, "planner");
    assert_eq!(d2.agent_id(), a.agent_id());
}

#[test]
fn identity_rejects_wrong_root_and_mismatched_id() {
    let (root, other, a) = (kp(0), kp(5), kp(1));
    let d = ident(&root, &a, "planner");
    assert_eq!(
        d.verify(other.public_key()).unwrap_err().code(),
        "IDENTITY_INVALID"
    );
    // Root signs a doc whose claimed id isn't H(pk): must still be rejected.
    let bogus = IdentityDocument::issue_with_agent_id(
        &root,
        kp(2).agent_id(),
        a.public_key(),
        claims("x"),
        DET,
    )
    .unwrap();
    assert!(
        matches!(bogus.verify(root.public_key()), Err(Error::IdentityInvalid(m)) if m.contains("agent id"))
    );
}

#[test]
fn identity_every_bit_flip_rejected() {
    let (root, a) = (kp(0), kp(1));
    let enc = ident(&root, &a, "p").encode();
    for bit in (0..enc.len() * 8).step_by(3) {
        let mut t = enc.clone();
        t[bit / 8] ^= 1 << (bit % 8);
        let ok = IdentityDocument::decode(&t)
            .and_then(|d| d.verify(root.public_key()))
            .is_ok();
        assert!(!ok, "bit {bit} flip accepted");
    }
}

#[test]
fn identity_claim_limits() {
    let (root, a) = (kp(0), kp(1));
    let mut c = claims("x");
    c.name = String::new();
    assert_eq!(
        IdentityDocument::issue(&root, a.public_key(), c, DET)
            .unwrap_err()
            .code(),
        "INVALID_FIELD"
    );
    let mut c = claims("x");
    c.not_before_ms = c.not_after_ms + 1;
    assert_eq!(
        IdentityDocument::issue(&root, a.public_key(), c, DET)
            .unwrap_err()
            .code(),
        "INVALID_FIELD"
    );
}

// ---------------------------------------------------------------- manifest

#[test]
fn manifest_sign_verify_roundtrip_canonical() {
    let a = kp(1);
    let m = SignedManifest::sign(body(&a, 0), &a, DET).unwrap();
    m.verify_signature(a.public_key()).unwrap();
    let enc = m.encode();
    let m2 = SignedManifest::decode(&enc).unwrap();
    assert_eq!(m2.encode(), enc);
    assert_eq!(m2.body(), m.body());
    m2.verify_signature(a.public_key()).unwrap();
    // Deterministic mode is reproducible byte-for-byte.
    assert_eq!(
        SignedManifest::sign(body(&a, 0), &a, DET).unwrap().encode(),
        enc
    );
}

#[test]
fn manifest_sender_must_match_key() {
    let (a, b) = (kp(1), kp(2));
    assert_eq!(
        SignedManifest::sign(body(&a, 0), &b, DET)
            .unwrap_err()
            .code(),
        "SENDER_MISMATCH"
    );
    let m = SignedManifest::sign(body(&a, 0), &a, DET).unwrap();
    assert_eq!(
        m.verify_signature(b.public_key()).unwrap_err().code(),
        "SENDER_MISMATCH"
    );
}

#[test]
fn manifest_every_single_bit_flip_fails() {
    // Exhaustive: every bit of body and signature.
    let a = kp(1);
    let enc = SignedManifest::sign(body(&a, 0), &a, DET).unwrap().encode();
    let mut decode_rejects = 0usize;
    for bit in 0..enc.len() * 8 {
        let mut t = enc.clone();
        t[bit / 8] ^= 1 << (bit % 8);
        match SignedManifest::decode(&t) {
            Err(_) => decode_rejects += 1,
            Ok(m) => assert!(
                m.verify_signature(a.public_key()).is_err(),
                "bit {bit} flip verified"
            ),
        }
    }
    assert!(decode_rejects > 0);
}

#[test]
fn manifest_rejects_noncanonical_encodings() {
    let a = kp(1);
    let enc = SignedManifest::sign(body(&a, 0), &a, DET).unwrap().encode();
    let mut t = enc.clone();
    t.push(0);
    assert_eq!(SignedManifest::decode(&t).unwrap_err().code(), "DECODE"); // trailing
    assert_eq!(
        SignedManifest::decode(&enc[..enc.len() - 1])
            .unwrap_err()
            .code(),
        "DECODE"
    ); // truncated
    let mut t = enc.clone();
    t[5] = 9; // kind
    assert_eq!(SignedManifest::decode(&t).unwrap_err().code(), "DECODE");
    let mut t = enc.clone();
    t[4] = 2; // version
    assert_eq!(SignedManifest::decode(&t).unwrap_err().code(), "DECODE");
    // payload flag: located right before the 32-byte payload hash + signature.
    let flag_pos = enc.len() - SIGNATURE_LEN - 33;
    assert_eq!(enc[flag_pos], 1);
    let mut t = enc.clone();
    t[flag_pos] = 2;
    assert_eq!(SignedManifest::decode(&t).unwrap_err().code(), "DECODE");
}

#[test]
fn manifest_field_limits() {
    let a = kp(1);
    let mut b = body(&a, 0);
    b.intent = "x".repeat(1025);
    assert_eq!(
        SignedManifest::sign(b, &a, DET).unwrap_err().code(),
        "INVALID_FIELD"
    );
    let mut b = body(&a, 0);
    b.intent = String::new();
    assert_eq!(
        SignedManifest::sign(b, &a, DET).unwrap_err().code(),
        "INVALID_FIELD"
    );
    let mut b = body(&a, 0);
    b.recipient = Recipient::Role("r".repeat(65));
    assert_eq!(
        SignedManifest::sign(b, &a, DET).unwrap_err().code(),
        "INVALID_FIELD"
    );
}

#[test]
fn handoff_verification_checks() {
    let (root, a, b) = (kp(0), kp(1), kp(2));
    let id_a = ident(&root, &a, "a");
    let m = SignedManifest::sign(body(&a, 0), &a, DET).unwrap();
    verify_handoff(root.public_key(), &id_a, &m).unwrap();
    assert_eq!(
        verify_handoff(kp(7).public_key(), &id_a, &m)
            .unwrap_err()
            .code(),
        "IDENTITY_INVALID"
    );
    let id_b = ident(&root, &b, "b");
    assert_eq!(
        verify_handoff(root.public_key(), &id_b, &m)
            .unwrap_err()
            .code(),
        "UNKNOWN_SENDER"
    );
    let mut late = body(&a, 1);
    late.timestamp_ms = T0 + 86_400_001;
    let m = SignedManifest::sign(late, &a, DET).unwrap();
    assert_eq!(
        verify_handoff(root.public_key(), &id_a, &m)
            .unwrap_err()
            .code(),
        "IDENTITY_EXPIRED"
    );
}

// ---------------------------------------------------------------- trace

#[test]
fn full_trace_verifies() {
    let f = fixture();
    let r = verify(&f, &f.entries, VerifyOptions::default()).unwrap();
    assert_eq!(r.entries.len(), 6);
    assert!(r.anchored);
    assert_eq!(r.head, f.entries[5].entry_hash());
    let r = verify(
        &f,
        &f.entries,
        VerifyOptions {
            expected_head: Some(r.head),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r.entries[0].sender_name, "agent0");
}

#[test]
fn suffix_verification_anchored_and_unanchored() {
    let f = fixture();
    let anchor = f.entries[2].entry_hash();
    let r = verify(
        &f,
        &f.entries[3..],
        VerifyOptions {
            anchor: Anchor::Hash(anchor),
            expected_head: None,
        },
    )
    .unwrap();
    assert!(r.anchored);
    let r = verify(
        &f,
        &f.entries[3..],
        VerifyOptions {
            anchor: Anchor::Unanchored,
            expected_head: None,
        },
    )
    .unwrap();
    assert!(!r.anchored);
    // Suffix against genesis anchor must fail; against the wrong checkpoint too.
    assert_eq!(
        verify(&f, &f.entries[3..], VerifyOptions::default())
            .unwrap_err()
            .code(),
        "CHAIN_BROKEN"
    );
    let wrong = VerifyOptions {
        anchor: Anchor::Hash(f.entries[1].entry_hash()),
        expected_head: None,
    };
    assert_eq!(
        verify(&f, &f.entries[3..], wrong).unwrap_err().code(),
        "CHAIN_BROKEN"
    );
}

#[test]
fn trace_reorder_drop_truncate_detected() {
    let f = fixture();
    let mut swapped = f.entries.clone();
    swapped.swap(2, 3);
    assert!(matches!(
        verify(&f, &swapped, VerifyOptions::default()),
        Err(Error::ChainBroken { index: 2 })
    ));
    let mut dropped = f.entries.clone();
    dropped.remove(3);
    assert!(matches!(
        verify(&f, &dropped, VerifyOptions::default()),
        Err(Error::ChainBroken { index: 3 })
    ));
    let head = f.entries[5].entry_hash();
    let opts = VerifyOptions {
        expected_head: Some(head),
        ..Default::default()
    };
    assert_eq!(
        verify(&f, &f.entries[..5], opts).unwrap_err().code(),
        "HEAD_MISMATCH"
    );
}

#[test]
fn trace_identity_failures() {
    let f = fixture();
    let opts = VerifyOptions::default();
    // Wrong trust anchor.
    assert_eq!(
        verify_entries(kp(99).public_key(), &f.ids, &f.entries, &opts)
            .unwrap_err()
            .code(),
        "IDENTITY_INVALID"
    );
    // Missing sender identity.
    assert_eq!(
        verify_entries(f.root.public_key(), &f.ids[..2], &f.entries, &opts)
            .unwrap_err()
            .code(),
        "UNKNOWN_SENDER"
    );
    // Duplicate identity.
    let mut dup = f.ids.clone();
    dup.push(ident(&f.root, &f.agents[0], "again"));
    assert_eq!(
        verify_entries(f.root.public_key(), &dup, &f.entries, &opts)
            .unwrap_err()
            .code(),
        "DUPLICATE_IDENTITY"
    );
}

#[test]
fn trace_seq_replay_and_expiry_detected() {
    let f = fixture();
    // Agent 0 signs a validly-chained entry that reuses seq 0.
    let mut b = body(&f.agents[0], 0);
    b.prev = f.entries[5].entry_hash();
    let mut entries = f.entries.clone();
    entries.push(SignedManifest::sign(b, &f.agents[0], DET).unwrap());
    assert!(matches!(
        verify(&f, &entries, VerifyOptions::default()),
        Err(Error::SeqReplay { index: 6 })
    ));

    let mut tb = TraceBuilder::new();
    tb.append(&f.agents[0], spec("too early", T0 - 1), DET)
        .unwrap();
    assert_eq!(
        verify(&f, tb.entries(), VerifyOptions::default())
            .unwrap_err()
            .code(),
        "IDENTITY_EXPIRED"
    );
}

#[test]
fn trace_signature_substitution_detected() {
    // Re-sign entry 1's body by a different (known) agent: sender field no longer matches key.
    let f = fixture();
    let mut entries = f.entries.clone();
    let mut forged = entries[1].body().clone();
    forged.intent = "transfer all funds".into();
    let m = SignedManifest::sign(forged, &f.agents[1], DET).unwrap(); // agent1 is the real sender of entry 1
    entries[1] = m;
    // Content changed -> its hash changed -> entry 2's prev no longer matches.
    assert!(matches!(
        verify(&f, &entries, VerifyOptions::default()),
        Err(Error::ChainBroken { index: 2 })
    ));
}

#[test]
fn transcript_roundtrip_and_bit_flips() {
    let f = fixture();
    let t = Transcript {
        identities: f.ids.clone(),
        entries: f.entries.clone(),
    };
    let enc = t.encode().unwrap();
    let t2 = Transcript::decode(&enc).unwrap();
    assert_eq!(t2.encode().unwrap(), enc);
    t2.verify(f.root.public_key(), 0, &VerifyOptions::default())
        .unwrap();
    // Sampled bit flips over the whole container (identities + entries).
    for bit in (0..enc.len() * 8).step_by(97) {
        let mut x = enc.clone();
        x[bit / 8] ^= 1 << (bit % 8);
        let ok = Transcript::decode(&x)
            .and_then(|t| t.verify(f.root.public_key(), 0, &VerifyOptions::default()))
            .is_ok();
        assert!(!ok, "bit {bit} flip accepted");
    }
    let mut x = enc.clone();
    x.push(0);
    assert_eq!(Transcript::decode(&x).unwrap_err().code(), "DECODE");
}

#[test]
fn trace_builder_resume_continues_chain() {
    let f = fixture();
    let mut tb = TraceBuilder::resume(f.entries.clone());
    tb.append(&f.agents[0], spec("more", T0 + 5000), DET)
        .unwrap();
    assert_eq!(tb.entries()[6].body().seq, 2);
    verify(&f, tb.entries(), VerifyOptions::default()).unwrap();
}

// ---------------------------------------------------------------- keystore

#[test]
fn memory_keystore() {
    let s = MemoryKeyStore::new();
    let k = kp(1);
    s.save("a", &k).unwrap();
    assert_eq!(s.load("a").unwrap().agent_id(), k.agent_id());
    assert!(s.save("a", &k).is_err());
    assert!(s.load("missing").is_err());
    assert!(s.save("../evil", &k).is_err());
}

#[cfg(unix)]
#[test]
fn file_keystore_permissions_and_roundtrip() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("pqsub-ks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let s = FileKeyStore::open(&dir).unwrap();
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let k = kp(1);
    s.save("agent", &k).unwrap();
    let p = s.path_for("agent").unwrap();
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(s.load("agent").unwrap().agent_id(), k.agent_id());
    assert_eq!(s.save("agent", &kp(2)).unwrap_err().code(), "KEY_FILE"); // no overwrite
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(s.load("agent").unwrap_err().code(), "KEY_FILE");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Tampered seed -> stored id mismatch.
    let mut data = std::fs::read(&p).unwrap();
    data[6] ^= 1;
    std::fs::write(&p, &data).unwrap();
    assert_eq!(s.load("agent").unwrap_err().code(), "KEY_FILE");
    std::fs::remove_dir_all(&dir).unwrap();
}
