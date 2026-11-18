//! CLI end-to-end, reproducibility and vector-drift tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_pqsub");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pqsub-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pqsub(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = pqsub(dir, args);
    assert!(
        o.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}

fn invalid(dir: &Path, args: &[&str]) -> String {
    let o = pqsub(dir, args);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{args:?} should be INVALID: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    String::from_utf8(o.stderr).unwrap()
}

#[test]
fn committed_vectors_match_regeneration() {
    let committed = std::fs::read_to_string(repo().join("test-vectors/vectors.json")).unwrap();
    let fresh = pqsub_cli::vectors::to_json(&pqsub_cli::vectors::generate().unwrap()).unwrap();
    assert!(
        committed == fresh,
        "test-vectors/vectors.json is stale: run `cargo run -p pqsub-cli -- gen-vectors`"
    );
}

#[test]
fn core_agrees_with_every_committed_vector() {
    let json = std::fs::read_to_string(repo().join("test-vectors/vectors.json")).unwrap();
    let v: pqsub_cli::vectors::Vectors = serde_json::from_str(&json).unwrap();
    for c in &v.cases {
        assert_eq!(
            pqsub_cli::vectors::core_outcome(&v.root_pk, c).unwrap(),
            c.expect,
            "case {}",
            c.name
        );
    }
}

#[test]
fn deterministic_simulation_is_reproducible_and_matches_committed_example() {
    let (a, _, _) = pqsub_cli::sim::run(true).unwrap();
    let (b, _, _) = pqsub_cli::sim::run(true).unwrap();
    let ea = a.transcript.encode().unwrap();
    assert_eq!(ea, b.transcript.encode().unwrap());
    assert_eq!(
        ea,
        std::fs::read(repo().join("examples/demo/transcript.pqst")).unwrap()
    );
    assert_eq!(
        a.text,
        std::fs::read_to_string(repo().join("examples/demo/transcript.txt")).unwrap()
    );
    // Independent verifier agrees with core on the demo transcript.
    let r = pqsub_verify::verify_transcript(
        a.root.public_key().as_bytes(),
        &ea,
        0,
        pqsub_verify::Anchor::Genesis,
        None,
    )
    .unwrap();
    assert_eq!(r.head, a.transcript.entries[5].entry_hash().0);
}

#[test]
fn hedged_simulation_verifies() {
    let (s, _, _) = pqsub_cli::sim::run(false).unwrap();
    let enc = s.transcript.encode().unwrap();
    pqsub_verify::verify_transcript(
        s.root.public_key().as_bytes(),
        &enc,
        0,
        pqsub_verify::Anchor::Genesis,
        None,
    )
    .unwrap();
}

#[test]
fn end_to_end_cli_workflow() {
    let d = tmpdir("e2e");
    ok(
        &d,
        &["root-init", "--keys", "keys", "--pub-out", "root.pub"],
    );
    ok(
        &d,
        &[
            "agent-new",
            "--keys",
            "keys",
            "--name",
            "alice",
            "--role",
            "planner",
            "--out",
            "alice.id",
        ],
    );
    ok(
        &d,
        &[
            "agent-new",
            "--keys",
            "keys",
            "--name",
            "bob",
            "--role",
            "executor",
            "--out",
            "bob.id",
        ],
    );
    std::fs::write(d.join("task.txt"), b"deploy v1.2 to staging").unwrap();

    // Standalone handoff.
    ok(
        &d,
        &[
            "sign",
            "--key",
            "keys/alice.key",
            "--to-agent",
            "bob.id",
            "--intent",
            "deploy to staging",
            "--payload",
            "task.txt",
            "--out",
            "h.pqsm",
        ],
    );
    let out = ok(
        &d,
        &[
            "verify",
            "--root",
            "root.pub",
            "--identity",
            "alice.id",
            "h.pqsm",
            "--payload",
            "task.txt",
        ],
    );
    assert!(out.starts_with("VALID"));
    assert!(invalid(
        &d,
        &[
            "verify",
            "--root",
            "root.pub",
            "--identity",
            "bob.id",
            "h.pqsm"
        ]
    )
    .contains("UNKNOWN_SENDER"));
    std::fs::write(d.join("other.txt"), b"deploy v6.6 to prod").unwrap();
    assert!(invalid(
        &d,
        &[
            "verify",
            "--root",
            "root.pub",
            "--identity",
            "alice.id",
            "h.pqsm",
            "--payload",
            "other.txt"
        ]
    )
    .contains("PAYLOAD_MISMATCH"));
    let mut m = std::fs::read(d.join("h.pqsm")).unwrap();
    let n = m.len();
    m[n - 1000] ^= 0x10;
    std::fs::write(d.join("h_bad.pqsm"), &m).unwrap();
    assert!(invalid(
        &d,
        &[
            "verify",
            "--root",
            "root.pub",
            "--identity",
            "alice.id",
            "h_bad.pqsm"
        ]
    )
    .contains("BAD_SIGNATURE"));

    // Trace.
    ok(
        &d,
        &[
            "append",
            "--root",
            "root.pub",
            "--transcript",
            "t.pqst",
            "--key",
            "keys/alice.key",
            "--identity",
            "alice.id",
            "--to-agent",
            "bob.id",
            "--intent",
            "deploy",
        ],
    );
    ok(
        &d,
        &[
            "append",
            "--root",
            "root.pub",
            "--transcript",
            "t.pqst",
            "--key",
            "keys/bob.key",
            "--identity",
            "bob.id",
            "--kind",
            "tool-auth",
            "--to-role",
            "deployer",
            "--intent",
            "run deploy script",
        ],
    );
    let out = ok(
        &d,
        &[
            "append",
            "--root",
            "root.pub",
            "--transcript",
            "t.pqst",
            "--key",
            "keys/bob.key",
            "--identity",
            "bob.id",
            "--kind",
            "action",
            "--to-agent",
            "alice.id",
            "--intent",
            "deployed",
        ],
    );
    assert!(out.contains("seq=1"));
    let out = ok(&d, &["verify-trace", "--root", "root.pub", "t.pqst"]);
    assert!(out.contains("VALID  3 entries  anchored=true"));
    let head = out.trim().rsplit("head=").next().unwrap().to_string();
    ok(
        &d,
        &[
            "verify-trace",
            "--root",
            "root.pub",
            "t.pqst",
            "--expect-head",
            &head,
        ],
    );
    let suffix = ok(
        &d,
        &[
            "verify-trace",
            "--root",
            "root.pub",
            "t.pqst",
            "--from",
            "1",
        ],
    );
    assert!(suffix.contains("anchored=false"));

    // A different root (attacker-controlled) must not validate the transcript.
    ok(
        &d,
        &["root-init", "--keys", "keys2", "--pub-out", "evil.pub"],
    );
    assert!(
        invalid(&d, &["verify-trace", "--root", "evil.pub", "t.pqst"]).contains("IDENTITY_INVALID")
    );

    // Independent verifier binary-equivalent check via library.
    let root = std::fs::read(d.join("root.pub")).unwrap();
    let t = std::fs::read(d.join("t.pqst")).unwrap();
    let r = pqsub_verify::verify_transcript(
        &pqsub_verify::parse_root(&root).unwrap(),
        &t,
        0,
        pqsub_verify::Anchor::Genesis,
        None,
    )
    .unwrap();
    assert_eq!(hex::encode(r.head), head);

    // Secret keys are not world-readable; overwrite refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.join("keys/alice.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(!pqsub(
        &d,
        &[
            "agent-new",
            "--keys",
            "keys",
            "--name",
            "alice",
            "--role",
            "x",
            "--out",
            "alice2.id"
        ]
    )
    .status
    .success());
    assert!(ok(&d, &["inspect", "keys/alice.key"]).contains("SECRET KEY FILE"));
    std::fs::remove_dir_all(&d).unwrap();
}
