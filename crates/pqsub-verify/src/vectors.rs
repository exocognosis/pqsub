//! Check the shared JSON test vectors with this independent implementation.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use serde::Deserialize;

use crate::{hd, parse_anchor, parse_h32, verify_transcript, D_AGENT_ID};

#[derive(Deserialize)]
struct File {
    format: String,
    root_pk: String,
    keygen: Vec<Keygen>,
    signatures: Vec<Sig>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Keygen {
    seed: String,
    public_key: String,
    agent_id: String,
}

#[derive(Deserialize)]
struct Sig {
    seed: String,
    rnd: String,
    ctx: String,
    msg: String,
    signature: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    root_pk: Option<String>,
    transcript: String,
    from: usize,
    anchor: String,
    #[serde(default)]
    expected_head: Option<String>,
    expect: Expect,
}

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    head: Option<String>,
    #[serde(default)]
    entry_hashes: Vec<String>,
    #[serde(default)]
    agent_ids: Vec<String>,
}

/// Outcome of running every vector.
#[derive(Debug, Default)]
pub struct Summary {
    /// Number of passing checks.
    pub passed: usize,
    /// Descriptions of failing checks.
    pub failures: Vec<String>,
}

fn h(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| e.to_string())
}

fn seed32(s: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(h(s)?).map_err(|_| "expected 32 bytes".to_string())
}

/// Run all vectors in `json`.
///
/// # Errors
/// Only if the file itself is malformed.
pub fn run(json: &str) -> Result<Summary, String> {
    let f: File = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if f.format != "pqsub-test-vectors/v1" {
        return Err(format!("unsupported vector format {}", f.format));
    }
    let mut s = Summary::default();
    let mut check = |ok: bool, what: String| {
        if ok {
            s.passed += 1;
        } else {
            s.failures.push(what);
        }
    };

    for k in &f.keygen {
        let (pk, _sk) = ml_dsa_65::KG::keygen_from_seed(&seed32(&k.seed)?);
        let pkb = pk.into_bytes();
        check(
            hex::encode(pkb) == k.public_key,
            format!("keygen {}: public key", &k.seed[..8]),
        );
        check(
            hex::encode(hd(D_AGENT_ID, &pkb)) == k.agent_id,
            format!("keygen {}: agent id", &k.seed[..8]),
        );
    }

    for v in &f.signatures {
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed32(&v.seed)?);
        let (msg, ctx) = (h(&v.msg)?, h(&v.ctx)?);
        let sig = sk
            .try_sign_with_seed(&seed32(&v.rnd)?, &msg, &ctx)
            .map_err(str::to_string)?;
        check(
            hex::encode(sig) == v.signature,
            format!("signature rnd={}: byte-identical", &v.rnd[..8]),
        );
        let want = <[u8; crate::SIG_LEN]>::try_from(h(&v.signature)?)
            .map_err(|_| "sig len".to_string())?;
        check(
            pk.verify(&msg, &want, &ctx),
            format!("signature rnd={}: verifies", &v.rnd[..8]),
        );
    }

    for c in &f.cases {
        let root = h(c.root_pk.as_deref().unwrap_or(&f.root_pk))?;
        let tr = h(&c.transcript)?;
        let anchor = parse_anchor(&c.anchor).map_err(|e| e.detail)?;
        let eh = c
            .expected_head
            .as_deref()
            .map(parse_h32)
            .transpose()
            .map_err(|e| e.detail)?;
        match (verify_transcript(&root, &tr, c.from, anchor, eh), &c.expect) {
            (Ok(r), e) if e.ok => {
                let hashes: Vec<String> = r.entry_hashes.iter().map(hex::encode).collect();
                let ids: Vec<String> = r.senders.iter().map(hex::encode).collect();
                let same = e.head.as_deref() == Some(hex::encode(r.head).as_str())
                    && hashes == e.entry_hashes
                    && ids == e.agent_ids;
                check(same, format!("case {}: values differ", c.name));
            }
            (Err(fl), e) if !e.ok => {
                check(
                    e.error.as_deref() == Some(fl.code),
                    format!("case {}: code {} != {:?}", c.name, fl.code, e.error),
                );
            }
            (got, _) => check(
                false,
                format!(
                    "case {}: verdict mismatch (got {:?})",
                    c.name,
                    got.map(|_| "ok")
                ),
            ),
        }
    }
    Ok(s)
}
