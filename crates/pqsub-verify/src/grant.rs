//! Grant decoding (V2_DESIGN §4.1, §14.5).

use crate::caveat::{self, Caveat, Kind};
use crate::{fail, hd, Cur, Failure, D_GRANT_ID, H32, SIG_LEN};

const MAX_CAVEATS: u8 = 32;

pub(crate) struct Grant<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) sig: &'a [u8],
    pub(crate) id: H32,
    pub(crate) issuer: H32,
    pub(crate) audience: H32,
    pub(crate) parent: H32,
    pub(crate) nb: u64,
    pub(crate) na: u64,
    pub(crate) depth: u8,
    pub(crate) caveats: Vec<Caveat>,
}

/// Strictly decode `grant_body | sig`. The signature is not checked here.
pub(crate) fn parse_grant(b: &[u8]) -> Result<Grant<'_>, Failure> {
    let mut c = Cur::new(b);
    c.header(b"PQSG")?;
    let issuer = c.h32()?;
    let audience = c.h32()?;
    let parent = c.h32()?;
    let nb = c.be(8)?;
    let na = c.be(8)?;
    if nb > na {
        return fail("DECODE", "grant validity window");
    }
    let depth = c.u8()?;
    c.take(16)?; // nonce
    let n = c.u8()?;
    if n > MAX_CAVEATS {
        return fail("DECODE", "too many caveats");
    }
    let mut caveats = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        caveats.push(caveat::decode(&mut c)?);
    }
    let has = |f: fn(&Kind) -> bool| caveats.iter().any(|cv| f(&cv.kind));
    if has(|k| matches!(k, Kind::MaxCalls(_))) && !has(|k| matches!(k, Kind::Executor(_))) {
        return fail("DECODE", "MaxCalls without Executor");
    }
    let body_end = c.p;
    let sig = c.take(SIG_LEN)?;
    c.end()?;
    let body = b.get(..body_end).unwrap_or_default();
    Ok(Grant {
        body,
        sig,
        id: hd(D_GRANT_ID, body),
        issuer,
        audience,
        parent,
        nb,
        na,
        depth,
        caveats,
    })
}
