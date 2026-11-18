//! Strict canonical binary codec helpers (big-endian, length-prefixed).
//!
//! Every reader method fails rather than guessing; [`Reader::finish`] rejects
//! trailing bytes. Together this makes each structure have exactly one valid
//! encoding.

use crate::error::{Error, Result};

#[derive(Default)]
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::with_capacity(512),
        }
    }
    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    /// Caller must have validated the length with [`check_str`].
    pub(crate) fn str_u8(&mut self, s: &str) {
        self.u8(s.len() as u8);
        self.bytes(s.as_bytes());
    }
    /// Caller must have validated the length with [`check_str`].
    pub(crate) fn str_u16(&mut self, s: &str) {
        self.u16(s.len() as u16);
        self.bytes(s.as_bytes());
    }
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Validate a string field length (in bytes) at construction time.
pub(crate) fn check_str(s: &str, min: usize, max: usize, what: &'static str) -> Result<()> {
    if s.len() < min || s.len() > max {
        return Err(Error::InvalidField(what));
    }
    Ok(())
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn position(&self) -> usize {
        self.pos
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Decode("length overflow"))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(Error::Decode("unexpected end of input"))?;
        self.pos = end;
        Ok(s)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(crate) fn magic(&mut self, m: &[u8; 4], ver: u8) -> Result<()> {
        if &self.array::<4>()? != m {
            return Err(Error::Decode("bad magic"));
        }
        if self.u8()? != ver {
            return Err(Error::Decode("unsupported version"));
        }
        Ok(())
    }
    fn utf8(&mut self, len: usize, min: usize, max: usize) -> Result<String> {
        if len < min || len > max {
            return Err(Error::Decode("string length out of range"));
        }
        let b = self.take(len)?;
        core::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| Error::Decode("invalid utf-8"))
    }
    pub(crate) fn str_u8(&mut self, min: usize, max: usize) -> Result<String> {
        let len = self.u8()? as usize;
        self.utf8(len, min, max)
    }
    pub(crate) fn str_u16(&mut self, min: usize, max: usize) -> Result<String> {
        let len = self.u16()? as usize;
        self.utf8(len, min, max)
    }
    pub(crate) fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(Error::Decode("trailing bytes"));
        }
        Ok(())
    }
}
