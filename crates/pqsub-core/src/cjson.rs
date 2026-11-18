//! Strict canonical JSON subset ("cjson", V2_DESIGN §14.2).
//!
//! Accepted iff the input parses under a restricted RFC 8259 grammar (integers
//! only, |n| ≤ 2^53−1, no duplicate keys, depth ≤ 4) **and** re-serializing in
//! canonical form (JCS-compatible: sorted keys by UTF-16 code units, minimal
//! escapes, no whitespace) reproduces the input byte-for-byte.

use crate::error::{Error, Result};

/// Max size of tool-call arguments.
pub const MAX_ARGS_LEN: usize = 8192;
/// Max size of a caveat value.
pub const MAX_VALUE_LEN: usize = 1024;
/// Max container nesting depth.
pub const MAX_DEPTH: usize = 4;
const MAX_INT: i64 = (1 << 53) - 1;

/// A parsed cjson value. Object members are kept in canonical (sorted) order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// Integer in [−(2^53−1), 2^53−1].
    Int(i64),
    /// String.
    Str(String),
    /// Array.
    Arr(Vec<Value>),
    /// Object (sorted by UTF-16 code units of the keys).
    Obj(Vec<(String, Value)>),
}

/// Parse and require canonical form. `object = true` for tool-call args
/// (top-level object, ≤ 8192 bytes); `false` for caveat values (any type, ≤ 1024).
///
/// # Errors
/// [`Error::Decode`] if not canonical cjson.
pub fn parse_canonical(bytes: &[u8], object: bool) -> Result<Value> {
    let max = if object { MAX_ARGS_LEN } else { MAX_VALUE_LEN };
    if bytes.len() > max {
        return Err(Error::Decode("cjson too large"));
    }
    if core::str::from_utf8(bytes).is_err() {
        return Err(Error::Decode("cjson invalid utf-8"));
    }
    let mut p = Parser { b: bytes, i: 0 };
    let v = p.value(0)?;
    if p.i != bytes.len() {
        return Err(Error::Decode("cjson trailing bytes"));
    }
    if object && !matches!(v, Value::Obj(_)) {
        return Err(Error::Decode("cjson args must be an object"));
    }
    if encode(&v) != bytes {
        return Err(Error::Decode("cjson not canonical"));
    }
    Ok(v)
}

/// Canonical serialization.
#[must_use]
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    enc(v, &mut out);
    out
}

fn enc(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Value::Str(s) => enc_str(s, out),
        Value::Arr(a) => {
            out.push(b'[');
            for (k, x) in a.iter().enumerate() {
                if k > 0 {
                    out.push(b',');
                }
                enc(x, out);
            }
            out.push(b']');
        }
        Value::Obj(m) => {
            let mut sorted: Vec<&(String, Value)> = m.iter().collect();
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (k, (key, x)) in sorted.into_iter().enumerate() {
                if k > 0 {
                    out.push(b',');
                }
                enc_str(key, out);
                out.push(b':');
                enc(x, out);
            }
            out.push(b'}');
        }
    }
}

fn enc_str(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

fn bad<T>(m: &'static str) -> Result<T> {
    Err(Error::Decode(m))
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn bump(&mut self) -> Result<u8> {
        let c = self.peek().ok_or(Error::Decode("cjson truncated"))?;
        self.i += 1;
        Ok(c)
    }
    fn expect(&mut self, c: u8) -> Result<()> {
        if self.bump()? == c {
            Ok(())
        } else {
            bad("cjson unexpected character")
        }
    }
    fn lit(&mut self, s: &[u8], v: Value) -> Result<Value> {
        if self.b.get(self.i..self.i + s.len()) == Some(s) {
            self.i += s.len();
            Ok(v)
        } else {
            bad("cjson bad literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        match self.peek() {
            Some(b'{') => {
                if depth + 1 > MAX_DEPTH {
                    return bad("cjson too deep");
                }
                self.i += 1;
                let mut m: Vec<(String, Value)> = Vec::new();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Value::Obj(m));
                }
                loop {
                    let k = self.string()?;
                    self.expect(b':')?;
                    let v = self.value(depth + 1)?;
                    if m.iter().any(|(x, _)| *x == k) {
                        return bad("cjson duplicate key");
                    }
                    m.push((k, v));
                    match self.bump()? {
                        b',' => {}
                        b'}' => break,
                        _ => return bad("cjson unexpected character"),
                    }
                }
                m.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
                Ok(Value::Obj(m))
            }
            Some(b'[') => {
                if depth + 1 > MAX_DEPTH {
                    return bad("cjson too deep");
                }
                self.i += 1;
                let mut a = Vec::new();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Value::Arr(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    match self.bump()? {
                        b',' => {}
                        b']' => break,
                        _ => return bad("cjson unexpected character"),
                    }
                }
                Ok(Value::Arr(a))
            }
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.lit(b"true", Value::Bool(true)),
            Some(b'f') => self.lit(b"false", Value::Bool(false)),
            Some(b'n') => self.lit(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.int(),
            _ => bad("cjson unexpected character"),
        }
    }

    fn int(&mut self) -> Result<Value> {
        let start = self.i;
        let neg = self.peek() == Some(b'-');
        if neg {
            self.i += 1;
        }
        let ds = self.i;
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return bad("cjson leading zero");
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return bad("cjson bad number"),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return bad("cjson floats not allowed");
        }
        if self.i - ds > 16 {
            return bad("cjson integer out of range");
        }
        let s = core::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| Error::Decode("cjson bad number"))?;
        let v: i64 = s.parse().map_err(|_| Error::Decode("cjson bad number"))?;
        if neg && v == 0 {
            return bad("cjson negative zero");
        }
        if !(-MAX_INT..=MAX_INT).contains(&v) {
            return bad("cjson integer out of range");
        }
        Ok(Value::Int(v))
    }

    fn hex4(&mut self) -> Result<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.bump()?;
            let d = (c as char)
                .to_digit(16)
                .ok_or(Error::Decode("cjson bad \\u escape"))?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.bump()?;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.bump()?;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.bump()? != b'\\' || self.bump()? != b'u' {
                                    return bad("cjson lone surrogate");
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return bad("cjson lone surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return bad("cjson lone surrogate");
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or(Error::Decode("cjson bad code point"))?
                        }
                        _ => return bad("cjson bad escape"),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c if c < 0x20 => return bad("cjson raw control character"),
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| Error::Decode("cjson invalid utf-8"))
    }
}

/// Validate RFC 6901 pointer syntax (empty, or `/`-prefixed with only `~0`/`~1` escapes).
///
/// # Errors
/// [`Error::Decode`].
pub fn validate_pointer(p: &str) -> Result<()> {
    if !p.is_empty() && !p.starts_with('/') {
        return bad("pointer must be empty or start with /");
    }
    let b = p.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'~' && !matches!(b.get(i + 1), Some(b'0' | b'1')) {
            return bad("pointer bad ~ escape");
        }
    }
    Ok(())
}

/// Evaluate an RFC 6901 pointer; `None` = absent.
#[must_use]
pub fn pointer<'a>(v: &'a Value, p: &str) -> Option<&'a Value> {
    let Some(rest) = p.strip_prefix('/') else {
        return p.is_empty().then_some(v);
    };
    let mut cur = v;
    for raw in rest.split('/') {
        let tok = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Obj(m) => &m.iter().find(|(k, _)| *k == tok)?.1,
            Value::Arr(a) => {
                let ok = tok == "0"
                    || (tok.starts_with(|c: char| ('1'..='9').contains(&c))
                        && tok.bytes().all(|c| c.is_ascii_digit()));
                if !ok {
                    return None;
                }
                a.get(tok.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(cur)
}
