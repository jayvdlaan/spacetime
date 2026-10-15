//! SSH wire encoding primitives (RFC 4251 §5): `byte`, `uint32` (big-endian)
//! and `string` (a `uint32` length followed by that many bytes).
//!
//! [`Reader`] is a zero-copy, bounds-checked cursor over a borrowed buffer;
//! every slice it hands out borrows from the input for its full lifetime.
//! [`Writer`] fills a caller-provided buffer and never grows it. Neither
//! allocates.

use crate::error::{Error, Section};

/// Length of an SSH `string` carrying `payload` bytes (4 + payload).
pub const fn string_len(payload: usize) -> usize {
    4 + payload
}

/// Zero-copy cursor over an SSH wire buffer. Every read is bounds-checked; a
/// short read is [`Error::Truncated`].
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading at the beginning of `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// `true` when every byte has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read one `byte`.
    pub fn u8(&mut self) -> Result<u8, Error> {
        let b = self.bytes(1)?;
        Ok(b[0])
    }

    /// Read one big-endian `uint32`.
    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read exactly `n` raw bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// `uint32` length followed by that many bytes. The length is checked
    /// against [`Reader::remaining`] BEFORE any conversion; `u32 -> usize`
    /// is lossless on 32- and 64-bit targets (a narrower target fails
    /// closed with [`Error::Truncated`]).
    pub fn string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()?;
        let len = usize::try_from(len).map_err(|_| Error::Truncated)?;
        self.bytes(len)
    }

    /// `Ok(())` iff nothing remains; otherwise [`Error::TrailingBytes`]`(section)`.
    pub fn finish(self, section: Section) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingBytes(section))
        }
    }
}

/// Bounds-checked writer into a caller buffer. Overflow is
/// [`Error::BufferTooSmall`]; a string payload longer than `u32::MAX` is
/// [`Error::TooLong`].
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Start writing at the beginning of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes written so far.
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// `true` when nothing has been written yet.
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Write one `byte`.
    pub fn put_u8(&mut self, v: u8) -> Result<(), Error> {
        self.put_bytes(&[v])
    }

    /// Write one big-endian `uint32`.
    pub fn put_u32(&mut self, v: u32) -> Result<(), Error> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Write raw bytes.
    pub fn put_bytes(&mut self, b: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(b.len()).ok_or(Error::BufferTooSmall)?;
        if end > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        self.buf[self.pos..end].copy_from_slice(b);
        self.pos = end;
        Ok(())
    }

    /// Write an SSH `string`: `uint32` length then `payload`.
    pub fn put_string(&mut self, payload: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(payload.len()).map_err(|_| Error::TooLong)?;
        self.put_u32(len)?;
        self.put_bytes(payload)
    }

    /// Bytes written.
    pub fn finish(self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_len_adds_header() {
        assert_eq!(string_len(0), 4);
        assert_eq!(string_len(32), 36);
    }

    #[test]
    fn reader_round_trips_writer() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        assert!(w.is_empty());
        w.put_u8(7).unwrap();
        w.put_u32(0x0102_0304).unwrap();
        w.put_string(b"abc").unwrap();
        w.put_bytes(b"zz").unwrap();
        assert_eq!(w.len(), 1 + 4 + 7 + 2);
        let n = w.finish();

        let mut r = Reader::new(&buf[..n]);
        assert_eq!(r.remaining(), n);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0x0102_0304);
        assert_eq!(r.string().unwrap(), b"abc");
        assert_eq!(r.bytes(2).unwrap(), b"zz");
        assert!(r.is_empty());
        assert_eq!(r.finish(Section::Outer), Ok(()));
    }

    #[test]
    fn reader_truncated_paths() {
        assert_eq!(Reader::new(&[]).u8(), Err(Error::Truncated));
        assert_eq!(Reader::new(&[0, 0, 0]).u32(), Err(Error::Truncated));
        assert_eq!(Reader::new(&[1, 2]).bytes(3), Err(Error::Truncated));
        // Declared length exceeds what remains.
        assert_eq!(
            Reader::new(&[0, 0, 0, 5, b'a']).string(),
            Err(Error::Truncated)
        );
        // Length field itself cut short.
        assert_eq!(Reader::new(&[0, 0, 1]).string(), Err(Error::Truncated));
        // A huge length must not overflow or panic.
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).string(),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn reader_finish_reports_section() {
        let r = Reader::new(&[1]);
        assert_eq!(
            r.finish(Section::PublicKey),
            Err(Error::TrailingBytes(Section::PublicKey))
        );
        let r = Reader::new(&[1]);
        assert_eq!(
            r.finish(Section::Signature),
            Err(Error::TrailingBytes(Section::Signature))
        );
    }

    #[test]
    fn writer_buffer_too_small() {
        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.put_u32(1), Err(Error::BufferTooSmall));
        assert_eq!(w.len(), 0);
        w.put_bytes(b"ab").unwrap();
        assert_eq!(w.put_bytes(b"cd"), Err(Error::BufferTooSmall));
        assert_eq!(w.put_u8(1), Ok(()));
        assert_eq!(w.put_u8(1), Err(Error::BufferTooSmall));
        assert_eq!(w.put_string(b""), Err(Error::BufferTooSmall));
        assert_eq!(w.finish(), 3);
    }

    // `Error::TooLong` needs a payload of more than `u32::MAX` bytes, which
    // no unit test can materialise; the guard is the `u32::try_from` in
    // `put_string` and is covered by review, not by a vector.
}
