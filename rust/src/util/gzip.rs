// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! gzip as shirudo reads and writes it, in place of zlib. A gzip file
//! is read as zlib 1.3.1's gzopen(), gzdirect(), gzread() and gzclose()
//! read one: input in loads of GZBUFSIZE, output through a buffer twice
//! that or straight into a large read, the members one after another,
//! what follows the last ignored, a file that is not gzip read as it
//! is, and a read failing, or the close reporting a cut, where zlib's
//! does; the members inflate as util/inflate.rs inflates them. gzip is
//! written with miniz_oxide's deflate, behind the header zlib writes.

use std::fs::File;
use std::io::{Read, Write};

use miniz_oxide::deflate::core::{
    CompressorOxide, TDEFLFlush, TDEFLStatus, compress, create_comp_flags_from_zip_params,
};

use super::inflate::{Inflate, Status};

/// zlib's return codes the callers compare with.
pub(crate) const Z_OK: i32 = 0;
pub(crate) const Z_BUF_ERROR: i32 = -5;
const Z_DATA_ERROR: i32 = -3;
const Z_ERRNO: i32 = -1;

/// GZBUFSIZE of zlib's gzguts.h: the input loads, and half the output.
const GZBUFSIZE: usize = 8192;

/// The CRC-32 of ISO 3309 that gzip carries, continued from `crc` as
/// zlib's crc32() continues it.
pub(crate) fn crc32(crc: u32, data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut c = !crc;
    for &b in data {
        c = TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum How {
    Look,
    Copy,
    Gzip,
}

/// A file open for reading as zlib's gzopen(path, "rb") opens it.
pub(crate) struct GzRead {
    file: File,
    /// The input: `inbuf[next..next + avail]` not yet consumed.
    inbuf: Vec<u8>,
    next: usize,
    avail: usize,
    eof: bool,
    /// The output buffer, `out[x_next..x_next + x_have]` not yet read.
    out: Vec<u8>,
    x_next: usize,
    x_have: usize,
    how: How,
    direct: bool,
    err: i32,
    inflate: Option<Box<Inflate>>,
}

/// Where gz_decomp() writes: the output buffer, or the reader's.
enum Into<'a> {
    Own,
    Theirs(&'a mut [u8]),
}

impl GzRead {
    /// gzopen(): Err(errno) when the file does not open.
    pub(crate) fn open(path: &std::path::Path) -> Result<GzRead, i32> {
        let file = File::open(path).map_err(|e| e.raw_os_error().unwrap_or(crate::errno::EIO))?;
        Ok(Self::from_file(file))
    }

    /// Read from a File whose ownership the caller has transferred.
    pub(crate) fn from_file(file: File) -> GzRead {
        GzRead {
            file,
            inbuf: Vec::new(),
            next: 0,
            avail: 0,
            eof: false,
            out: Vec::new(),
            x_next: 0,
            x_have: 0,
            how: How::Look,
            // zlib takes an empty file for one read as it is.
            direct: true,
            err: Z_OK,
            inflate: None,
        }
    }

    fn serious(&self) -> bool {
        self.err != Z_OK && self.err != Z_BUF_ERROR
    }

    fn error(&mut self, err: i32) {
        self.err = err;
        if self.serious() {
            self.x_have = 0;
        }
    }

    /// gz_load(): up to `len` bytes of the file at `at` of `buf`, the
    /// end of the file marked when a read finds it.
    fn load(&mut self, into_out: bool, at: usize, len: usize) -> Result<usize, ()> {
        let mut have = 0;
        while have < len {
            let buf = if into_out {
                &mut self.out
            } else {
                &mut self.inbuf
            };
            match self.file.read(&mut buf[at + have..at + len]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => have += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.error(Z_ERRNO);
                    return Err(());
                }
            }
        }
        Ok(have)
    }

    /// gz_load() into a reader's buffer.
    fn load_into(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        let mut have = 0;
        while have < buf.len() {
            match self.file.read(&mut buf[have..]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => have += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.error(Z_ERRNO);
                    return Err(());
                }
            }
        }
        Ok(have)
    }

    /// gz_avail(): the input topped up to GZBUFSIZE, what is left moved
    /// to its start, unless the file has ended.
    fn avail(&mut self) -> Result<(), ()> {
        if self.serious() {
            return Err(());
        }
        if !self.eof {
            self.inbuf.copy_within(self.next..self.next + self.avail, 0);
            self.next = 0;
            let got = self.load(false, self.avail, GZBUFSIZE - self.avail)?;
            self.avail += got;
        }
        Ok(())
    }

    /// gz_look(): gzip decoding where the input starts with gzip's magic,
    /// what follows a member ignored where it does not, and the file read
    /// as it is where its first bytes are not.
    fn look(&mut self) -> Result<(), ()> {
        if self.inflate.is_none() {
            self.inbuf = vec![0; GZBUFSIZE];
            self.out = vec![0; GZBUFSIZE << 1];
            self.inflate = Some(Inflate::new());
        }
        if self.avail < 2 {
            self.avail()?;
            if self.avail == 0 {
                return Ok(());
            }
        }
        if self.avail > 1 && self.inbuf[self.next] == 0x1f && self.inbuf[self.next + 1] == 0x8b {
            self.inflate.as_mut().expect("set up above").reset();
            self.how = How::Gzip;
            self.direct = false;
            return Ok(());
        }
        if !self.direct {
            self.avail = 0;
            self.eof = true;
            self.x_have = 0;
            return Ok(());
        }
        self.out[..self.avail].copy_from_slice(&self.inbuf[self.next..self.next + self.avail]);
        self.x_next = 0;
        self.x_have = self.avail;
        self.avail = 0;
        self.how = How::Copy;
        self.direct = true;
        Ok(())
    }

    /// gz_decomp(): output into `into`, `room` bytes of it, until it is
    /// full or the member ends.
    fn decomp(&mut self, mut into: Into<'_>, room: usize) -> Result<(), ()> {
        let mut produced = 0;
        let mut status = Status::Ok;
        loop {
            if self.avail == 0 {
                self.avail()?;
            }
            if self.avail == 0 {
                self.error(Z_BUF_ERROR);
                break;
            }
            let mut ip = 0;
            let inflate = self.inflate.as_mut().expect("set up by look()");
            let input = &self.inbuf[self.next..self.next + self.avail];
            let out = match &mut into {
                Into::Own => &mut self.out[..room],
                Into::Theirs(buf) => &mut buf[..room],
            };
            status = inflate.inflate(input, &mut ip, out, &mut produced);
            self.next += ip;
            self.avail -= ip;
            if let Status::Data(_) = status {
                self.error(Z_DATA_ERROR);
                return Err(());
            }
            if produced == room || status == Status::StreamEnd {
                break;
            }
        }
        self.x_have = produced;
        self.x_next = 0;
        if status == Status::StreamEnd {
            self.how = How::Look;
        }
        Ok(())
    }

    /// gz_fetch(): the output buffer filled, by copying or inflating.
    fn fetch(&mut self) -> Result<(), ()> {
        loop {
            match self.how {
                How::Look => {
                    self.look()?;
                    if self.how == How::Look {
                        return Ok(());
                    }
                }
                How::Copy => {
                    self.x_have = self.load(true, 0, GZBUFSIZE << 1)?;
                    self.x_next = 0;
                    return Ok(());
                }
                How::Gzip => self.decomp(Into::Own, GZBUFSIZE << 1)?,
            }
            if !(self.x_have == 0 && (!self.eof || self.avail != 0)) {
                return Ok(());
            }
        }
    }

    /// gzdirect(): whether the file is read as it is, not being gzip.
    pub(crate) fn direct(&mut self) -> bool {
        if self.how == How::Look && self.x_have == 0 {
            let _ = self.look();
        }
        self.direct
    }

    /// gz_read(): up to `buf.len()` bytes, 0 at the end or on an error.
    fn read_some(&mut self, buf: &mut [u8]) -> usize {
        let mut got = 0;
        while got < buf.len() {
            let n = buf.len() - got;
            if self.x_have != 0 {
                let n = n.min(self.x_have);
                buf[got..got + n].copy_from_slice(&self.out[self.x_next..self.x_next + n]);
                self.x_next += n;
                self.x_have -= n;
                got += n;
            } else if self.eof && self.avail == 0 {
                break;
            } else if self.how == How::Look || n < GZBUFSIZE << 1 {
                if self.fetch().is_err() {
                    return 0;
                }
            } else if self.how == How::Copy {
                match self.load_into(&mut buf[got..]) {
                    Ok(k) => got += k,
                    Err(()) => return 0,
                }
            } else {
                if self.decomp(Into::Theirs(&mut buf[got..]), n).is_err() {
                    return 0;
                }
                got += self.x_have;
                self.x_have = 0;
            }
        }
        got
    }

    /// gzread(): how many bytes, 0 at the end, or -1 on an error.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> i32 {
        if self.serious() {
            return -1;
        }
        if buf.is_empty() {
            return 0;
        }
        let len = buf.len().min(i32::MAX as usize);
        let n = self.read_some(&mut buf[..len]);
        if n == 0 && self.serious() {
            return -1;
        }
        n as i32
    }

    /// gzclose(): Z_OK, or Z_BUF_ERROR when a member was cut short.
    pub(crate) fn close(self) -> i32 {
        if self.err == Z_BUF_ERROR {
            Z_BUF_ERROR
        } else {
            Z_OK
        }
    }
}

/// The one gzip member `input` holds, nothing behind it, as
/// inflateInit2(16 + 15) and inflate() read it into a buffer grown to at
/// most `max` bytes: Err(EINVAL) for anything else, Err(EFBIG) for more.
pub(crate) fn gunzip_one(input: &[u8], max: usize) -> Result<Vec<u8>, i32> {
    let mut inflate = Inflate::new();
    let (mut ip, mut out, mut have) = (0, Vec::new(), 0);
    loop {
        if have == out.len() {
            if out.len() >= max {
                return Err(crate::errno::EFBIG);
            }
            let want = if out.is_empty() { 65536 } else { out.len() * 2 }.min(max);
            out.resize(want, 0);
        }
        match inflate.inflate(input, &mut ip, &mut out, &mut have) {
            Status::StreamEnd => break,
            Status::Data(_) => return Err(crate::errno::EINVAL),
            Status::Ok if ip == input.len() && have < out.len() => {
                return Err(crate::errno::EINVAL);
            }
            Status::Ok => {}
        }
    }
    if ip != input.len() {
        return Err(crate::errno::EINVAL);
    }
    out.truncate(have);
    Ok(out)
}

/// A gzip member written as zlib's deflate() writes one for gzip: its
/// header, as zlib's for `level`, with `os` for its operating system,
/// the data deflated, and the CRC-32 and length behind it.
pub(crate) struct GzWrite<W: Write> {
    sink: W,
    deflate: Box<CompressorOxide>,
    crc: u32,
    len: u32,
    out: Vec<u8>,
}

impl<W: Write> GzWrite<W> {
    /// `level` as zlib's, -1 for its default, 6.
    pub(crate) fn new(mut sink: W, level: i32, os: u8) -> std::io::Result<Self> {
        let level = if level < 0 { 6 } else { level.min(9) };
        // zlib marks its best and its fastest levels in XFL.
        let xfl = if level == 9 {
            2
        } else if level < 2 {
            4
        } else {
            0
        };
        sink.write_all(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, os])?;
        let flags = create_comp_flags_from_zip_params(level, -15, 0);
        Ok(GzWrite {
            sink,
            deflate: Box::new(CompressorOxide::new(flags)),
            crc: 0,
            len: 0,
            out: vec![0; 1 << 16],
        })
    }

    fn pump(&mut self, mut data: &[u8], flush: TDEFLFlush) -> std::io::Result<()> {
        loop {
            let (status, read, written) = compress(&mut self.deflate, data, &mut self.out, flush);
            self.sink.write_all(&self.out[..written])?;
            data = &data[read..];
            match status {
                TDEFLStatus::Done => return Ok(()),
                TDEFLStatus::Okay if data.is_empty() && written < self.out.len() => {
                    if flush == TDEFLFlush::None {
                        return Ok(());
                    }
                }
                TDEFLStatus::Okay => {}
                _ => return Err(std::io::Error::other("deflate failed")),
            }
        }
    }

    pub(crate) fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.crc = crc32(self.crc, data);
        self.len = self.len.wrapping_add(data.len() as u32);
        self.pump(data, TDEFLFlush::None)
    }

    /// The member finished, its trailer written: the sink.
    pub(crate) fn finish(mut self) -> std::io::Result<W> {
        self.pump(&[], TDEFLFlush::Finish)?;
        let (crc, len) = (self.crc, self.len);
        self.sink.write_all(&crc.to_le_bytes())?;
        self.sink.write_all(&len.to_le_bytes())?;
        Ok(self.sink)
    }
}

/// `data` as one gzip member at zlib's default level, as deflate() with
/// gzip framing writes it on Unix.
pub(crate) fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut w = GzWrite::new(Vec::new(), -1, 3)?;
    w.write(data)?;
    w.finish()
}
