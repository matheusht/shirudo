// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A gzip member inflated as zlib 1.3.1's inflate() inflates one for
//! inflateInit2(16 + 15): its header and trailer checked, the deflate
//! stream of RFC 1951 decoded, and every malformation refused with
//! zlib's message where zlib refuses it, a back-reference before the
//! member's start among them. It stops where zlib stops: when it needs
//! input it was not given, or room for output, having decoded on as far
//! as that takes neither, so that a reader buffering as gzread() does
//! fails the read zlib's fails. A canonical code is decoded a bit at a
//! time; what it consumes and when is what zlib's tables take.

use super::gzip::crc32;

/// The history a back-reference reaches into.
const WSIZE: usize = 32768;

/// What inflate() returned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// Input or output ran out.
    Ok,
    /// The member ended, its trailer checked.
    StreamEnd,
    /// The stream is malformed, as zlib's message says.
    Data(&'static str),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Head,
    Flags,
    Time,
    Os,
    ExLen,
    Extra,
    Name,
    Comment,
    Hcrc,
    Type,
    Stored,
    Copy,
    Table,
    LenLens,
    CodeLens,
    Len,
    LenExt,
    Dist,
    DistExt,
    Match,
    Lit,
    Check,
    Length,
    Done,
    Bad,
}

/// What a code is for, which decides the incomplete codes admitted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    CodeLengths,
    Lengths,
    Distances,
}

/// A canonical Huffman code as zlib's inflate_table() admits it: none
/// over-subscribed, and none incomplete but a single code of one bit
/// for lengths or distances. A code of no symbols at all is admitted,
/// and decodes nothing, each attempt one bit.
struct Code {
    count: [u16; 16],
    symbol: Vec<u16>,
    max: u32,
}

impl Code {
    fn new(lens: &[u8], kind: Kind) -> Option<Code> {
        let mut count = [0u16; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        let max = (1..16).rev().find(|&l| count[l] != 0).unwrap_or(0) as u32;
        if max != 0 {
            let mut left: i32 = 1;
            for &c in &count[1..] {
                left = (left << 1) - i32::from(c);
                if left < 0 {
                    return None;
                }
            }
            if left > 0 && (kind == Kind::CodeLengths || max != 1) {
                return None;
            }
        }
        let mut offs = [0u16; 16];
        for l in 1..15 {
            offs[l + 1] = offs[l] + count[l];
        }
        let mut symbol = vec![0u16; lens.len()];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        Some(Code { count, symbol, max })
    }

    /// The fixed codes of RFC 1951 3.2.6, as zlib builds them: 288
    /// lengths and 32 distances, the last two of each refused when met.
    fn fixed() -> (Code, Code) {
        let mut lens = [0u8; 288];
        lens[..144].fill(8);
        lens[144..256].fill(9);
        lens[256..280].fill(7);
        lens[280..].fill(8);
        let len = Code::new(&lens, Kind::Lengths).expect("the fixed code is complete");
        let dist = Code::new(&[5u8; 32], Kind::Distances).expect("the fixed code is complete");
        (len, dist)
    }
}

/// A decoded code: its symbol and length, or a pattern no symbol has,
/// with the bits zlib's table takes for it.
enum Decoded {
    Symbol(u16, u32),
    Invalid(u32),
}

const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// The gzip flags this reads.
const FHCRC: u32 = 0x0200;
const FEXTRA: u32 = 0x0400;
const FNAME: u32 = 0x0800;
const FCOMMENT: u32 = 0x1000;

/// The inflation of one gzip member.
pub(crate) struct Inflate {
    mode: Mode,
    msg: &'static str,
    hold: u64,
    bits: u32,
    last: bool,
    flags: u32,
    /// The header's CRC-32, then the data's.
    check: u32,
    /// The member's output so far.
    total: u64,
    length: u32,
    extra: u32,
    offset: u32,
    nlen: usize,
    ndist: usize,
    ncode: usize,
    have: usize,
    lens: [u8; 320],
    codes: Option<Code>,
    lencode: Option<Code>,
    distcode: Option<Code>,
    fixed: bool,
    window: Box<[u8; WSIZE]>,
    wpos: usize,
}

/// Where inflate() reads and writes: the input and output, and how far
/// into each it got.
struct Io<'a> {
    input: &'a [u8],
    ip: usize,
    out: &'a mut [u8],
    op: usize,
    /// The output not yet in the data's check.
    crc_from: usize,
}

impl Inflate {
    pub(crate) fn new() -> Box<Inflate> {
        Box::new(Inflate {
            mode: Mode::Head,
            msg: "",
            hold: 0,
            bits: 0,
            last: false,
            flags: 0,
            check: 0,
            total: 0,
            length: 0,
            extra: 0,
            offset: 0,
            nlen: 0,
            ndist: 0,
            ncode: 0,
            have: 0,
            lens: [0; 320],
            codes: None,
            lencode: None,
            distcode: None,
            fixed: false,
            window: Box::new([0; WSIZE]),
            wpos: 0,
        })
    }

    /// inflateReset(): ready for a member from its header on.
    pub(crate) fn reset(&mut self) {
        self.mode = Mode::Head;
        self.msg = "";
        self.hold = 0;
        self.bits = 0;
        self.last = false;
        self.flags = 0;
        self.check = 0;
        self.total = 0;
        self.codes = None;
        self.lencode = None;
        self.distcode = None;
        self.fixed = false;
        self.wpos = 0;
    }

    /// One byte of input into the bit buffer: false when there is none.
    fn pull(&mut self, io: &mut Io<'_>) -> bool {
        let Some(&b) = io.input.get(io.ip) else {
            return false;
        };
        io.ip += 1;
        self.hold |= u64::from(b) << self.bits;
        self.bits += 8;
        true
    }

    /// At least `n` bits in the buffer: false when the input ends first.
    fn need(&mut self, n: u32, io: &mut Io<'_>) -> bool {
        while self.bits < n {
            if !self.pull(io) {
                return false;
            }
        }
        true
    }

    fn peek(&self, n: u32) -> u32 {
        (self.hold & ((1u64 << n) - 1)) as u32
    }

    fn drop_bits(&mut self, n: u32) {
        self.hold >>= n;
        self.bits -= n;
    }

    /// The byte boundary, the bits up to it dropped.
    fn align(&mut self) {
        let n = self.bits & 7;
        self.drop_bits(n);
    }

    /// The header bytes of the first `n` bits into the header's CRC.
    fn crc_header(&mut self, n: u32) {
        if self.flags & FHCRC != 0 {
            let b = self.hold.to_le_bytes();
            self.check = crc32(self.check, &b[..(n / 8) as usize]);
        }
    }

    fn bad(&mut self, msg: &'static str) {
        self.msg = msg;
        self.mode = Mode::Bad;
    }

    /// The next code of `code`, its bits left in the buffer: None when
    /// the input ends before zlib's table would have them.
    fn decode(&mut self, code: &Code, io: &mut Io<'_>) -> Option<Decoded> {
        if code.max == 0 {
            return self.need(1, io).then_some(Decoded::Invalid(1));
        }
        let (mut c, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=code.max {
            if !self.need(len, io) {
                return None;
            }
            c |= ((self.hold >> (len - 1)) & 1) as i32;
            let count = i32::from(code.count[len as usize]);
            if c - count < first {
                let sym = code.symbol[(index + c - first) as usize];
                return Some(Decoded::Symbol(sym, len));
            }
            index += count;
            first = (first + count) << 1;
            c <<= 1;
        }
        Some(Decoded::Invalid(code.max))
    }

    /// The output since the last fold into the data's check, as zlib
    /// updates it where it leaves inflate() and before the trailer.
    fn fold_check(&mut self, io: &mut Io<'_>) {
        if io.op != io.crc_from {
            self.check = crc32(self.check, &io.out[io.crc_from..io.op]);
            io.crc_from = io.op;
        }
    }

    /// One byte out, into the window.
    fn put(&mut self, b: u8, io: &mut Io<'_>) {
        io.out[io.op] = b;
        io.op += 1;
        self.window[self.wpos] = b;
        self.wpos = (self.wpos + 1) % WSIZE;
        self.total += 1;
    }

    /// inflate(): from `input`, the bytes taken counted in `ip`, into
    /// `out`, the bytes written counted in `op`.
    pub(crate) fn inflate(
        &mut self,
        input: &[u8],
        ip: &mut usize,
        out: &mut [u8],
        op: &mut usize,
    ) -> Status {
        let mut io = Io {
            input,
            ip: *ip,
            out,
            op: *op,
            crc_from: *op,
        };
        let status = self.run(&mut io);
        self.fold_check(&mut io);
        *ip = io.ip;
        *op = io.op;
        status
    }

    fn run(&mut self, io: &mut Io<'_>) -> Status {
        loop {
            match self.mode {
                Mode::Head => {
                    if !self.need(16, io) {
                        return Status::Ok;
                    }
                    if self.peek(16) != 0x8b1f {
                        self.bad("incorrect header check");
                        continue;
                    }
                    self.check = crc32(0, &[0x1f, 0x8b]);
                    self.drop_bits(16);
                    self.mode = Mode::Flags;
                }
                Mode::Flags => {
                    if !self.need(16, io) {
                        return Status::Ok;
                    }
                    self.flags = self.peek(16);
                    if self.flags & 0xff != 8 {
                        self.bad("unknown compression method");
                        continue;
                    }
                    if self.flags & 0xe000 != 0 {
                        self.bad("unknown header flags set");
                        continue;
                    }
                    self.crc_header(16);
                    self.drop_bits(16);
                    self.mode = Mode::Time;
                }
                Mode::Time => {
                    if !self.need(32, io) {
                        return Status::Ok;
                    }
                    self.crc_header(32);
                    self.drop_bits(32);
                    self.mode = Mode::Os;
                }
                Mode::Os => {
                    if !self.need(16, io) {
                        return Status::Ok;
                    }
                    self.crc_header(16);
                    self.drop_bits(16);
                    self.mode = Mode::ExLen;
                }
                Mode::ExLen => {
                    if self.flags & FEXTRA != 0 {
                        if !self.need(16, io) {
                            return Status::Ok;
                        }
                        self.length = self.peek(16);
                        self.crc_header(16);
                        self.drop_bits(16);
                    }
                    self.mode = Mode::Extra;
                }
                Mode::Extra => {
                    if self.flags & FEXTRA != 0 {
                        let n = (self.length as usize).min(io.input.len() - io.ip);
                        let taken = &io.input[io.ip..io.ip + n];
                        if self.flags & FHCRC != 0 {
                            self.check = crc32(self.check, taken);
                        }
                        io.ip += n;
                        self.length -= n as u32;
                        if self.length != 0 {
                            return Status::Ok;
                        }
                    }
                    self.length = 0;
                    self.mode = Mode::Name;
                }
                Mode::Name | Mode::Comment => {
                    let flag = if self.mode == Mode::Name {
                        FNAME
                    } else {
                        FCOMMENT
                    };
                    if self.flags & flag != 0 {
                        let rest = &io.input[io.ip..];
                        if rest.is_empty() {
                            return Status::Ok;
                        }
                        let n = rest
                            .iter()
                            .position(|&c| c == 0)
                            .map_or(rest.len(), |i| i + 1);
                        if self.flags & FHCRC != 0 {
                            self.check = crc32(self.check, &rest[..n]);
                        }
                        io.ip += n;
                        if rest[n - 1] != 0 {
                            return Status::Ok;
                        }
                    }
                    self.mode = if self.mode == Mode::Name {
                        Mode::Comment
                    } else {
                        Mode::Hcrc
                    };
                }
                Mode::Hcrc => {
                    if self.flags & FHCRC != 0 {
                        if !self.need(16, io) {
                            return Status::Ok;
                        }
                        if self.peek(16) != self.check & 0xffff {
                            self.bad("header crc mismatch");
                            continue;
                        }
                        self.drop_bits(16);
                    }
                    self.check = 0;
                    self.mode = Mode::Type;
                }
                Mode::Type => {
                    if self.last {
                        self.align();
                        self.mode = Mode::Check;
                        continue;
                    }
                    if !self.need(3, io) {
                        return Status::Ok;
                    }
                    self.last = self.peek(1) == 1;
                    let ty = (self.hold >> 1) & 3;
                    self.drop_bits(3);
                    match ty {
                        0 => self.mode = Mode::Stored,
                        1 => {
                            let (len, dist) = Code::fixed();
                            self.lencode = Some(len);
                            self.distcode = Some(dist);
                            self.fixed = true;
                            self.mode = Mode::Len;
                        }
                        2 => self.mode = Mode::Table,
                        _ => self.bad("invalid block type"),
                    }
                }
                Mode::Stored => {
                    self.align();
                    if !self.need(32, io) {
                        return Status::Ok;
                    }
                    let (len, nlen) = (self.peek(16), (self.hold >> 16) as u32 & 0xffff);
                    if len != nlen ^ 0xffff {
                        self.bad("invalid stored block lengths");
                        continue;
                    }
                    self.length = len;
                    self.drop_bits(32);
                    self.mode = Mode::Copy;
                }
                Mode::Copy => {
                    if self.length == 0 {
                        self.mode = Mode::Type;
                        continue;
                    }
                    let n = (self.length as usize)
                        .min(io.input.len() - io.ip)
                        .min(io.out.len() - io.op);
                    if n == 0 {
                        return Status::Ok;
                    }
                    for i in 0..n {
                        let b = io.input[io.ip + i];
                        self.put(b, io);
                    }
                    io.ip += n;
                    self.length -= n as u32;
                }
                Mode::Table => {
                    if !self.need(14, io) {
                        return Status::Ok;
                    }
                    self.nlen = self.peek(5) as usize + 257;
                    self.ndist = (self.hold >> 5) as usize % 32 + 1;
                    self.ncode = (self.hold >> 10) as usize % 16 + 4;
                    self.drop_bits(14);
                    if self.nlen > 286 || self.ndist > 30 {
                        self.bad("too many length or distance symbols");
                        continue;
                    }
                    self.fixed = false;
                    self.have = 0;
                    self.mode = Mode::LenLens;
                }
                Mode::LenLens => {
                    while self.have < self.ncode {
                        if !self.need(3, io) {
                            return Status::Ok;
                        }
                        self.lens[ORDER[self.have]] = self.peek(3) as u8;
                        self.drop_bits(3);
                        self.have += 1;
                    }
                    while self.have < 19 {
                        self.lens[ORDER[self.have]] = 0;
                        self.have += 1;
                    }
                    let Some(codes) = Code::new(&self.lens[..19], Kind::CodeLengths) else {
                        self.bad("invalid code lengths set");
                        continue;
                    };
                    self.codes = Some(codes);
                    self.have = 0;
                    self.mode = Mode::CodeLens;
                }
                Mode::CodeLens => {
                    let total = self.nlen + self.ndist;
                    let codes = self.codes.take().expect("the code lengths' code");
                    let status = self.code_lengths(&codes, total, io);
                    self.codes = Some(codes);
                    if let Some(s) = status {
                        return s;
                    }
                    if self.mode == Mode::Bad {
                        continue;
                    }
                    if self.lens[256] == 0 {
                        self.bad("invalid code -- missing end-of-block");
                        continue;
                    }
                    let Some(len) = Code::new(&self.lens[..self.nlen], Kind::Lengths) else {
                        self.bad("invalid literal/lengths set");
                        continue;
                    };
                    let Some(dist) = Code::new(&self.lens[self.nlen..total], Kind::Distances)
                    else {
                        self.bad("invalid distances set");
                        continue;
                    };
                    self.lencode = Some(len);
                    self.distcode = Some(dist);
                    self.mode = Mode::Len;
                }
                Mode::Len => {
                    let code = self.lencode.take().expect("the lengths' code");
                    let got = self.decode(&code, io);
                    self.lencode = Some(code);
                    let Some(got) = got else {
                        return Status::Ok;
                    };
                    match got {
                        Decoded::Symbol(sym, n) => {
                            self.drop_bits(n);
                            match sym {
                                0..=255 => {
                                    self.length = u32::from(sym);
                                    self.mode = Mode::Lit;
                                }
                                256 => self.mode = Mode::Type,
                                257..=285 => {
                                    let i = usize::from(sym - 257);
                                    self.length = u32::from(LBASE[i]);
                                    self.extra = u32::from(LEXT[i]);
                                    self.mode = Mode::LenExt;
                                }
                                _ => self.bad("invalid literal/length code"),
                            }
                        }
                        Decoded::Invalid(n) => {
                            self.drop_bits(n);
                            self.bad("invalid literal/length code");
                        }
                    }
                }
                Mode::LenExt => {
                    if self.extra != 0 {
                        if !self.need(self.extra, io) {
                            return Status::Ok;
                        }
                        self.length += self.peek(self.extra);
                        self.drop_bits(self.extra);
                    }
                    self.mode = Mode::Dist;
                }
                Mode::Dist => {
                    let code = self.distcode.take().expect("the distances' code");
                    let got = self.decode(&code, io);
                    self.distcode = Some(code);
                    let Some(got) = got else {
                        return Status::Ok;
                    };
                    match got {
                        Decoded::Symbol(sym, n) if sym < 30 => {
                            self.drop_bits(n);
                            self.offset = u32::from(DBASE[usize::from(sym)]);
                            self.extra = u32::from(DEXT[usize::from(sym)]);
                            self.mode = Mode::DistExt;
                        }
                        Decoded::Symbol(_, n) | Decoded::Invalid(n) => {
                            self.drop_bits(n);
                            self.bad("invalid distance code");
                        }
                    }
                }
                Mode::DistExt => {
                    if self.extra != 0 {
                        if !self.need(self.extra, io) {
                            return Status::Ok;
                        }
                        self.offset += self.peek(self.extra);
                        self.drop_bits(self.extra);
                    }
                    self.mode = Mode::Match;
                }
                Mode::Match => {
                    if io.op == io.out.len() {
                        return Status::Ok;
                    }
                    if u64::from(self.offset) > self.total {
                        self.bad("invalid distance too far back");
                        continue;
                    }
                    let n = (self.length as usize).min(io.out.len() - io.op);
                    for _ in 0..n {
                        let b = self.window[(self.wpos + WSIZE - self.offset as usize) % WSIZE];
                        self.put(b, io);
                    }
                    self.length -= n as u32;
                    if self.length == 0 {
                        self.mode = Mode::Len;
                    }
                }
                Mode::Lit => {
                    if io.op == io.out.len() {
                        return Status::Ok;
                    }
                    self.put(self.length as u8, io);
                    self.mode = Mode::Len;
                }
                Mode::Check => {
                    if !self.need(32, io) {
                        return Status::Ok;
                    }
                    self.fold_check(io);
                    if self.peek(32) != self.check {
                        self.bad("incorrect data check");
                        continue;
                    }
                    self.drop_bits(32);
                    self.mode = Mode::Length;
                }
                Mode::Length => {
                    if !self.need(32, io) {
                        return Status::Ok;
                    }
                    if self.peek(32) != self.total as u32 {
                        self.bad("incorrect length check");
                        continue;
                    }
                    self.drop_bits(32);
                    self.mode = Mode::Done;
                }
                Mode::Done => return Status::StreamEnd,
                Mode::Bad => return Status::Data(self.msg),
            }
        }
    }

    /// The code lengths of a dynamic block, `total` of them: Some when
    /// the input ends first, None once they are read or one is bad.
    fn code_lengths(&mut self, codes: &Code, total: usize, io: &mut Io<'_>) -> Option<Status> {
        while self.have < total {
            let Some(got) = self.decode(codes, io) else {
                return Some(Status::Ok);
            };
            // zlib's table for a code of no symbols reads as length 0.
            let (sym, n) = match got {
                Decoded::Symbol(sym, n) => (sym, n),
                Decoded::Invalid(n) => (0, n),
            };
            if sym < 16 {
                self.drop_bits(n);
                self.lens[self.have] = sym as u8;
                self.have += 1;
                continue;
            }
            let (extra, base, from_last) = match sym {
                16 => (2, 3, true),
                17 => (3, 3, false),
                _ => (7, 11, false),
            };
            if !self.need(n + extra, io) {
                return Some(Status::Ok);
            }
            self.drop_bits(n);
            if from_last && self.have == 0 {
                self.bad("invalid bit length repeat");
                return None;
            }
            let len = if from_last {
                self.lens[self.have - 1]
            } else {
                0
            };
            let copy = base + self.peek(extra) as usize;
            self.drop_bits(extra);
            if self.have + copy > total {
                self.bad("invalid bit length repeat");
                return None;
            }
            self.lens[self.have..self.have + copy].fill(len);
            self.have += copy;
        }
        None
    }
}
