// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The .BTF.ext section: function, line and CO-RE relocation records,
//! grouped by the ELF section of the code they describe.

use core::ffi::c_int;

use crate::errno::{EINVAL, EOPNOTSUPP};

fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// The records of one ELF section: the section name's BTF string offset
/// and the records, each `rec_size` bytes.
pub(crate) struct Group<'a> {
    pub(crate) sec_name_off: u32,
    pub(crate) recs: &'a [u8],
}

/// One kind of record: their size and their groups in file order.
#[derive(Default)]
pub(crate) struct Info<'a> {
    pub(crate) rec_size: usize,
    pub(crate) groups: Vec<Group<'a>>,
}

/// The section, as btf_ext__new() checks it.
pub(crate) struct BtfExt<'a> {
    pub(crate) func: Info<'a>,
    pub(crate) line: Info<'a>,
    pub(crate) core: Info<'a>,
}

/// One kind's records at `off`/`len` past the header, each at least
/// `min` bytes; none when `len` is 0.
fn parse_info<'a>(
    data: &'a [u8],
    hdr_len: usize,
    off: usize,
    len: usize,
    min: usize,
) -> Result<Info<'a>, c_int> {
    let bad = Err(-EINVAL);
    if len == 0 {
        return Ok(Info::default());
    }
    let left = data.len() - hdr_len;
    if off % 4 != 0 || off > left || len > left - off || len < 4 {
        return bad;
    }
    let info = &data[hdr_len + off..hdr_len + off + len];
    let rec_size = le32(info, 0).ok_or(-EINVAL)? as usize;
    if rec_size < min || rec_size % 4 != 0 || len == 4 {
        return bad;
    }
    let mut groups = Vec::new();
    let mut at = 4;
    while at < len {
        let (Some(name), Some(n)) = (le32(info, at), le32(info, at + 4)) else {
            return bad;
        };
        let total = 8 + n as usize * rec_size;
        if n == 0 || len - at < total {
            return bad;
        }
        groups.push(Group {
            sec_name_off: name,
            recs: &info[at + 8..at + total],
        });
        at += total;
    }
    Ok(Info { rec_size, groups })
}

/// Whether the section is of the other byte order, which libbpf reads
/// and this does not.
pub(crate) fn foreign(data: &[u8]) -> bool {
    data.len() >= 8 && u16::from_be_bytes([data[0], data[1]]) == super::btf::MAGIC
}

impl<'a> BtfExt<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, c_int> {
        let bad = Err(-EINVAL);
        let word = |off| le32(data, off).ok_or(-EINVAL);
        if data.len() < 8 || u16::from_le_bytes([data[0], data[1]]) != super::btf::MAGIC {
            return bad;
        }
        // Version 1 and no flags.
        if data[2] != 1 || data[3] != 0 {
            return Err(-EOPNOTSUPP);
        }
        let hdr_len = word(4)? as usize;
        if hdr_len < 24 || hdr_len >= data.len() {
            return bad;
        }
        let func = parse_info(data, hdr_len, word(8)? as usize, word(12)? as usize, 8)?;
        let line = parse_info(data, hdr_len, word(16)? as usize, word(20)? as usize, 16)?;
        let core = if hdr_len >= 32 {
            parse_info(data, hdr_len, word(24)? as usize, word(28)? as usize, 16)?
        } else {
            Info::default()
        };
        Ok(BtfExt { func, line, core })
    }
}
