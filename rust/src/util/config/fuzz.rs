// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-config: shirudo.conf loaded, and its lines read as bpm reads
//! its source and tree configuration files.

use super::Config;
use crate::fuzzing::{fuzz_target, input_file};
use crate::util::bpm_source_config::{parse_source_line, parse_tree_line};

const PATH_MAX: usize = 4096;
/// The rooms of an OCI client's endpoint, key and digest.
const MAX_ENDPOINT: usize = 512;
const MAX_KEY: usize = 256;
const MAX_DIGEST: usize = 128;

fuzz_target!(shirudo_fuzz_config, shirudo_fuzz_config_init, |data| {
    let Some(input) = input_file(data) else {
        return;
    };
    let mut cfg = Box::new(Config::zeroed());
    super::load_path(&mut cfg, &input.path);
    let (mut endpoint, mut reference) = ([0u8; MAX_ENDPOINT], [0u8; MAX_DIGEST]);
    let (mut index_repository, mut key_file) = ([0u8; MAX_ENDPOINT], [0u8; MAX_KEY]);
    // Read as load_source() and load_tree_config() read their files: as
    // fgets() gives them, a line or PATH_MAX - 1 bytes of one.
    let mut rest = data;
    while !rest.is_empty() {
        let end = rest
            .iter()
            .take(PATH_MAX - 1)
            .position(|&b| b == b'\n')
            .map_or(rest.len().min(PATH_MAX - 1), |n| n + 1);
        let mut line = [0u8; PATH_MAX];
        line[..end].copy_from_slice(&rest[..end]);
        rest = &rest[end..];
        let mut copy = line;
        parse_source_line(
            &mut copy,
            &mut endpoint,
            &mut index_repository,
            &mut key_file,
        );
        parse_tree_line(&mut line, &mut endpoint, &mut reference);
    }
});
