use crate::{
    results::log_result,
    stack_strings::CallContext,
    utils::{extract_strings, get_pointer_size},
    {StaticString, StringEncoding, StringOptions, TightString, Verbosity},
};
use lazy_static::lazy_static;
use log::{debug, info, trace};
use regex::Regex;
use std::collections::HashMap;
use vivisect::workspace::VivWorkspace;

pub const SLICE_SIZE: usize = 4096;
pub const ASCII_BYTES: &str = " !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}\\~\t";

lazy_static! {
    pub static ref REPEATS: Vec<String> = vec![
        "A".to_string(),
        "\x00".to_string(),
        String::from_utf8(vec![0xFE]).unwrap(),
        String::from_utf8(vec![0xFF]).unwrap()
    ];
}

pub fn get_ascii_regex() -> Regex {
    Regex::new(format!("([{}]{{{},}})", ASCII_BYTES, 4).as_str()).unwrap()
}

pub fn get_unicode_regex() -> Regex {
    Regex::new(format!("((?:[{}]\x00){{{},}})", ASCII_BYTES, 4).as_str()).unwrap()
}

pub fn extract_ascii_unicode_strings(buffer: Vec<u8>, n: i32) -> Vec<StaticString> {
    if let Ok(buffer_str) = String::from_utf8(buffer) {
        let mut static_strings = extract_ascii_strings(buffer_str.as_str(), n);
        static_strings.append(&mut extract_unicode_string(buffer_str.as_str(), n));
        return static_strings;
    }
    Vec::new()
}
// pub fn extract_utf16_endian_unicode_strings(buffer: Vec<u16>, n: i32) -> Vec<StaticString>{
//     if let Ok(buffer_str) = &str::from_utf16(buffer){
//         let mut static_strings = extract_utf16_endian_strings(buffer_str.as_str(),n);
//         static_strings.append(&mut extract_unicode_string(buffer_str.as_str(), n));
//         return static_strings;
//     }
//     Vec::new()
// }
// pub fn extract_ascii_unicode_strings(buffer: Vec<u16>, n: i32) -> Vec<StaticString>{
//     if let Ok(buffer_str) = &str::from_utf16(buffer){
//         let mut static_strings = extract_ascii_strings(buffer_str.as_str(),n);
//         static_strings.append(&mut extract_unicode_string(buffer_str.as_str(), n));
//         return static_strings;
//     }
//     Vec::new()
// }

/// Extract ASCII strings from the given binary data.
/// :param buf: A bytestring.
/// :type buf: str
/// :param n: The minimum length of strings to extract.
/// :type n: int
/// :rtype: Sequence[StaticString]
pub fn extract_ascii_strings(buffer: &str, n: i32) -> Vec<StaticString> {
    if buffer.len() == 0 {
        return vec![];
    }
    let first_char = buffer.chars().next().unwrap();
    if REPEATS.contains(&first_char.to_string()) && buffer_filled_with(buffer, first_char) {
        return vec![];
    }
    let r;
    if n == 4 {
        r = Some(get_ascii_regex());
    } else {
        r = Some(Regex::new(format!("([{}]{{{},}})", ASCII_BYTES, n).as_str()).unwrap());
    }
    let mut static_strings = Vec::new();
    for _match in r.unwrap().find_iter(buffer) {
        static_strings.push(StaticString {
            string: _match.as_str().to_string(),
            offset: _match.start() as i32,
            encoding: StringEncoding::ASCII,
        });
    }
    static_strings
}

/// Extract naive UTF-16 strings from the given binary data.
/// :param buf: A bytestring.
/// :type buf: str
/// :param n: The minimum length of strings to extract.
/// :type n: int
/// :rtype: Sequence[StaticString]

pub fn extract_unicode_string(buffer: &str, n: i32) -> Vec<StaticString> {
    if buffer.len() == 0 {
        return vec![];
    }
    let first_char = buffer.chars().next().unwrap();
    if REPEATS.contains(&first_char.to_string()) && buffer_filled_with(buffer, first_char) {
        return vec![];
    }
    let r;
    if n == 4 {
        r = Some(get_unicode_regex());
    } else {
        r = Some(Regex::new(format!("((?:[{}]\x00){{{},}})", ASCII_BYTES, n).as_str()).unwrap());
    }
    let mut static_strings = Vec::new();
    for _match in r.unwrap().find_iter(buffer) {
        static_strings.push(StaticString {
            string: _match.as_str().to_string(),
            offset: _match.start() as i32,
            encoding: StringEncoding::UTF16LE,
        });
    }
    static_strings
}

pub fn buffer_filled_with(buffer: &str, character: char) -> bool {
    let dupe_chunk = [character; SLICE_SIZE];
    for offset in (0..buffer.len()).step_by(SLICE_SIZE) {
        let new_chunk = &buffer[offset..(offset + SLICE_SIZE)];
        if dupe_chunk[..new_chunk.len()]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("")
            != new_chunk
        {
            return false;
        }
    }
    true
}

/// Extracts tightstrings from functions that contain tight loops.
/// Tightstrings are a special form of stackstrings. Their bytes are loaded on the stack and then modified in a
/// tight loop. To extract tightstrings we use a mix between the string decoding and stackstring algorithms.
/// To reduce computation time we only run this on previously identified functions that contain tight loops.
/// :param vw: The vivisect_rs workspace
/// :param tightloop_functions: functions containing tight loops
/// :param min_length: minimum string length
/// :param verbosity: verbosity level
/// :param disable_progress: do NOT show progress bar
pub fn extract_tight_strings(
    workspace: VivWorkspace,
    tight_loop_funcs: HashMap<i32, Vec<i32>>,
    min_length: i32,
    verbosity: Verbosity,
    _disable_progress: bool,
) -> Vec<TightString> {
    info!(
        "Extracting tight strings from {} functions...",
        tight_loop_funcs.len()
    );
    let mut tight_strings = Vec::new();
    for (fva, tloops) in tight_loop_funcs {
        debug!("Extracting tightstrings from function {:#0x}", fva);
        let ctxs: Vec<CallContext> =
            extract_tight_string_contexts(workspace.clone(), fva, min_length, tloops);
        for (_, ctx) in ctxs.iter().enumerate() {
            trace!(
                "Extracting tightstring at checkpoint: {:#0x} stacksize: {:#0x}",
                ctx.pc,
                ctx.init_sp
            );
            trace!("pre_ctx strings: {:?}", ctx.pre_ctx_strings);
            for s in extract_strings(
                ctx.stack_memory.clone(),
                min_length,
                ctx.pre_ctx_strings.as_ref().cloned().unwrap(),
            )
            .unwrap()
            {
                let frame_offset = (ctx.init_sp - ctx.sp)
                    - s.offset
                    - get_pointer_size(workspace.clone()).unwrap();
                let ts = TightString {
                    function: fva,
                    string: s.string.clone(),
                    encoding: s.encoding,
                    program_counter: ctx.pc,
                    stack_pointer: ctx.sp,
                    original_stack_pointer: ctx.init_sp,
                    offset: s.offset,
                    frame_offset,
                };
                log_result(StringOptions::TightString(ts.clone()), verbosity.clone());
                tight_strings.push(ts);
            }
        }
    }
    tight_strings
}

pub fn extract_tight_string_contexts(
    _workspace: VivWorkspace,
    _fva: i32,
    _min_length: i32,
    _tloops: Vec<i32>,
) -> Vec<CallContext> {
    // let emu = make_emulator(workspace.clone());
    // let monitor = TightStringContextMonitor::new(emu.get_stack_counter(), min_length);
    // let driver
    Vec::new()
}
