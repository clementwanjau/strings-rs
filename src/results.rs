#![allow(dead_code, unused)]
use crate::sanitize::sanitize;
use chrono::{DateTime, Local};
use log::{debug, info, warn};
use serde::Deserialize;
use serde_json::from_str;
use std::{collections::HashMap, fs, str::from_utf8};

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq)]
pub enum StringEncoding {
    UTF16LE,
    #[default]
    ASCII,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
pub struct StackString {
    /// the address of the function from which the stackstring was extracted
    pub(crate) function: i32,
    /// the extracted string
    pub string: String,
    pub(crate) encoding: StringEncoding,
    /// the program counter at the moment the string was extracted
    pub(crate) program_counter: i32,
    /// the stack counter at the moment the string was extracted
    pub(crate) stack_pointer: i32,
    /// the initial stack counter when the function was entered
    pub(crate) original_stack_pointer: i32,
    /// the offset into the stack from at which the stack string was found
    pub(crate) offset: i32,
    /// the offset from the function frame at which the stack string was found
    pub(crate) frame_offset: i32,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
pub struct TightString {
    /// the address of the function from which the stackstring was extracted
    pub(crate) function: i32,
    /// the extracted string
    pub(crate) string: String,
    pub(crate) encoding: StringEncoding,
    /// the program counter at the moment the string was extracted
    pub(crate) program_counter: i32,
    /// the stack counter at the moment the string was extracted
    pub(crate) stack_pointer: i32,
    /// the initial stack counter when the function was entered
    pub(crate) original_stack_pointer: i32,
    /// the offset into the stack from at which the stack string was found
    pub(crate) offset: i32,
    /// the offset from the function frame at which the stack string was found
    pub(crate) frame_offset: i32,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq)]
pub enum AddressType {
    STACK,
    #[default]
    GLOBAL,
    HEAP,
}

/// A decoding string and details about where it was found.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
pub struct DecodedString {
    /// address of the string in memory
    address: i32,
    /// type of the address of the string in memory
    address_type: AddressType,
    /// the decoded string
    pub string: String,
    /// the string encoding, like ASCII or unicode
    encoding: StringEncoding,
    /// the address at which the decoding routine is called
    decoded_at: i32,
    /// the address of the decoding routine
    decoding_routine: i32,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
pub struct StaticString {
    pub string: String,
    pub offset: i32,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Runtime {
    pub start_date: String,
    pub total: i64,
    pub vivisect: i64,
    pub find_features: i64,
    pub static_strings: i64,
    pub stack_strings: i64,
    pub decoded_strings: i64,
    pub tight_strings: i64,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct Functions {
    pub discovered: i32,
    pub library: i32,
    pub analyzed_stack_strings: i32,
    pub analyzed_tight_strings: i32,
    pub analyzed_decoded_strings: i32,
    pub decoding_function_scores: HashMap<i32, f32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Analysis {
    pub(crate) enable_static_strings: bool,
    pub(crate) enable_stack_strings: bool,
    pub(crate) enable_tight_strings: bool,
    pub(crate) enable_decoded_strings: bool,
    pub(crate) functions: Functions,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub file_path: String,
    pub version: String,
    pub imagebase: i32,
    pub min_length: i32,
    pub runtime: Runtime,
}

//  Metadata::new("", 2);
// let b = Metadata::default();
// b.new();

impl Metadata {
    pub fn new(file_path: &str, min_len: i32) -> Self {
        Metadata {
            file_path: file_path.to_string(),
            version: "1".to_string(),
            imagebase: 0,
            min_length: min_len,
            runtime: Runtime {
                start_date: Local::now().to_rfc3339(),
                total: 0,
                vivisect: 0,
                find_features: 0,
                static_strings: 0,
                stack_strings: 0,
                decoded_strings: 0,
                tight_strings: 0,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Strings {
    pub stack_strings: Vec<String>,
    pub tight_strings: Vec<TightString>,
    pub decoded_strings: Vec<String>,
    pub static_strings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub enum StringOptions {
    StackString(StackString),
    DecodedString(DecodedString),
    TightString(TightString),
    StaticString(StaticString),
}

impl StringOptions {
    pub fn as_stack_string(&self) -> Option<StackString> {
        match self {
            StringOptions::StackString(t) => Some(t.clone()),
            _ => None,
        }
    }

    pub fn as_decoded_string(&self) -> Option<DecodedString> {
        match self {
            StringOptions::DecodedString(t) => Some(t.clone()),
            _ => None,
        }
    }

    pub fn as_tight_string(&self) -> Option<TightString> {
        match self {
            StringOptions::TightString(t) => Some(t.clone()),
            _ => None,
        }
    }

    pub fn as_static_string(&self) -> Option<StaticString> {
        match self {
            StringOptions::StaticString(t) => Some(t.clone()),
            _ => None,
        }
    }

    pub fn get_string(&self) -> String {
        match self {
            StringOptions::TightString(t) => t.clone().string,
            StringOptions::StackString(t) => t.clone().string,
            StringOptions::DecodedString(t) => t.clone().string,
            StringOptions::StaticString(t) => t.clone().string,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResultDocument {
    pub metadata: Metadata,
    pub analysis: Analysis,
    pub strings: Strings,
}

impl ResultDocument {
    pub fn new(metadata: Metadata, analysis: Analysis) -> Self {
        ResultDocument {
            metadata,
            analysis,
            strings: Strings {
                stack_strings: Vec::new(),
                tight_strings: Vec::new(),
                decoded_strings: Vec::new(),
                static_strings: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum Verbosity {
    VERBOSE,
    DEFAULT,
}

pub fn log_result(decoded_string: StringOptions, verbosity: Verbosity) {
    match verbosity {
        Verbosity::VERBOSE => match decoded_string {
            StringOptions::DecodedString(t) => {
                let string = sanitize(t.string);
                info!(
                    "{} [{:?}] decoded by {} called at {}.",
                    string, t.encoding, t.decoding_routine, t.decoded_at
                );
            }
            StringOptions::StackString(t) => {
                let string = sanitize(t.string);
                info!(
                    "{} [{:?}] decoded by {} called at {}.",
                    string, t.encoding, t.function, t.program_counter
                );
            }
            StringOptions::TightString(t) => {
                let string = sanitize(t.string);
                info!(
                    "{} [{:?}] decoded by {} called at {}.",
                    string, t.encoding, t.function, t.program_counter
                );
            }
            StringOptions::StaticString(t) => {
                let string = sanitize(t.string);
                info!("{} [{:?}] is a static string.", string, t.encoding);
            }
        },
        _ => info!("{:?}", decoded_string.get_string()),
    }
}

pub fn load(
    sample: &str,
    analysis: Analysis,
    functions: Vec<i32>,
    min_length: i32,
) -> ResultDocument {
    debug!("Loading results document: {}", sample);
    let mut results = read(sample);
    results.metadata.file_path = format!("{}\n{}", sample, results.metadata.file_path);
    check_set_string_types(results.clone(), analysis);
    if !functions.is_empty() {
        filter_functions(results.clone(), functions);
    }
    if min_length > 0 {
        filter_string_len(results.clone(), min_length);
        results.metadata.min_length = min_length;
    }
    results.clone()
}

pub fn read(sample: &str) -> ResultDocument {
    let contents = fs::read(sample).expect("Could not read file.");
    let results = from_str::<ResultDocument>(from_utf8(&contents).unwrap()).unwrap();
    results
}

pub fn check_set_string_types(mut results: ResultDocument, wanted_analysis: Analysis) {
    if wanted_analysis.enable_decoded_strings && !results.analysis.enable_decoded_strings {
        warn!(
            "enable_decoded_strings not in loaded data, use --only --no to enable/disable types."
        );
        results.analysis.enable_decoded_strings = wanted_analysis.enable_decoded_strings;
    } else if wanted_analysis.enable_static_strings && !results.analysis.enable_static_strings {
        warn!("enable_static_strings not in loaded data, use --only --no to enable/disable types.");
        results.analysis.enable_static_strings = wanted_analysis.enable_static_strings;
    } else if wanted_analysis.enable_stack_strings && !results.analysis.enable_stack_strings {
        warn!("enable_stack_strings not in loaded data, use --only --no to enable/disable types.");
        results.analysis.enable_stack_strings = wanted_analysis.enable_stack_strings;
    } else if wanted_analysis.enable_tight_strings && !results.analysis.enable_tight_strings {
        warn!("enable_tight_strings not in loaded data, use --only --no to enable/disable types.");
        results.analysis.enable_tight_strings = wanted_analysis.enable_tight_strings;
    }
}

pub fn filter_functions(mut results: ResultDocument, functions: Vec<i32>) {
    let mut filtered_scores = HashMap::new();
    for fva in functions.clone() {
        *filtered_scores.get_mut(&fva).unwrap() =
            results.analysis.functions.decoding_function_scores[&fva];
    }
    results.analysis.functions.decoding_function_scores = filtered_scores;
    // results.strings.stack_strings = results.strings.stack_strings.iter().filter(|f| functions.contains(&f.function)).map(|stack_string| stack_string.clone()).collect::<Vec<_>>();
    results.strings.tight_strings = results
        .strings
        .tight_strings
        .iter()
        .filter(|function| functions.contains(&function.function)).cloned()
        .collect::<Vec<_>>();
    // results.strings.decoded_strings = results.strings.decoded_strings.iter().filter(|function| functions.contains(&function.decoding_routine)).map(|decoded_string| decoded_string.clone()).collect::<Vec<_>>();
    results.analysis.functions.analyzed_stack_strings = results.strings.stack_strings.len() as i32;
    results.analysis.functions.analyzed_tight_strings = results.strings.tight_strings.len() as i32;
    results.analysis.functions.analyzed_decoded_strings =
        results.strings.decoded_strings.len() as i32;
}

pub fn filter_string_len(mut results: ResultDocument, min_len: i32) {
    results.strings.stack_strings = results
        .strings
        .stack_strings
        .iter()
        .filter(|stack_string| stack_string.len() >= min_len as usize).cloned()
        .collect::<Vec<_>>();
    results.strings.static_strings = results
        .strings
        .static_strings
        .iter()
        .filter(|static_string| static_string.len() >= min_len as usize).cloned()
        .collect::<Vec<_>>();
    results.strings.tight_strings = results
        .strings
        .tight_strings
        .iter()
        .filter(|tight_string| tight_string.string.len() >= min_len as usize).cloned()
        .collect::<Vec<_>>();
    results.strings.decoded_strings = results
        .strings
        .decoded_strings
        .iter()
        .filter(|decoded_string| decoded_string.len() >= min_len as usize).cloned()
        .collect::<Vec<_>>();
}
