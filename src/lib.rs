extern crate core;

pub mod api_hooks;
pub mod constants;
pub mod error;
pub mod identify;
pub mod results;
pub mod sanitize;
pub mod stack_strings;
pub mod strings;
pub mod utils;

use self::{
    constants::{
        EXTENSIONS_SHELLCODE_32, EXTENSIONS_SHELLCODE_64, MAX_FILE_SIZE, MIN_STRING_LENGTH,
        SUPPORTED_FILE_MAGIC,
    },
    error::{FlossError, Result},
    results::{
        Analysis, DecodedString, Functions, Metadata, ResultDocument, StackString, StaticString,
        StringEncoding, StringOptions, TightString, Verbosity,
    },
    strings::{extract_ascii_unicode_strings, extract_tight_strings},
    utils::{
        append_unique, find_decoding_function_features, get_function_fvas,
        get_functions_with_tightloops, get_runtime_diff, get_tight_function_fvas,
        get_top_functions, get_vivisect_meta_info, is_string_type_enabled,
    },
};
use crate::stack_strings::extract_stack_strings2;
use chrono::Local;
use log::{debug, info, trace, warn};
use rust_strings::{Encoding, FileConfig};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::exit,
    rc::Rc,
};
use vivisect::{
    analysis::{EntryPointsAnalyzer, RelocationsAnalyzer, StringConstantAnalyzer},
    workspace::VivWorkspace,
};
use vivutils::{
    get_imagebase, get_shell_code_workspace, get_shell_code_workspace_from_file,
    register_flirt_signature_analyzers,
};

/// The function to call to analyze a file.
pub fn analyze(
    path_to_sample: &str,
    disabled_types: Vec<StringOptions>,
    enabled_types: Vec<StringOptions>,
    format: &str,
    signature_path: &str,
    should_save_workspace: bool,
) -> Result<ResultDocument> {
    if is_string_type_enabled(
        StringOptions::StaticString(StaticString::default()),
        disabled_types.clone(),
        enabled_types.clone(),
    ) {
        warn!("Analyzing specified functions, not showing static strings.")
    }
    let analysis = Analysis {
        enable_static_strings: is_string_type_enabled(
            StringOptions::StaticString(StaticString::default()),
            disabled_types.clone(),
            enabled_types.clone(),
        ),
        enable_stack_strings: is_string_type_enabled(
            StringOptions::StackString(StackString::default()),
            disabled_types.clone(),
            enabled_types.clone(),
        ),
        enable_tight_strings: is_string_type_enabled(
            StringOptions::TightString(TightString::default()),
            disabled_types.clone(),
            enabled_types.clone(),
        ),
        enable_decoded_strings: is_string_type_enabled(
            StringOptions::DecodedString(DecodedString::default()),
            disabled_types.clone(),
            enabled_types.clone(),
        ),
        functions: Functions::default(),
    };
    let mut results =
        ResultDocument::new(Metadata::new(path_to_sample, MIN_STRING_LENGTH), analysis);
    let time0 = Local::now();
    let mut _interim = Local::now();
    let sample_size = File::open(path_to_sample)
        .unwrap()
        .read(&mut Vec::new())
        .unwrap() as i32;
    // In order of expected run time. Fast to slow.
    // 1. Static strings,
    // 2. Stack strings,
    // 3. Tight strings,
    // 4. Decoded strings
    if results.analysis.enable_static_strings {
        info!("Extracting static strings...");
        // Load the contents of the binary file
        // panic
        // short
        // i8, i16, i32, i64, // Signed integers, -23, -278761
        // u8, u16, u32, u64 // Positive integers
        results.strings.static_strings = Vec::new();
        results.metadata.runtime.static_strings = get_runtime_diff(_interim);
        _interim = Local::now();
    }
    if results.analysis.enable_decoded_strings
        || results.analysis.enable_stack_strings
        || results.analysis.enable_tight_strings
    {
        if sample_size > MAX_FILE_SIZE {
            eprintln!(
                "Cannot de-obufscate strings from files larger than {} bytes.",
                MAX_FILE_SIZE
            );
            exit(-1);
        }
        // Add ASCII strings
        let mut config = FileConfig::new(Path::new(path_to_sample))
            .with_min_length(MIN_STRING_LENGTH as usize)
            .with_encoding(Encoding::ASCII);
        let mut extracted_strings = rust_strings::strings(&config).unwrap();

        results.strings.static_strings = extracted_strings
            .iter()
            .map(|x| x.0.clone())
            .collect::<Vec<_>>();
        // Add UTF16_LE strings
        config = FileConfig::new(Path::new(path_to_sample))
            .with_min_length(MIN_STRING_LENGTH as usize)
            .with_encoding(Encoding::UTF16LE);
        extracted_strings = rust_strings::strings(&config).unwrap();
        results.strings.static_strings.append(
            &mut extracted_strings
                .iter()
                .map(|x| x.0.clone())
                .collect::<Vec<_>>(),
        );
        let dead_data = extracted_strings
            .clone()
            .iter()
            .map(|x| (x.0.clone(), x.1 as i32))
            .collect::<Vec<_>>();
        let mut workspace = load_workspace(
            path_to_sample,
            format,
            signature_path,
            should_save_workspace,
            dead_data,
        )
        .unwrap_or_else(|_| panic!("Failed to analyze sample: {}", path_to_sample));

        info!("Finished loading workspace.");
        results.metadata.imagebase = get_imagebase(workspace.clone());
        let selected_functions = select_functions(workspace.clone(), None);
        results.analysis.functions.discovered = workspace.get_functions().len() as i32;

        let (decoding_function_features, _library_functions) = find_decoding_function_features(
            workspace.clone(),
            selected_functions.as_ref().cloned().unwrap(),
        );
        results.analysis.functions.library = workspace.library_functions.len() as i32;
        results.metadata.runtime.find_features = get_runtime_diff(_interim);
        _interim = Local::now();
        trace!("Analysis summary:");
        for (key, val) in get_vivisect_meta_info(
            workspace.clone(),
            selected_functions.as_ref().cloned().unwrap(),
            decoding_function_features.clone(),
        ) {
            trace!(" {}: {}", key, val);
        }

        if results.analysis.enable_stack_strings {
            if results.analysis.enable_tight_strings {
                // selected_functions = get_fun
            }
            results.strings.stack_strings = extract_stack_strings2(path_to_sample)?
                .iter()
                .map(|x| x.string.clone())
                .collect::<Vec<_>>();
            results.analysis.functions.analyzed_stack_strings =
                selected_functions.as_ref().cloned().unwrap().len() as i32;
            results.metadata.runtime.stack_strings = get_runtime_diff(_interim);
            _interim = Local::now();
        }
        if results.analysis.enable_tight_strings {
            let tight_loop_functions =
                get_functions_with_tightloops(decoding_function_features.clone());
            results.strings.tight_strings = extract_tight_strings(
                workspace.clone(),
                tight_loop_functions.clone(),
                MIN_STRING_LENGTH,
                Verbosity::DEFAULT,
                true,
            );
            results.analysis.functions.analyzed_tight_strings = tight_loop_functions.len() as i32;
            results.metadata.runtime.tight_strings = get_runtime_diff(_interim);
            _interim = Local::now();
        }
        if results.analysis.enable_decoded_strings {
            let top_functions = get_top_functions(decoding_function_features.clone(), 20);
            let mut fvas_to_emulate = get_function_fvas(top_functions);
            let fvas_tight_functions = get_tight_function_fvas(decoding_function_features);
            fvas_to_emulate = append_unique(fvas_to_emulate, fvas_tight_functions);
            if fvas_to_emulate.is_empty() {
                info!("No candidate decoding functions found.");
            } else {
                debug!(
                    "Identified {} candidate decoding functions",
                    fvas_to_emulate.len()
                );
            }
        }
    }

    results.metadata.runtime.total = get_runtime_diff(time0);
    info!(
        "Finished execution after {} seconds.",
        results.metadata.runtime.total
    );
    Ok(results.clone())
}

/// Given a workspace and an optional list of function addresses,
/// collect the set of valid functions,
/// or all valid function addresses.
/// arguments:
/// asked_functions: the functions a user wants, or None.
pub fn select_functions(
    mut workspace: VivWorkspace,
    asked_functions: Option<Vec<i32>>,
) -> Result<Vec<i32>> {
    let functions = workspace.get_functions();
    if asked_functions.is_none() {
        // User did not specify anything, so we return them all.
        debug!("Selected ALL functions.");
        return Ok(functions);
    }
    let asked_functions_ = asked_functions.unwrap();
    let missing_functions = asked_functions_
        .iter()
        .filter(|&x| functions.contains(x))
        .map(|x| format!("{:#0x}", x))
        .collect::<Vec<_>>();
    if !missing_functions.is_empty() {
        return Err(FlossError::InvalidAddress(format!(
            "Failed to find functions {}",
            missing_functions.join(", ")
        )));
    }
    debug!("Selected {} functions", asked_functions_.len());
    trace!(
        "Selected the following functions {}",
        asked_functions_
            .iter()
            .map(|x| format!("{:#0x}", x))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(asked_functions_)
}

/// Return if FLOSS supports the input file type, based on header bytes
/// :param sample_file_path:
/// :return: True if file type is supported, False otherwise
pub fn is_supported_file_type(sample_file_path: &str) -> bool {
    let mut magic_bytes = vec![2; 0];
    File::open(sample_file_path)
        .expect("Could not open the sample file.")
        .read_exact(&mut magic_bytes)
        .unwrap();
    return SUPPORTED_FILE_MAGIC == magic_bytes.as_slice();
}

pub fn load_workspace(
    sample_path: &str,
    mut format: &str,
    signature_path: &str,
    should_save_workspace: bool,
    dead_data: Vec<(String, i32)>,
) -> Result<VivWorkspace> {
    if !["sc32", "sc64"].contains(&format) && !is_supported_file_type(sample_path) {
        return Err(FlossError::WorkspaceLoadError("FLOSS currently supports the following formats for string decoding and stackstrings: PE\n
            You can analyze shellcode using the --format sc32|sc64 switch. See the help (-h) for more information.".to_string()));
    }
    if format == "auto"
        && (sample_path.ends_with(EXTENSIONS_SHELLCODE_32.0)
            || sample_path.ends_with(EXTENSIONS_SHELLCODE_32.1))
    {
        format = "sc32";
    } else if format == "auto"
        && (sample_path.ends_with(EXTENSIONS_SHELLCODE_64.0)
            || sample_path.ends_with(EXTENSIONS_SHELLCODE_64.1))
    {
        format = "sc64";
    }
    let mut workspace;
    if format == "sc32" {
        workspace = get_shell_code_workspace_from_file(sample_path, "i368", false);
    } else if format == "sc64" {
        workspace = get_shell_code_workspace_from_file(sample_path, "amd64", false);
    } else {
        workspace = get_shell_code_workspace(fs::read(sample_path).unwrap(), None, false);
    }
    workspace._dead_data = dead_data;
    let sig_paths = match get_signatures(signature_path) {
        Ok(t) => t,
        _ => Vec::new(),
    };
    register_flirt_signature_analyzers(&mut workspace, sig_paths);
    workspace.load_from_file(sample_path, Some(format.to_string()), None);
    // Register the analyzers
    workspace.add_analyzer(Rc::new(RelocationsAnalyzer::new()));
    workspace.add_analyzer(Rc::new(EntryPointsAnalyzer::new()));
    workspace.add_analyzer(Rc::new(StringConstantAnalyzer::new()));
    workspace.analyze(sample_path);

    if should_save_workspace {
        debug!("Saving workspace.");
        workspace.save_workspace();
    } else {
        debug!("Not saving workspace.");
    }
    Ok(workspace.clone())
}

pub fn get_signatures(signature_path: &str) -> Result<Vec<String>> {
    let sigs_path = Path::new(signature_path);
    if !sigs_path.exists() {
        return Err(FlossError::MissingSignatures);
    }
    let mut paths = Vec::new();
    if sigs_path.is_file() {
        paths.push(format!("{}", sigs_path.display()));
    } else if sigs_path.is_dir() {
        debug!("Reading signatures from directory {}", sigs_path.display());
        for dir_entry in sigs_path
            .read_dir()
            .expect("Error reading directory.")
            .flatten()
        {
            if let Some(ext) = dir_entry.path().clone().extension() {
                if ["sig", "pat", "gz"].contains(&ext.to_str().unwrap()) {
                    paths.push(format!("{}", dir_entry.path().display()));
                }
            }
        }
    }
    // Sort the signatures in deterministic order the alphabetic sorting of filename.
    //  this means that `0_sigs.pat` loads before `1_sigs.pat`.
    paths.sort();
    for path in paths.clone() {
        debug!("Found signature file {}", path);
    }
    Ok(paths.clone())
}
