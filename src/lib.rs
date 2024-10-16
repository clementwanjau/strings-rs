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
        EXTENSIONS_SHELLCODE_32, EXTENSIONS_SHELLCODE_64,
        SUPPORTED_FILE_MAGIC,
    },
    error::{FlossError, Result},
    results::{
           ResultDocument,
         StringOptions, TightString, Verbosity,
    },
    strings::{extract_ascii_unicode_strings},
};
use log::{debug, info, trace};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    rc::Rc,
};
use std::ops::Deref;
use std::process::Command;
use serde_json::from_str;
use vivisect::{
    analysis::{EntryPointsAnalyzer, RelocationsAnalyzer, StringConstantAnalyzer},
    workspace::VivWorkspace,
};
use vivutils::{
    get_shell_code_workspace, get_shell_code_workspace_from_file,
    register_flirt_signature_analyzers,
};

/// The function to call to analyze a file.
pub fn analyze(
    path_to_sample: &str,
) -> Result<ResultDocument> {
   get_strings(path_to_sample)
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
        for dir_entry in sigs_path.read_dir().expect("Error reading directory.").flatten() {
            if dir_entry.path().clone().extension().unwrap() == "sig"
                || dir_entry.path().clone().extension().unwrap() == "pat"
                || dir_entry.path().clone().extension().unwrap() == "gz"
            {
                paths.push(format!("{}", dir_entry.path().display()));
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

fn get_strings(payload: &str) -> Result<ResultDocument> {
    #[cfg(target_os = "windows")]
    const FLOSS_FILE: &str = "assets/floss_win.exe";
    #[cfg(target_os = "macos")]
    const FLOSS_FILE: &str = "assets/floss_osx";
    #[cfg(target_os = "linux")]
    const FLOSS_FILE: &str = "assets/floss_nix";
    info!("Extracting Strings...");
    let floss = Path::new(env!("CARGO_MANIFEST_DIR")).join(FLOSS_FILE);
    let output = Command::new(floss)
        .args(["-j", payload])
        .output()?;
    let data = String::from_utf8_lossy(&output.stdout);
    let results = from_str::<ResultDocument>(data.deref())?;
    info!("Finished extracting Strings.");
    Ok(results)
}
