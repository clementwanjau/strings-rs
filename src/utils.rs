use crate::{
    constants::{MAX_STRING_LENGTH, MEGABYTE, MOD_NAME},
    error::{FlossError, Result},
    extract_ascii_unicode_strings,
    identify::get_function_meta,
    results::{StaticString, StringOptions},
};
use chrono::{DateTime, Local};
use lazy_static::lazy_static;
use log::{debug, info, trace, warn};
use regex::Regex;
use std::{collections::HashMap, ops::Sub};
use vivisect::{
    emulator::{Emulator, GenericEmulator, WorkspaceEmulator},
    workspace::VivWorkspace,
};
use vivutils::{
    function::Function,
    {get_function_name, is_library_function, is_thunk_function, remove_default_vivi_hooks},
};

lazy_static! {
    pub static ref ENABLED_VIV_DEFAULT_HOOKS: Vec<String> = vec![
        "kernel32.LoadLibraryA".to_string(),
        "kernel32.LoadLibraryW".to_string(),
        "kernel32.GetProcAddress".to_string(),
        "kernel32.GetModuleHandleA".to_string(),
        "kernel32.GetModuleHandleW".to_string(),
        "kernel32.LoadLibraryExA".to_string(),
        "kernel32.LoadLibraryExW".to_string(),
        // TODO the below APIs are named incorrectly currently in vivisect_rs, should be fixed in vivisect_rs > 1.0.8
        "kernel32.GetModuleHandleExA".to_string(),
        "kernel32.GetModuleHandleExW".to_string(),
    ];
    pub static ref FP_STRINGS: Vec<String>  = vec![
        "R6002".to_string(),
        "R6016".to_string(),
        "R6030".to_string(),
        "Program: ".to_string(),
        "Runtime Error!".to_string(),
        "bad locale name".to_string(),
        "ios_base::badbit set".to_string(),
        "ios_base::eofbit set".to_string(),
        "ios_base::failbit set".to_string(),
        "- CRT not initialized".to_string(),
        "program name unknown>".to_string(),
        "<program name unknown>".to_string(),
        "- floating point not loaded".to_string(),
        "Program: <program name unknown>".to_string(),
        "- not enough space for thread data".to_string(),
        " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~".to_string()
    ];

    pub static ref FP_FLOSS_ARTIFACTS: Vec<&'static str> = vec![
        MOD_NAME,
        &MOD_NAME[1..],
        &MOD_NAME[2..],
        &MOD_NAME[..MOD_NAME.len()],
        &MOD_NAME[1..MOD_NAME.len()],
        &MOD_NAME[2..MOD_NAME.len()]
    ];
}
pub const FP_FILTER_PREFIX_1: &str = r"^.{0,2}[0pP]?[]^\[_\\V]A";
pub const FP_FILTER_SUFFIX_1: &str = r"[0pP]?[VWU][A@]$|Tp$";
pub const FP_FILTER_REP_CHARS_1: &str = r"([ -~])\\1{3,}";
pub const FP_FILTER_REP_CHARS_2: &str = r"([^% ]{4})\\1{4,}";
pub const MAX_STRING_LENGTH_FILTER_STRICT: i32 = 6;
// e.g. [ESC], [Alt], %d.dll
pub const FP_FILTER_STRICT_INCLUDE: &str = r"^\[.*?]$|%[sd]";
// remove special characters
pub const FP_FILTER_STRICT_SPECIAL_CHARS: &str = r"[^A-Za-z0-9.]";
pub const FP_FILTER_STRICT_KNOWN_FP: &str = r"^O.*A$";
pub const STACK_MEM_NAME: &str = "[stack]";

pub const TIGHT_LOOP: i32 = 0;
pub const KINDA_TIGHT_LOOP: i32 = 1;
pub const TIGHT_FUNCTION: i32 = 2;

pub type FunctionFva = HashMap<String, HashMap<String, i32>>;

pub struct ExtendAction {}

/// Create an emulator using consistent settings.
pub fn make_emulator(mut workspace: VivWorkspace) -> GenericEmulator {
    let mut emu = workspace.get_emulator(true, b"\xFE");
    remove_stack_memory(emu.clone());
    emu.init_stack_memory((0.5 * MEGABYTE as f32) as usize);
    let stack_counter = emu.get_stack_counter().unwrap();
    emu.set_stack_counter(stack_counter - (0.25 * MEGABYTE as f32) as i32);
    emu.set_emu_opt("i386:repmax", 256);
    remove_default_vivi_hooks(emu.clone(), Some(ENABLED_VIV_DEFAULT_HOOKS.clone()));
    emu.clone()
}

pub fn remove_stack_memory(mut emu: GenericEmulator) {
    let memory_snap: Vec<(i32, i32, Vec<String>, i32)> = emu.get_memory_snap();
    for _ in (-1..memory_snap.len() as i32 - 1).step_by(1) {
        let (_, _, info, _) = memory_snap.get(1).unwrap();
        if info[3] == STACK_MEM_NAME {
            emu.set_memory_snap(memory_snap);
            *emu.get_stack_map_base() = None;
            return;
        }
    }
    panic!("STACK_MEM_NAME not in memory map.")
}

/// Convenience debugging routine for showing
/// state current state of the stack.
pub fn dump_stack(mut emu: GenericEmulator) -> String {
    let esp: i32 = emu.get_stack_counter().unwrap();
    let mut stack_str = String::new();
    for i in (-16..16).step_by(4) {
        let sp = if i == 0 {
            "<= SP".to_string()
        } else {
           format!("{}", -i)
        };
        stack_str = format!(
            "{}\n0x{} - 0x{} {}",
            stack_str,
            esp - i,
            get_stack_value(emu.clone(), -i),
            sp
        );
    }
    trace!("{}", stack_str.as_str());
    stack_str
}

pub fn get_stack_value(mut emu: GenericEmulator, offset: i32) -> i32 {
    let stack_counter = emu.get_stack_counter().unwrap();
    *emu.read_memory_format(stack_counter + offset, "<P").first()
        .unwrap()
}

pub fn get_pointer_size(workspace: VivWorkspace) -> Result<i32> {
    match workspace.arch as i32 {
        vivisect::constants::ARCH_AMD64  => Ok(8),
        vivisect::constants::ARCH_I386 => Ok(4),
        t => Err(FlossError::UnexpectedArchitecture(t)),
    }
}

pub fn get_vivisect_meta_info(
    mut workspace: VivWorkspace,
    selected_functions: Vec<i32>,
    decoding_function_features: HashMap<i32, HashMap<String, HashMap<String, i32>>>,
) -> HashMap<String, String> {
    let entry_points: Vec<i32> = workspace.get_entry_points();
    let mut info = HashMap::new();
    let mut basename: Option<String> = None;
    if !entry_points.is_empty() {
        basename = workspace.get_file_by_va(*entry_points.first().unwrap());
    }
    let mut version = 0;
    let mut md5sum = 0;
    let mut baseva = 0;
    if basename.is_some() && basename.as_ref().cloned().unwrap() != *"blob" {
        version = workspace.get_file_meta(basename.as_ref().cloned().unwrap().as_str(), "Version");
        md5sum = workspace.get_file_meta(basename.as_ref().cloned().unwrap().as_str(), "md5sum");
        baseva = workspace.get_file_meta(basename.as_ref().cloned().unwrap().as_str(), "imagebase");
    }
    info.insert("version".to_string(), version.to_string());
    info.insert("md5 sum".to_string(), md5sum.to_string());
    info.insert(
        "format".to_string(),
        workspace
            .get_meta("Format")
            .get_or_insert("Generic".to_string())
            .clone(),
    );
    info.insert(
        "architecture".to_string(),
        workspace
            .get_meta("Architecture")
            .get_or_insert("Generic".to_string())
            .clone(),
    );
    info.insert(
        "platform".to_string(),
        workspace
            .get_meta("Platform")
            .get_or_insert("Unknown".to_string())
            .clone(),
    );
    let disc: i32 = workspace.get_discovered_info().0;
    let undisc: i32 = workspace.get_discovered_info().1;
    if (disc + undisc) > 0 {
        info!(
            "Percentage of discovered executable surface area = {}% ({} / {})",
            disc * 100 / (disc + undisc),
            disc,
            disc + undisc
        );
    }
    info.insert("base VA".to_string(), baseva.to_string());
    info.insert(
        "entry point(s)".to_string(),
        entry_points
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    // info.insert("number of imports".to_string(), workspace.get_imports().len());
    // info.insert("number of exports".to_string(), workspace.get_exports().len());
    info.insert(
        "number of functions".to_string(),
        workspace.get_functions().len().to_string(),
    );

    if !selected_functions.is_empty() {
        let mut meta = Vec::new();
        for fva in selected_functions {
            let xrefs_to = workspace.get_xrefs_to(fva, Some(0)).len();
            let num_args = workspace.get_function_args(fva).len();
            let function_meta = workspace.get_function_meta_dict(fva);
            let instr_count: i32 = *function_meta.get("InstructionCount").unwrap();
            let block_count: i32 = *function_meta.get("BlockCount").unwrap();
            let size: i32 = *function_meta.get("Size").unwrap();
            let score = *decoding_function_features
                .get(&fva)
                .unwrap()
                .get(&"meta".to_string())
                .unwrap()
                .clone()
                .get("score")
                .unwrap();
            meta.append(&mut vec![
                fva,
                score,
                xrefs_to as i32,
                num_args as i32,
                size,
                block_count,
                instr_count,
            ]);
            info.insert(
                "Selected functions' info".to_string(),
                meta.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
    }

    info.clone()
}

pub fn extract_strings(
    buffer: Vec<u8>,
    min_length: i32,
    exclude: Vec<String>,
) -> Option<Vec<StaticString>> {
    if buffer.len() < min_length as usize {
        return None;
    }
    let mut strings = Vec::new();
    for s in extract_ascii_unicode_strings(buffer, MAX_STRING_LENGTH) {
        if s.string.len() as i32 > MAX_STRING_LENGTH {
            continue;
        }
        if FP_STRINGS.contains(&s.string) {
            continue;
        }
        if FP_FLOSS_ARTIFACTS.contains(&s.string.as_str()) {
            trace!("Filtered floss artifact {}", s.string.clone());
            continue;
        }
        let decoded_string: String = strip_string(s.string.clone());
        if decoded_string.len() < min_length as usize {
            trace!("Filtered {} -> {}", s.string, decoded_string);
            continue;
        }
        trace!("Strip {} -> {}", s.string, decoded_string);
        if !exclude.is_empty() && exclude.contains(&decoded_string) {
            continue;
        }
        strings.push(StaticString {
            string: decoded_string,
            offset: s.offset,
            encoding: s.encoding,
        });
    }
    Some(strings)
}

/// Return string stripped from false positive (FP) pre- or suffixes.
/// :param s: input string
/// :return: string stripped from FP pre- or suffixes
pub fn strip_string(mut text: String) -> String {
    let reg_patterns: Vec<Regex> = vec![
        Regex::new(FP_FILTER_PREFIX_1).unwrap(),
        Regex::new(FP_FILTER_SUFFIX_1).unwrap(),
        Regex::new(FP_FILTER_REP_CHARS_1).unwrap(),
        Regex::new(FP_FILTER_REP_CHARS_2).unwrap(),
    ];
    let reg_patterns_2 = vec![
        Regex::new(FP_FILTER_STRICT_KNOWN_FP).unwrap(),
        Regex::new(FP_FILTER_STRICT_SPECIAL_CHARS).unwrap(),
    ];

    for regex in reg_patterns {
        text = regex.replace("", text).to_string();
    }
    if text.len() as i32 <= MAX_STRING_LENGTH_FILTER_STRICT && !Regex::new(FP_FILTER_STRICT_INCLUDE)
            .unwrap()
            .is_match(text.as_str()) {
        for regex in reg_patterns_2 {
            text = regex.replace("", text).to_string();
        }
    }
    text
}

pub fn is_string_type_enabled(
    string_opt: StringOptions,
    disabled_types: Vec<StringOptions>,
    enabled_types: Vec<StringOptions>,
) -> bool {
    if !disabled_types.is_empty() {
        !disabled_types.contains(&string_opt)
    } else if !enabled_types.is_empty() {
        enabled_types.contains(&string_opt)
    } else {
        true
    }
}

pub fn get_runtime_diff(time: DateTime<Local>) -> i64 {
    Local::now().sub(time).num_seconds()
}

pub fn find_decoding_function_features(
    workspace: VivWorkspace,
    functions: Vec<i32>,
) -> (
    HashMap<i32, FunctionFva>,
    HashMap<i32, String>,
) {
    let mut decoding_candidate_functions = HashMap::new();
    let mut library_functions = HashMap::new();
    for function in functions {
        if is_thunk_function(workspace.clone(), function) {
            continue;
        }
        if is_library_function(workspace.clone(), function) {
            let function_name: String = get_function_name(workspace.clone(), function);
            debug!(
                "Skipping library function {:#0x} ({})",
                function, function_name
            );
            library_functions.insert(function, function_name);
            continue;
        }
        let f: Function = Function::new(workspace.clone(), function);
        let mut functions_data = HashMap::new();
        functions_data.insert("meta".to_string(), get_function_meta(f.clone()));
        decoding_candidate_functions.insert(function, functions_data);
    }
    (decoding_candidate_functions, library_functions)
}

pub fn get_functions_with_tightloops(
    functions: HashMap<i32, FunctionFva>,
) -> HashMap<i32, Vec<i32>> {
    get_functions_with_features(functions, vec![TIGHT_LOOP, KINDA_TIGHT_LOOP])
}

pub fn get_functions_with_features(
    functions: HashMap<i32, FunctionFva>,
    features: Vec<i32>,
) -> HashMap<i32, Vec<i32>> {
    let mut functions_by_features = HashMap::new();
    for (fva, function_data) in functions {
        let func_features = function_data
            .get("features")
            .get_or_insert(&HashMap::new())
            .iter()
            .filter(|x| features.contains(x.1))
            .map(|x| *x.1)
            .collect::<Vec<_>>();
        if !func_features.is_empty() {
            functions_by_features.insert(fva, func_features);
        }
    }
    functions_by_features
}

pub fn get_top_functions(
    functions: HashMap<i32, FunctionFva>,
    index: i32,
) -> Vec<(i32, FunctionFva)> {
    let mut funcs = functions
        .iter()
        .map(|(fva, meta)| (*fva, meta.clone()))
        .collect::<Vec<_>>();
    if index > funcs.len() as i32 {
        warn!("The provided index is greater than the length of the functions provided.");
        return functions
            .iter()
            .map(|x| (*x.0, x.1.clone()))
            .collect::<Vec<_>>();
    }
    funcs.sort_by(|x, y| {
        x.1.get("meta")
            .unwrap()
            .get("score")
            .unwrap()
            .partial_cmp(y.1.get("meta").unwrap().get("score").unwrap())
            .unwrap()
    });
    funcs[index as usize..].to_vec()
}

pub fn get_tight_function_fvas(
    functions: HashMap<i32, HashMap<String, HashMap<String, i32>>>,
) -> Vec<(i32, FunctionFva)> {
    let mut tight_functions_fva = Vec::new();
    for (fva, function_data) in functions {
        let func_features = function_data
            .get("features")
            .get_or_insert(&HashMap::new())
            .iter()
            .filter(|x| *x.1 == TIGHT_FUNCTION)
            .map(|x| *x.1)
            .collect::<Vec<_>>();
        if !func_features.is_empty() {
            tight_functions_fva.push((fva, function_data));
        }
    }
    tight_functions_fva
}

pub fn append_unique(
    mut functions: Vec<i32>,
    tight_funcs: Vec<(i32, FunctionFva)>,
) -> Vec<i32> {
    for fva in tight_funcs {
        if !functions.contains(&fva.0) {
            functions.push(fva.0);
        }
    }
    functions
}

pub fn get_function_fvas(functions: Vec<(i32, FunctionFva)>) -> Vec<i32> {
    let fvas = functions.iter().map(|x| x.0).collect::<Vec<_>>();
    fvas
}