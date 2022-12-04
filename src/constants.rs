pub const KILOBYTE: i32 = 1024;
pub const MEGABYTE: i32 = 1024 * KILOBYTE;
pub const MAX_FILE_SIZE: i32 = 16 * MEGABYTE;

pub const SUPPORTED_FILE_MAGIC: &[u8; 2] = b"MZ";
pub const MIN_STRING_LENGTH: i32 = 4;
pub const MAX_STRING_LENGTH: i32 = 2048;

// Decoded String (DS)
// maximum number of instructions to emulate per function
pub const DS_MAX_INSN_COUNT: i32 = 20000;
// maximum number of address revisits per function when emulating decoding functions
pub const DS_MAX_ADDRESS_REVISITS_EMULATION: i32 = 300;
// shortcut decoding of a function if only few strings are found
pub const DS_FUNCTION_MIN_DECODED_STRINGS: i32 = 5;
// decoding candidate only called a few times
pub const DS_FUNCTION_CALLS_RARE: i32 = 7;
// decoding candidate called more often
pub const DS_FUNCTION_CALLS_OFTEN: i32 = 15;
// for decoders called very often, limit threshold shortcut
pub const DS_FUNCTION_SHORTCUT_THRESHOLD_VERY_OFTEN: i32 = 15;

// Tight String (TS)
// max instruction count to emulate in a tight loop
pub const TS_MAX_INSN_COUNT: i32 = 10000;
// max basic blocks per tight function (that basically just wraps a tight loop)
pub const TS_TIGHT_FUNCTION_MAX_BLOCKS: i32 = 10;

// values used by API hooks
// FIXME: This works on windows only. Make it cross platform.
pub const MOD_NAME: &str = "C:\\Users\\flare\\program.exe";

pub const EXTENSIONS_SHELLCODE_32: (&str, &str) = ("sc32", "raw32");
pub const EXTENSIONS_SHELLCODE_64: (&str, &str) = ("sc64", "raw64");
