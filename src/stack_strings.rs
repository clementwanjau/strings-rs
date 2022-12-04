use crate::{
    error::{FlossError, Result},
    results::{StackString, Verbosity},
    utils::make_emulator,
};
use log::info;
use vivisect::{
    emulator::{GenericEmulator, OpCode, WorkspaceEmulator},
    memory::Memory,
    workspace::VivWorkspace,
};
use vivutils::{emulator_drivers::FullCoverageEmulatorDriver, function::Function};

pub const MAX_STACK_SIZE: i32 = 0x10000;
pub const MIN_NUMBER_OF_MOVS: i32 = 5;

/// Context for stackstring extraction.
/// Attributes:
/// pc: the current program counter
/// sp: the current stack counter
/// init_sp: the initial stack counter at start of function
/// stack_memory: the active stack frame contents
/// pre_ctx_strings: strings identified before this context
#[derive(Clone, Debug)]
pub struct CallContext {
    pub pc: i32,
    pub sp: i32,
    pub init_sp: i32,
    pub stack_memory: Vec<u8>,
    pub pre_ctx_strings: Option<Vec<String>>,
}

/// Observes emulation and extracts the active stack frame contents:
/// - at each function call in a function, and
/// - based on heuristics looking for mov instructions to a hardcoded buffer.
#[derive(Clone, Debug)]
pub struct StackStringContextMonitor {
    ctxs: Vec<CallContext>,
    _init_sp: i32,
    _bb_ends: Vec<i32>,
    _mov_count: i32,
}

impl StackStringContextMonitor {
    pub fn new(init_sp: i32, bb_ends: Vec<i32>) -> Self {
        StackStringContextMonitor {
            ctxs: vec![],
            _init_sp: init_sp,
            _bb_ends: bb_ends,
            _mov_count: 0,
        }
    }

    pub fn api_call(&mut self, mut emu: GenericEmulator) {
        self.update_contexts(emu.clone(), emu.get_program_counter());
    }

    pub fn update_contexts(&mut self, emu: GenericEmulator, va: i32) {
        if let Ok(context) = self.get_call_context(emu, va, None) {
            self.ctxs.push(context);
        }
    }

    /// Returns a context with the bytes on the stack between the base pointer
    /// (specifically, stack pointer at function entry), and stack pointer.
    pub fn get_call_context(
        &self,
        mut emu: GenericEmulator,
        va: i32,
        pre_ctx_strings: Option<Vec<String>>,
    ) -> Result<CallContext> {
        let stack_top = emu.get_stack_counter().unwrap();
        let stack_bottom = self._init_sp;
        let stack_size = stack_bottom - stack_top;
        if stack_size > MAX_STACK_SIZE {
            Err(FlossError::StackSizeTooBig(stack_size)) as Result<CallContext>;
        }
        let stack_buf = emu.read_memory(stack_top, stack_size).unwrap();
        let ctx = CallContext {
            pc: va,
            sp: stack_top,
            init_sp: stack_bottom,
            stack_memory: stack_buf,
            pre_ctx_strings,
        };
        Ok(ctx)
    }

    pub fn posthook(&mut self, emu: GenericEmulator, op: OpCode, endpc: i32) {
        self.check_mov_heuristics(emu, op, endpc);
    }

    ///  Extract contexts at end of a basic block (bb) if bb contains enough movs to a harcoded buffer.
    pub fn check_mov_heuristics(&mut self, emu: GenericEmulator, op: OpCode, endpc: i32) {
        if self._mov_count < MIN_NUMBER_OF_MOVS && self.is_stack_mov(op.clone()) {
            self._mov_count += 1;
        }

        if self._bb_ends.contains(&endpc) {
            if self._mov_count >= MIN_NUMBER_OF_MOVS {
                self.update_contexts(emu, op.va);
            }
            self._mov_count = 0;
        }
    }

    pub fn is_stack_mov(&self, op: OpCode) -> bool {
        if !op.mnem.starts_with("mov") {
            return false;
        }
        let operands: Option<String> = op.get_operands();
        if operands.is_none() {
            return true;
        }
        // TODO Check architecture
        false
    }
}

pub fn extract_call_contexts(vw: VivWorkspace, fva: i32, bb_ends: Vec<i32>) -> Vec<CallContext> {
    let mut emu = make_emulator(vw.clone());
    let monitor = StackStringContextMonitor::new(emu.get_stack_counter().unwrap(), bb_ends);
    let mut driver = FullCoverageEmulatorDriver::new(vw.clone(), emu, 256);
    driver.add_monitor(monitor.clone());
    driver.run(fva);
    monitor.ctxs
}

/// Return the set of VAs that are the last instructions of basic blocks.
pub fn get_basic_block_ends(mut vw: VivWorkspace) -> Vec<i32> {
    let mut index = Vec::new();
    for funcva in vw.get_functions() {
        let mut f = Function::new(vw.clone(), funcva);
        for mut bb in f.basic_blocks() {
            if bb.instructions().len() == 0 {
                continue;
            }
            index.push(bb.instructions().last().unwrap().va);
        }
    }
    index
}

/// Extracts the stackstrings from functions in the given workspace.
/// :param vw: The vivisect_rs workspace from which to extract stackstrings.
/// :param selected_functions: list of selected functions
/// :param min_length: minimum string length
/// :param verbosity: verbosity level
/// :param disable_progress: do NOT show progress bar
pub fn extract_stackstrings(
    vw: VivWorkspace,
    selected_functions: Vec<i32>,
    min_length: i32,
    verbosity: Verbosity,
    disable_progress: bool,
) -> Vec<StackString> {
    info!(
        "Extracting stack strings from {} functions.",
        selected_functions.len()
    );
    let mut stack_strings = Vec::new();
    let bb_ends = get_basic_block_ends(vw.clone());
    stack_strings
}
