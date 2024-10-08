use capstone::{Capstone, RegId};
use capstone::arch::ArchOperand;
use capstone::prelude::BuildsCapstone;
use crate::{
    error::{FlossError, Result},
    results::{StackString},
    utils::make_emulator,
};
use log::{debug};
use vivisect::{
    emulator::{GenericEmulator, OpCode, WorkspaceEmulator},
    memory::Memory,
    workspace::VivWorkspace,
};
use vivutils::{emulator_drivers::FullCoverageEmulatorDriver, function::Function};
use crate::results::StringEncoding;

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
            return Err(FlossError::StackSizeTooBig(stack_size));
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
            if bb.instructions().is_empty() {
                continue;
            }
            index.push(bb.instructions().last().unwrap().va);
        }
    }
    index
}

/// Extract stack strings from a function using emulation.
pub fn extract_stack_strings(file_path: &str) -> Vec<StackString> {
    let mut stack_strings = Vec::new();
    // Open a goblin reader for the file
    let bytes = std::fs::read(file_path).unwrap();
    if let Ok(elf) = goblin::elf::Elf::parse(&bytes) {
        let arch  = match elf.header.e_machine {
            goblin::elf::header::EM_386 => capstone::arch::x86::ArchMode::Mode32,
            goblin::elf::header::EM_X86_64 => capstone::arch::x86::ArchMode::Mode64,
            _ => panic!("Unsupported architecture"),
        };
        let disasm = Capstone::new()
            .x86()
            .mode(arch)
            .detail(true).build().unwrap();
        let pc = elf.header.e_entry;
        let instructions = disasm.disasm_all(&bytes, pc).unwrap();
        debug!("Found {} instructions", instructions.len());
        for instruction in instructions.iter() {
            // Analyze instruction mnemonics and operands
            let mut potential_string = false;
            let mut string_register = "";
            let detail = disasm.insn_detail(instruction).unwrap();
            let ops = detail.arch_detail().operands();
            match instruction.mnemonic() {
                Some("mov") | Some("push") => {
                    // Check if operand is a register
                    string_register = match reg_names(&disasm, detail.regs_read()).as_str() {
                        "esp" | "rsp" => {
                            "stack_pointer"
                        }
                        _ => {
                            continue
                        }
                    };
                    potential_string = true;
                }
                _ => {}
            }
            if potential_string {
                if let ArchOperand::X86Operand(operand) = &ops[1] {
                    if let capstone::arch::x86::X86OperandType::Imm(imm) = operand.op_type {
                        // Check if immediate value is a null-terminated string address
                        let string_addr = (pc + instruction.address() + imm as u64) as usize;
                        if is_null_terminated_string(&bytes[string_addr..]).unwrap() {
                            println!("Potential stack string (register: {}, address: 0x{:x?}):", string_register, string_addr);
                            // Print the string at the address (up to a certain limit to avoid garbage)
                            let string_chars = &bytes[string_addr..]
                                .iter()
                                .take_while(|byte| **byte != 0)
                                .map(|byte| *byte as char)
                                .collect::<String>();
                            let stack_string = StackString {
                                function: pc as i32,
                                string: string_chars.clone(),
                                encoding: StringEncoding::UTF16LE,
                                program_counter: pc as i32,
                                stack_pointer: string_addr as i32,
                                original_stack_pointer: 0,
                                offset: 0,
                                frame_offset: 0,
                            };
                            stack_strings.push(stack_string);
                        }
                    }
                }
            }
        }
    }
    stack_strings
}

fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

// Helper function to check for null-terminated string (replace with your implementation)
fn is_null_terminated_string(data: &[u8]) -> std::result::Result<bool, &'static str> {
    for byte in data {
        if *byte == 0 {
            return Ok(true);
        }
    }
    Err("Not null-terminated")
}
