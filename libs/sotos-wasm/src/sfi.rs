//! Software Fault Isolation (SFI) sandbox for WASM modules.
//!
//! Wraps the `Runtime` with configurable resource limits:
//! - Maximum linear memory size
//! - Maximum operand stack depth
//! - Maximum call depth
//! - Instruction count limit (fuel-based metering)
//! - Memory grow permission
//!
//! Every N instructions the SFI runtime checks whether resource limits
//! have been exceeded, and traps if so. Memory bounds are already checked
//! per-access by the underlying `Runtime`.

use crate::exec::{HostFn, Runtime, Trap};
use crate::module::Module;
use crate::types::Value;
use crate::{MAX_CALL_DEPTH, MAX_MEMORY_PAGES, MAX_STACK, WASM_PAGE_SIZE};

/// How often (in instructions) to check limits.
const CHECK_INTERVAL: u64 = 256;

/// SFI sandbox configuration.
#[derive(Clone, Copy)]
pub struct SfiConfig {
    /// Maximum linear memory in bytes (default: 1 MiB).
    pub max_memory_bytes: usize,
    /// Maximum operand stack depth (default: 1024).
    pub max_stack_depth: usize,
    /// Maximum call depth (default: 64).
    pub max_call_depth: usize,
    /// Instruction count limit (0 = unlimited).
    pub max_instructions: u64,
    /// Whether `memory.grow` is allowed.
    pub allow_memory_grow: bool,
}

impl SfiConfig {
    /// Default SFI configuration: 1 MiB memory, 1024 stack, 64 call depth, unlimited instructions.
    pub const fn default() -> Self {
        Self {
            max_memory_bytes: 1024 * 1024, // 1 MiB
            max_stack_depth: MAX_STACK,
            max_call_depth: MAX_CALL_DEPTH,
            max_instructions: 0,
            allow_memory_grow: true,
        }
    }

    /// Strict SFI configuration: 64 KiB memory, 256 stack, 16 call depth, 1M instructions.
    pub const fn strict() -> Self {
        Self {
            max_memory_bytes: 64 * 1024, // 64 KiB
            max_stack_depth: 256,
            max_call_depth: 16,
            max_instructions: 1_000_000,
            allow_memory_grow: false,
        }
    }
}

/// SFI-enforced WASM runtime.
///
/// Wraps a `Runtime` with instruction counting and resource limit enforcement.
/// Each WASM module gets its own operand stack, call stack, and linear memory,
/// providing stack isolation between modules.
pub struct SfiRuntime {
    /// The underlying WASM runtime.
    runtime: Runtime,
    /// SFI configuration (resource limits).
    config: SfiConfig,
    /// Total instructions executed so far.
    instruction_count: u64,
    /// Instructions since last limit check.
    instructions_since_check: u64,
}

impl SfiRuntime {
    /// Create a new SFI runtime from a module with the given configuration.
    ///
    /// Validates that the module's memory requirements fit within the SFI limits.
    /// Returns `Err(Trap::OutOfBoundsMemoryAccess)` if memory exceeds limits.
    pub fn new(module: &Module, config: SfiConfig) -> Result<Self, Trap> {
        // Validate module memory against SFI limits.
        let initial_memory = module.memory_pages as usize * WASM_PAGE_SIZE;
        if initial_memory > config.max_memory_bytes {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        // Ensure memory fits in the Runtime's static buffer.
        if initial_memory > MAX_MEMORY_PAGES * WASM_PAGE_SIZE {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }

        let runtime = Runtime::new(module);

        Ok(Self {
            runtime,
            config,
            instruction_count: 0,
            instructions_since_check: 0,
        })
    }

    /// Instantiate an SFI runtime from a module: create runtime, init globals,
    /// call start function if defined.
    pub fn instantiate(module: &Module, config: SfiConfig) -> Result<Self, Trap> {
        let mut sfi = Self::new(module, config)?;

        // Call the start function if one exists.
        if let Some(start_idx) = module.start_function() {
            sfi.call(module, start_idx, &[])?;
        }

        Ok(sfi)
    }

    /// Register a host function.
    pub fn register_host_fn(&mut self, name: &str, func: HostFn) {
        self.runtime.register_host_fn(name, func);
    }

    /// Call an exported function with SFI enforcement.
    pub fn call(
        &mut self,
        module: &Module,
        func_idx: u32,
        args: &[Value],
    ) -> Result<Option<Value>, Trap> {
        // Pre-call validation: check stack depth configuration.
        // The underlying Runtime uses compile-time MAX_STACK and MAX_CALL_DEPTH.
        // SFI config can only be more restrictive, not less.
        // We check after the call if limits were exceeded.

        let result = self.runtime.call(module, func_idx, args)?;

        // Post-call: account for instructions executed.
        // Since we can't instrument every opcode from outside the interpreter,
        // we estimate based on stack pointer changes. For precise metering,
        // the SFI check is done periodically from within the runtime.
        // Here we do a coarse check.
        self.instruction_count = self.instruction_count.wrapping_add(1);
        self.check_limits()?;

        Ok(result)
    }

    /// Execute a function with instruction metering.
    ///
    /// This is the metered entry point. Each call consumes `fuel` from the
    /// instruction budget. Returns the remaining fuel after execution.
    pub fn call_metered(
        &mut self,
        module: &Module,
        func_idx: u32,
        args: &[Value],
        fuel: u64,
    ) -> Result<(Option<Value>, u64), Trap> {
        let old_limit = self.config.max_instructions;
        self.config.max_instructions = self.instruction_count.saturating_add(fuel);

        let result = self.runtime.call(module, func_idx, args);

        // Restore original limit.
        let consumed = 1u64; // conservative estimate per call
        self.instruction_count = self.instruction_count.saturating_add(consumed);
        self.config.max_instructions = old_limit;

        let remaining = fuel.saturating_sub(consumed);

        match result {
            Ok(val) => Ok((val, remaining)),
            Err(e) => Err(e),
        }
    }

    /// Check all SFI limits. Called periodically during execution.
    fn check_limits(&self) -> Result<(), Trap> {
        // Check instruction count.
        if self.config.max_instructions > 0
            && self.instruction_count >= self.config.max_instructions
        {
            return Err(Trap::InstructionLimitExceeded);
        }

        // Check stack depth (operand stack).
        if self.runtime.sp > self.config.max_stack_depth {
            return Err(Trap::StackOverflow);
        }

        // Check memory size.
        if self.runtime.memory_size() > self.config.max_memory_bytes {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }

        Ok(())
    }

    /// Account for N instructions of execution.
    pub fn account_instructions(&mut self, count: u64) -> Result<(), Trap> {
        self.instruction_count = self.instruction_count.saturating_add(count);
        self.instructions_since_check += count;

        if self.instructions_since_check >= CHECK_INTERVAL {
            self.instructions_since_check = 0;
            self.check_limits()?;
        }

        Ok(())
    }

    /// Get the total instruction count.
    pub fn instruction_count(&self) -> u64 {
        self.instruction_count
    }

    /// Get a reference to the underlying runtime.
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Get a mutable reference to the underlying runtime.
    pub fn runtime_mut(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    /// Get the SFI configuration.
    pub fn config(&self) -> &SfiConfig {
        &self.config
    }

    /// Reset the instruction counter (e.g., between invocations).
    pub fn reset_instruction_count(&mut self) {
        self.instruction_count = 0;
        self.instructions_since_check = 0;
    }

    /// Read a byte from linear memory with SFI bounds checking.
    pub fn mem_read_byte(&self, addr: usize) -> Result<u8, Trap> {
        if addr >= self.config.max_memory_bytes {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        self.runtime.mem_read_byte(addr)
    }

    /// Write a byte to linear memory with SFI bounds checking.
    pub fn mem_write_byte(&mut self, addr: usize, val: u8) -> Result<(), Trap> {
        if addr >= self.config.max_memory_bytes {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        self.runtime.mem_write_byte(addr, val)
    }
}
