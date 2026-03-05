//! WASM module parser — reads binary `.wasm` format into runtime structures.
//!
//! Parses the WASM binary format (version 1) including:
//! - Type section (function signatures)
//! - Function section (type indices)
//! - Memory section (linear memory limits)
//! - Global section (mutable/immutable globals)
//! - Export section (named function exports)
//! - Code section (function bodies)

use crate::decode::{self, section, valtype};
use crate::types::ValType;

/// Maximum number of functions in a module.
const MAX_FUNCTIONS: usize = 128;
/// Maximum number of types (signatures).
const MAX_TYPES: usize = 64;
/// Maximum code size per function (bytes).
const MAX_CODE_SIZE: usize = 8192;
/// Maximum number of exports.
const MAX_EXPORTS: usize = 32;
/// Maximum number of globals.
const MAX_GLOBALS: usize = 32;
/// Maximum parameters per function.
const MAX_PARAMS: usize = 8;
/// Maximum locals per function.
const MAX_LOCALS: usize = 32;
/// Maximum number of imports.
const MAX_IMPORTS: usize = 16;

/// Error during module parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    InvalidMagic,
    InvalidVersion,
    InvalidSection,
    TooManyFunctions,
    TooManyTypes,
    TooManyExports,
    TooManyGlobals,
    TooManyParams,
    TooManyLocals,
    TooManyImports,
    CodeTooLarge,
    UnexpectedEof,
    InvalidEncoding,
}

/// An imported item (function or memory).
#[derive(Clone, Copy)]
pub struct Import {
    /// Module name (e.g. "env").
    pub module_name: [u8; 32],
    pub module_name_len: usize,
    /// Field name (e.g. "memory" or "print").
    pub field_name: [u8; 32],
    pub field_name_len: usize,
    /// Import kind: 0=function, 2=memory.
    pub kind: u8,
    /// For function imports: index into types array.
    pub type_idx: u32,
    /// For memory imports: minimum pages.
    pub mem_min: u32,
    /// For memory imports: maximum pages (0 = no max).
    pub mem_max: u32,
}

impl Import {
    const fn empty() -> Self {
        Self {
            module_name: [0; 32],
            module_name_len: 0,
            field_name: [0; 32],
            field_name_len: 0,
            kind: 0,
            type_idx: 0,
            mem_min: 0,
            mem_max: 0,
        }
    }
}

/// Function type (signature): params → results.
#[derive(Clone, Copy)]
pub struct FuncType {
    pub params: [ValType; MAX_PARAMS],
    pub param_count: usize,
    pub result: Option<ValType>,
}

impl FuncType {
    const fn empty() -> Self {
        Self {
            params: [ValType::I32; MAX_PARAMS],
            param_count: 0,
            result: None,
        }
    }
}

/// A function body (code).
#[derive(Clone, Copy)]
pub struct FuncBody {
    /// Index into the types array for this function's signature.
    pub type_idx: u32,
    /// Local variable declarations (type of each local group).
    pub locals: [ValType; MAX_LOCALS],
    pub local_count: usize,
    /// Bytecode offset and length within the module's code buffer.
    pub code_offset: usize,
    pub code_len: usize,
}

impl FuncBody {
    const fn empty() -> Self {
        Self {
            type_idx: 0,
            locals: [ValType::I32; MAX_LOCALS],
            local_count: 0,
            code_offset: 0,
            code_len: 0,
        }
    }
}

/// An exported function.
#[derive(Clone, Copy)]
pub struct Export {
    /// Name of the export (null-terminated, max 31 chars).
    pub name: [u8; 32],
    pub name_len: usize,
    /// Function index.
    pub func_idx: u32,
}

impl Export {
    const fn empty() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            func_idx: 0,
        }
    }
}

/// A global variable.
#[derive(Clone, Copy)]
pub struct Global {
    pub val_type: ValType,
    pub mutable: bool,
    pub init_i32: i32,
    pub init_i64: i64,
}

impl Global {
    const fn empty() -> Self {
        Self {
            val_type: ValType::I32,
            mutable: false,
            init_i32: 0,
            init_i64: 0,
        }
    }
}

/// A parsed WASM module.
pub struct Module {
    /// Function type signatures.
    pub types: [FuncType; MAX_TYPES],
    pub type_count: usize,
    /// Function bodies.
    pub functions: [FuncBody; MAX_FUNCTIONS],
    pub func_count: usize,
    /// Exports.
    pub exports: [Export; MAX_EXPORTS],
    pub export_count: usize,
    /// Global variables.
    pub globals: [Global; MAX_GLOBALS],
    pub global_count: usize,
    /// Imports.
    pub imports: [Import; MAX_IMPORTS],
    pub import_count: usize,
    /// Number of imported functions (these occupy function indices before local functions).
    pub import_func_count: usize,
    /// Linear memory initial size (in WASM pages = 64 KiB).
    pub memory_pages: u32,
    /// Linear memory max size (in pages, 0 = no max).
    pub memory_max: u32,
    /// Start function index (auto-called on instantiation), or u32::MAX if none.
    pub start_func: u32,
    /// Flat code buffer (all function bytecodes concatenated).
    pub code: [u8; MAX_FUNCTIONS * MAX_CODE_SIZE / 4],
    pub code_len: usize,
}

impl Module {
    /// Parse a WASM binary module from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::UnexpectedEof);
        }
        // Magic number: \0asm
        if data[0..4] != [0x00, 0x61, 0x73, 0x6D] {
            return Err(ParseError::InvalidMagic);
        }
        // Version: 1
        if data[4..8] != [0x01, 0x00, 0x00, 0x00] {
            return Err(ParseError::InvalidVersion);
        }

        let mut module = Module {
            types: [FuncType::empty(); MAX_TYPES],
            type_count: 0,
            functions: [FuncBody::empty(); MAX_FUNCTIONS],
            func_count: 0,
            exports: [Export::empty(); MAX_EXPORTS],
            export_count: 0,
            globals: [Global::empty(); MAX_GLOBALS],
            global_count: 0,
            imports: [Import::empty(); MAX_IMPORTS],
            import_count: 0,
            import_func_count: 0,
            memory_pages: 0,
            memory_max: 0,
            start_func: u32::MAX,
            code: [0; MAX_FUNCTIONS * MAX_CODE_SIZE / 4],
            code_len: 0,
        };

        let mut func_type_indices: [u32; MAX_FUNCTIONS] = [0; MAX_FUNCTIONS];
        let mut func_type_count = 0usize;

        let mut pos = 8;
        while pos < data.len() {
            if pos + 1 > data.len() {
                break;
            }
            let section_id = data[pos];
            pos += 1;

            let (section_len, n) = decode::read_u32_leb128(&data[pos..])
                .ok_or(ParseError::InvalidEncoding)?;
            pos += n;
            let section_end = pos + section_len as usize;
            if section_end > data.len() {
                return Err(ParseError::UnexpectedEof);
            }

            match section_id {
                section::TYPE => {
                    pos = parse_type_section(data, pos, section_end, &mut module)?;
                }
                section::IMPORT => {
                    pos = parse_import_section(data, pos, section_end, &mut module)?;
                }
                section::FUNCTION => {
                    let (count, new_pos) = parse_function_section(
                        data,
                        pos,
                        section_end,
                        &mut func_type_indices,
                        &mut func_type_count,
                    )?;
                    let _ = count;
                    pos = new_pos;
                }
                section::MEMORY => {
                    pos = parse_memory_section(data, pos, section_end, &mut module)?;
                }
                section::GLOBAL => {
                    pos = parse_global_section(data, pos, section_end, &mut module)?;
                }
                section::EXPORT => {
                    pos = parse_export_section(data, pos, section_end, &mut module)?;
                }
                section::START => {
                    pos = parse_start_section(data, pos, section_end, &mut module)?;
                }
                section::CODE => {
                    pos = parse_code_section(
                        data,
                        pos,
                        section_end,
                        &mut module,
                        &func_type_indices,
                        func_type_count,
                    )?;
                }
                _ => {
                    // Skip unknown sections.
                    pos = section_end;
                }
            }
        }

        Ok(module)
    }

    /// Find an exported function by name. Returns function index.
    pub fn find_export(&self, name: &[u8]) -> Option<u32> {
        for i in 0..self.export_count {
            let exp = &self.exports[i];
            if exp.name_len == name.len() && &exp.name[..exp.name_len] == name {
                return Some(exp.func_idx);
            }
        }
        None
    }

    /// Parse a WASM module from raw bytes loaded from initrd.
    ///
    /// This is a convenience wrapper around `parse()` for loading modules
    /// that were read from an initrd/CPIO archive. The bytes must contain
    /// a valid WASM binary module (magic + version header + sections).
    pub fn from_initrd_bytes(data: &[u8]) -> Result<Self, ParseError> {
        Self::parse(data)
    }

    /// Returns true if this module has a start function.
    pub fn has_start(&self) -> bool {
        self.start_func != u32::MAX
    }

    /// Returns the start function index, if any.
    pub fn start_function(&self) -> Option<u32> {
        if self.start_func != u32::MAX {
            Some(self.start_func)
        } else {
            None
        }
    }

    /// Find an import by module and field name.
    pub fn find_import(&self, module_name: &[u8], field_name: &[u8]) -> Option<&Import> {
        for i in 0..self.import_count {
            let imp = &self.imports[i];
            if imp.module_name_len == module_name.len()
                && &imp.module_name[..imp.module_name_len] == module_name
                && imp.field_name_len == field_name.len()
                && &imp.field_name[..imp.field_name_len] == field_name
            {
                return Some(imp);
            }
        }
        None
    }
}

fn parse_type_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    module: &mut Module,
) -> Result<usize, ParseError> {
    let (count, n) = decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;

    for _ in 0..count {
        if module.type_count >= MAX_TYPES {
            return Err(ParseError::TooManyTypes);
        }
        if pos >= end || data[pos] != valtype::FUNC {
            return Err(ParseError::InvalidEncoding);
        }
        pos += 1;

        // Parse parameters.
        let (param_count, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;
        let mut ft = FuncType::empty();
        if param_count as usize > MAX_PARAMS {
            return Err(ParseError::TooManyParams);
        }
        for j in 0..param_count as usize {
            ft.params[j] = decode_valtype(data[pos])?;
            pos += 1;
        }
        ft.param_count = param_count as usize;

        // Parse results.
        let (result_count, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;
        if result_count > 0 {
            ft.result = Some(decode_valtype(data[pos])?);
            pos += result_count as usize;
        }

        module.types[module.type_count] = ft;
        module.type_count += 1;
    }
    Ok(pos.min(end))
}

fn parse_function_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    type_indices: &mut [u32; MAX_FUNCTIONS],
    count_out: &mut usize,
) -> Result<(usize, usize), ParseError> {
    let (count, n) = decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;

    if count as usize > MAX_FUNCTIONS {
        return Err(ParseError::TooManyFunctions);
    }

    for i in 0..count as usize {
        let (type_idx, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;
        type_indices[i] = type_idx;
    }
    *count_out = count as usize;
    Ok((count as usize, pos.min(end)))
}

fn parse_memory_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    module: &mut Module,
) -> Result<usize, ParseError> {
    let (count, n) = decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;

    if count > 0 {
        let flags = data[pos];
        pos += 1;
        let (min, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;
        module.memory_pages = min;
        if flags & 1 != 0 {
            let (max, n) =
                decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
            pos += n;
            module.memory_max = max;
        }
    }
    Ok(pos.min(end))
}

fn parse_global_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    module: &mut Module,
) -> Result<usize, ParseError> {
    let (count, n) = decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;

    for _ in 0..count {
        if module.global_count >= MAX_GLOBALS {
            return Err(ParseError::TooManyGlobals);
        }
        let vt = decode_valtype(data[pos])?;
        pos += 1;
        let mutable = data[pos] != 0;
        pos += 1;

        let mut g = Global::empty();
        g.val_type = vt;
        g.mutable = mutable;

        // Parse init expression (simplified: i32.const or i64.const + end).
        match data[pos] {
            0x41 => {
                pos += 1;
                let (val, n) = decode::read_i32_leb128(&data[pos..])
                    .ok_or(ParseError::InvalidEncoding)?;
                pos += n;
                g.init_i32 = val;
            }
            0x42 => {
                pos += 1;
                let (val, n) = decode::read_i64_leb128(&data[pos..])
                    .ok_or(ParseError::InvalidEncoding)?;
                pos += n;
                g.init_i64 = val;
            }
            _ => {
                // Skip unknown init expr.
                while pos < end && data[pos] != 0x0B {
                    pos += 1;
                }
            }
        }
        // Skip end opcode.
        if pos < end && data[pos] == 0x0B {
            pos += 1;
        }

        module.globals[module.global_count] = g;
        module.global_count += 1;
    }
    Ok(pos.min(end))
}

fn parse_export_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    module: &mut Module,
) -> Result<usize, ParseError> {
    let (count, n) = decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;

    for _ in 0..count {
        if module.export_count >= MAX_EXPORTS {
            return Err(ParseError::TooManyExports);
        }
        let (name_len, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;

        let mut exp = Export::empty();
        let copy_len = (name_len as usize).min(31);
        exp.name[..copy_len].copy_from_slice(&data[pos..pos + copy_len]);
        exp.name_len = copy_len;
        pos += name_len as usize;

        let kind = data[pos];
        pos += 1;
        let (idx, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;

        // Only export functions (kind 0).
        if kind == 0 {
            exp.func_idx = idx;
            module.exports[module.export_count] = exp;
            module.export_count += 1;
        }
    }
    Ok(pos.min(end))
}

fn parse_code_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    module: &mut Module,
    type_indices: &[u32; MAX_FUNCTIONS],
    func_count: usize,
) -> Result<usize, ParseError> {
    let (count, n) = decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;

    if count as usize != func_count {
        return Err(ParseError::InvalidSection);
    }

    for i in 0..count as usize {
        if module.func_count >= MAX_FUNCTIONS {
            return Err(ParseError::TooManyFunctions);
        }

        let (body_size, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;
        let body_end = pos + body_size as usize;
        if body_end > end {
            return Err(ParseError::UnexpectedEof);
        }

        let mut fb = FuncBody::empty();
        fb.type_idx = type_indices[i];

        // Parse locals.
        let (local_decl_count, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;

        for _ in 0..local_decl_count {
            let (lcount, n) =
                decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
            pos += n;
            let vt = decode_valtype(data[pos])?;
            pos += 1;
            for _ in 0..lcount {
                if fb.local_count >= MAX_LOCALS {
                    return Err(ParseError::TooManyLocals);
                }
                fb.locals[fb.local_count] = vt;
                fb.local_count += 1;
            }
        }

        // Copy bytecode into module code buffer.
        let code_bytes = body_end - pos;
        if code_bytes > MAX_CODE_SIZE {
            return Err(ParseError::CodeTooLarge);
        }
        if module.code_len + code_bytes > module.code.len() {
            return Err(ParseError::CodeTooLarge);
        }
        fb.code_offset = module.code_len;
        fb.code_len = code_bytes;
        module.code[module.code_len..module.code_len + code_bytes]
            .copy_from_slice(&data[pos..body_end]);
        module.code_len += code_bytes;

        module.functions[module.func_count] = fb;
        module.func_count += 1;
        pos = body_end;
    }

    Ok(pos.min(end))
}

/// Parse the import section (section ID 2).
fn parse_import_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    module: &mut Module,
) -> Result<usize, ParseError> {
    let (count, n) = decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;

    for _ in 0..count {
        if module.import_count >= MAX_IMPORTS {
            return Err(ParseError::TooManyImports);
        }

        let mut imp = Import::empty();

        // Read module name.
        let (mod_name_len, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;
        let copy_len = (mod_name_len as usize).min(31);
        if pos + mod_name_len as usize > end {
            return Err(ParseError::UnexpectedEof);
        }
        imp.module_name[..copy_len].copy_from_slice(&data[pos..pos + copy_len]);
        imp.module_name_len = copy_len;
        pos += mod_name_len as usize;

        // Read field name.
        let (field_name_len, n) =
            decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
        pos += n;
        let copy_len = (field_name_len as usize).min(31);
        if pos + field_name_len as usize > end {
            return Err(ParseError::UnexpectedEof);
        }
        imp.field_name[..copy_len].copy_from_slice(&data[pos..pos + copy_len]);
        imp.field_name_len = copy_len;
        pos += field_name_len as usize;

        // Read import kind.
        if pos >= end {
            return Err(ParseError::UnexpectedEof);
        }
        imp.kind = data[pos];
        pos += 1;

        match imp.kind {
            0x00 => {
                // Function import: read type index.
                let (type_idx, n) =
                    decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
                pos += n;
                imp.type_idx = type_idx;
                module.import_func_count += 1;
            }
            0x02 => {
                // Memory import: read limits.
                let flags = data[pos];
                pos += 1;
                let (min, n) =
                    decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
                pos += n;
                imp.mem_min = min;
                if module.memory_pages == 0 {
                    module.memory_pages = min;
                }
                if flags & 1 != 0 {
                    let (max, n) = decode::read_u32_leb128(&data[pos..])
                        .ok_or(ParseError::InvalidEncoding)?;
                    pos += n;
                    imp.mem_max = max;
                    if module.memory_max == 0 {
                        module.memory_max = max;
                    }
                }
            }
            _ => {
                // Skip unknown import kinds (table=0x01, global=0x03).
                // We must skip the descriptor; for simplicity, scan to next entry
                // by skipping based on kind. Tables have element type + limits,
                // globals have valtype + mutability.
                match imp.kind {
                    0x01 => {
                        // Table: elemtype + limits
                        pos += 1; // element type
                        let flags = data[pos];
                        pos += 1;
                        let (_min, n) = decode::read_u32_leb128(&data[pos..])
                            .ok_or(ParseError::InvalidEncoding)?;
                        pos += n;
                        if flags & 1 != 0 {
                            let (_max, n) = decode::read_u32_leb128(&data[pos..])
                                .ok_or(ParseError::InvalidEncoding)?;
                            pos += n;
                        }
                    }
                    0x03 => {
                        // Global: valtype + mutability
                        pos += 2;
                    }
                    _ => {}
                }
            }
        }

        module.imports[module.import_count] = imp;
        module.import_count += 1;
    }
    Ok(pos.min(end))
}

/// Parse the start section (section ID 8).
fn parse_start_section(
    data: &[u8],
    mut pos: usize,
    end: usize,
    module: &mut Module,
) -> Result<usize, ParseError> {
    let (func_idx, n) =
        decode::read_u32_leb128(&data[pos..]).ok_or(ParseError::InvalidEncoding)?;
    pos += n;
    module.start_func = func_idx;
    Ok(pos.min(end))
}

fn decode_valtype(byte: u8) -> Result<ValType, ParseError> {
    match byte {
        valtype::I32 => Ok(ValType::I32),
        valtype::I64 => Ok(ValType::I64),
        _ => Err(ParseError::InvalidEncoding),
    }
}
