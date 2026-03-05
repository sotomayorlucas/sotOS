//! Typed IPC payload descriptors for heterogeneous compute.
//!
//! Extends the existing IPC `Message` with typed payload metadata that
//! describes the contents being transferred. This allows kernel-mediated
//! dispatch to the correct compute unit (CPU, GPU, NPU) without userspace
//! having to implement its own type-tagging protocol.
//!
//! Payload types supported:
//! - **Raw**: Untyped bytes (backward-compatible with existing IPC).
//! - **Tensor**: Multi-dimensional array data for NPU/ML inference.
//! - **Shader**: GPU shader programs (vertex, fragment, compute).
//! - **Image**: Framebuffer/image data with format metadata.

use super::endpoint::Message;

// ---------------------------------------------------------------------------
// Data types for tensor payloads
// ---------------------------------------------------------------------------

/// Numeric data types for tensor elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataType {
    /// 32-bit floating point.
    F32 = 0,
    /// 16-bit floating point (half precision).
    F16 = 1,
    /// 32-bit signed integer.
    I32 = 2,
    /// 8-bit signed integer (quantized models).
    I8 = 3,
    /// 8-bit unsigned integer.
    U8 = 4,
}

impl DataType {
    /// Size of one element in bytes.
    pub const fn element_size(self) -> usize {
        match self {
            DataType::F32 => 4,
            DataType::F16 => 2,
            DataType::I32 => 4,
            DataType::I8 => 1,
            DataType::U8 => 1,
        }
    }

    /// Decode from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(DataType::F32),
            1 => Some(DataType::F16),
            2 => Some(DataType::I32),
            3 => Some(DataType::I8),
            4 => Some(DataType::U8),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Shader types
// ---------------------------------------------------------------------------

/// GPU shader program types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ShaderType {
    /// Vertex shader (per-vertex transformation).
    Vertex = 0,
    /// Fragment/pixel shader (per-pixel color).
    Fragment = 1,
    /// Compute shader (general-purpose GPU compute).
    Compute = 2,
}

impl ShaderType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ShaderType::Vertex),
            1 => Some(ShaderType::Fragment),
            2 => Some(ShaderType::Compute),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Image formats
// ---------------------------------------------------------------------------

/// Pixel formats for image data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ImageFormat {
    /// 32-bit RGBA (8 bits per channel).
    Rgba8 = 0,
    /// 16-bit RGB (5-6-5 bit layout).
    Rgb565 = 1,
    /// 32-bit BGRA (8 bits per channel).
    Bgra8 = 2,
    /// 8-bit grayscale.
    Grayscale8 = 3,
}

impl ImageFormat {
    /// Bytes per pixel for this format.
    pub const fn bytes_per_pixel(self) -> usize {
        match self {
            ImageFormat::Rgba8 => 4,
            ImageFormat::Bgra8 => 4,
            ImageFormat::Rgb565 => 2,
            ImageFormat::Grayscale8 => 1,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ImageFormat::Rgba8),
            1 => Some(ImageFormat::Rgb565),
            2 => Some(ImageFormat::Bgra8),
            3 => Some(ImageFormat::Grayscale8),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Payload descriptors
// ---------------------------------------------------------------------------

/// Tensor data descriptor.
///
/// Describes a multi-dimensional tensor stored in physical memory.
/// Supports up to 4 dimensions (batch, channels, height, width).
#[derive(Clone, Copy, Debug)]
pub struct TensorDesc {
    /// Element data type.
    pub dtype: DataType,
    /// Dimension sizes: [N, C, H, W] (NCHW layout).
    pub dims: [u32; 4],
    /// Number of active dimensions (1-4).
    pub ndim: u8,
    /// Physical address of the tensor data.
    pub data_phys: u64,
    /// Total size in bytes.
    pub data_size: u32,
}

impl TensorDesc {
    pub const fn empty() -> Self {
        Self {
            dtype: DataType::F32,
            dims: [0; 4],
            ndim: 0,
            data_phys: 0,
            data_size: 0,
        }
    }

    /// Calculate the total number of elements.
    pub fn element_count(&self) -> u64 {
        let mut count = 1u64;
        for i in 0..self.ndim as usize {
            count *= self.dims[i] as u64;
        }
        count
    }

    /// Validate that data_size matches dims * dtype.
    pub fn is_valid(&self) -> bool {
        let expected = self.element_count() * self.dtype.element_size() as u64;
        self.data_size as u64 == expected && self.ndim > 0 && self.ndim <= 4
    }
}

/// Shader program descriptor.
///
/// Describes a GPU shader program stored in physical memory.
#[derive(Clone, Copy, Debug)]
pub struct ShaderDesc {
    /// Type of shader (vertex, fragment, compute).
    pub shader_type: ShaderType,
    /// Physical address of the shader bytecode.
    pub code_phys: u64,
    /// Size of the shader bytecode in bytes.
    pub code_size: u32,
    /// Compute shader workgroup dimensions [X, Y, Z].
    pub workgroup_size: [u32; 3],
}

impl ShaderDesc {
    pub const fn empty() -> Self {
        Self {
            shader_type: ShaderType::Compute,
            code_phys: 0,
            code_size: 0,
            workgroup_size: [1, 1, 1],
        }
    }

    /// Validate the descriptor.
    pub fn is_valid(&self) -> bool {
        self.code_size > 0
            && self.code_phys != 0
            && self.workgroup_size[0] > 0
            && self.workgroup_size[1] > 0
            && self.workgroup_size[2] > 0
    }
}

/// Image data descriptor.
///
/// Describes a 2D image or framebuffer region in physical memory.
#[derive(Clone, Copy, Debug)]
pub struct ImageDesc {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Pixel format.
    pub format: ImageFormat,
    /// Physical address of the pixel data.
    pub data_phys: u64,
    /// Row stride in bytes (may include padding).
    pub stride: u32,
}

impl ImageDesc {
    pub const fn empty() -> Self {
        Self {
            width: 0,
            height: 0,
            format: ImageFormat::Rgba8,
            data_phys: 0,
            stride: 0,
        }
    }

    /// Calculate the total data size in bytes.
    pub fn data_size(&self) -> u64 {
        self.stride as u64 * self.height as u64
    }

    /// Validate the descriptor.
    pub fn is_valid(&self) -> bool {
        self.width > 0
            && self.height > 0
            && self.stride >= self.width * self.format.bytes_per_pixel() as u32
            && self.data_phys != 0
    }
}

// ---------------------------------------------------------------------------
// Typed payload enum
// ---------------------------------------------------------------------------

/// Typed IPC payload descriptor.
///
/// Wraps the payload metadata for type-safe IPC between services
/// and heterogeneous compute units.
#[derive(Clone, Copy, Debug)]
pub enum PayloadType {
    /// Raw bytes (existing/default). Backward-compatible.
    Raw,
    /// Tensor data for NPU dispatch.
    Tensor(TensorDesc),
    /// Shader program for GPU dispatch.
    Shader(ShaderDesc),
    /// Image/framebuffer data.
    Image(ImageDesc),
}

impl PayloadType {
    /// Discriminant byte for serialization.
    pub fn discriminant(&self) -> u8 {
        match self {
            PayloadType::Raw => 0,
            PayloadType::Tensor(_) => 1,
            PayloadType::Shader(_) => 2,
            PayloadType::Image(_) => 3,
        }
    }

    /// Check if the payload has a physical address that needs validation.
    pub fn data_phys(&self) -> Option<u64> {
        match self {
            PayloadType::Raw => None,
            PayloadType::Tensor(t) => Some(t.data_phys),
            PayloadType::Shader(s) => Some(s.code_phys),
            PayloadType::Image(i) => Some(i.data_phys),
        }
    }

    /// Total data size in bytes.
    pub fn data_size(&self) -> u64 {
        match self {
            PayloadType::Raw => 0,
            PayloadType::Tensor(t) => t.data_size as u64,
            PayloadType::Shader(s) => s.code_size as u64,
            PayloadType::Image(i) => i.data_size(),
        }
    }
}

// ---------------------------------------------------------------------------
// Extended message type
// ---------------------------------------------------------------------------

/// Extended message with typed payload descriptor.
///
/// Embeds the existing `Message` (tag + register file + cap transfer)
/// alongside a `PayloadType` that describes what the message carries.
/// The kernel can inspect the payload type to route messages to the
/// correct compute unit or validate data addresses.
#[derive(Clone, Copy, Debug)]
pub struct TypedMessage {
    /// The base IPC message (tag, registers, cap transfer).
    pub base: Message,
    /// Typed payload descriptor.
    pub payload: PayloadType,
}

impl TypedMessage {
    /// Create a typed message wrapping a raw (untyped) base message.
    pub const fn raw(base: Message) -> Self {
        Self {
            base,
            payload: PayloadType::Raw,
        }
    }

    /// Create a typed message with a tensor payload.
    pub fn tensor(base: Message, desc: TensorDesc) -> Self {
        Self {
            base,
            payload: PayloadType::Tensor(desc),
        }
    }

    /// Create a typed message with a shader payload.
    pub fn shader(base: Message, desc: ShaderDesc) -> Self {
        Self {
            base,
            payload: PayloadType::Shader(desc),
        }
    }

    /// Create a typed message with an image payload.
    pub fn image(base: Message, desc: ImageDesc) -> Self {
        Self {
            base,
            payload: PayloadType::Image(desc),
        }
    }

    /// Validate the typed payload (check address, size constraints).
    pub fn is_valid(&self) -> bool {
        match &self.payload {
            PayloadType::Raw => true,
            PayloadType::Tensor(t) => t.is_valid(),
            PayloadType::Shader(s) => s.is_valid(),
            PayloadType::Image(i) => i.is_valid(),
        }
    }
}
