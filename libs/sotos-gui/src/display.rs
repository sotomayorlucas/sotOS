//! Framebuffer display adapter implementing embedded-graphics DrawTarget.
//!
//! Wraps a raw BGRA framebuffer pointer as an embedded-graphics display target.
//! Pixel format: 0xAARRGGBB (little-endian BGRA in memory).

use embedded_graphics::prelude::*;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::primitives::Rectangle;

/// A display backed by a raw BGRA framebuffer in memory.
pub struct FramebufferDisplay {
    fb: *mut u32,
    width: u32,
    height: u32,
    stride: u32, // pixels per row (pitch / 4)
}

impl FramebufferDisplay {
    /// Create a new framebuffer display.
    ///
    /// # Safety
    /// `fb` must point to a valid framebuffer of at least `stride * height` u32 pixels.
    /// `stride` is in pixels (= pitch_bytes / 4 for 32bpp).
    pub unsafe fn new(fb: *mut u32, width: u32, height: u32, stride: u32) -> Self {
        Self { fb, width, height, stride }
    }

    pub fn width(&self) -> u32 { self.width }
    pub fn height(&self) -> u32 { self.height }
    pub fn stride(&self) -> u32 { self.stride }
    pub fn fb_ptr(&self) -> *mut u32 { self.fb }

    /// Convert Rgb888 to our BGRA u32 format (0xFFRRGGBB).
    #[inline(always)]
    fn to_pixel(color: Rgb888) -> u32 {
        0xFF000000 | (color.r() as u32) << 16 | (color.g() as u32) << 8 | color.b() as u32
    }

    /// Fill the entire display with a vertical gradient (top color to bottom color).
    pub fn gradient_v(&mut self, r1: u8, g1: u8, b1: u8, r2: u8, g2: u8, b2: u8) {
        if self.height == 0 { return; }
        let h = self.height as i32;
        for y in 0..self.height {
            let yi = y as i32;
            let r = (r1 as i32 + (r2 as i32 - r1 as i32) * yi / h) as u8;
            let g = (g1 as i32 + (g2 as i32 - g1 as i32) * yi / h) as u8;
            let b = (b1 as i32 + (b2 as i32 - b1 as i32) * yi / h) as u8;
            let pixel = 0xFF000000 | (r as u32) << 16 | (g as u32) << 8 | b as u32;
            let row = (y * self.stride) as usize;
            for x in 0..self.width {
                unsafe { *self.fb.add(row + x as usize) = pixel; }
            }
        }
    }
}

impl DrawTarget for FramebufferDisplay {
    type Color = Rgb888;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb888>>,
    {
        for Pixel(point, color) in pixels {
            let x = point.x;
            let y = point.y;
            if x >= 0 && y >= 0 && (x as u32) < self.width && (y as u32) < self.height {
                unsafe {
                    *self.fb.add((y as u32 * self.stride + x as u32) as usize) =
                        Self::to_pixel(color);
                }
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb888) -> Result<(), Self::Error> {
        let pixel = Self::to_pixel(color);
        let x0 = area.top_left.x.max(0) as u32;
        let y0 = area.top_left.y.max(0) as u32;
        let x1 = (area.top_left.x + area.size.width as i32)
            .max(0)
            .min(self.width as i32) as u32;
        let y1 = (area.top_left.y + area.size.height as i32)
            .max(0)
            .min(self.height as i32) as u32;
        for y in y0..y1 {
            let row = (y * self.stride) as usize;
            for x in x0..x1 {
                unsafe { *self.fb.add(row + x as usize) = pixel; }
            }
        }
        Ok(())
    }
}

impl OriginDimensions for FramebufferDisplay {
    fn size(&self) -> Size {
        Size::new(self.width, self.height)
    }
}
