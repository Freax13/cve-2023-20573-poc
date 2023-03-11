//! This crate contains constants shared between the kernel, loader and host executable.
#![no_std]

pub const EXIT_PORT: u16 = 0xf4;
pub const LOG_PORT: u16 = 0x3f8;
