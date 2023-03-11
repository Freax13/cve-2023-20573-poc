#![no_std]
#![no_main]
#![feature(
    abi_x86_interrupt,
    asm_const,
    core_intrinsics,
    inline_const,
    layout_for_ptr,
    naked_functions,
    once_cell
)]

use core::ops::Deref;

use log::{debug, LevelFilter};

use crate::serial_logger::SerialLogger;

mod cpuid;
mod exception;
mod ghcb;
mod pagetable;
mod panic;
mod reset_vector;
mod serial_logger;

fn main() {
    exception::init();

    log::set_logger(&SerialLogger).unwrap();
    log::set_max_level(LevelFilter::Trace);
    debug!("initialized logger");

    exception::run_debuggee();
}

/// The kernel runs singlethreaded, so we don't need statics to be`Sync`.
/// This type can wrap another type and make it `Sync`.
pub struct FakeSync<T>(T);

impl<T> FakeSync<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for FakeSync<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

unsafe impl<T> Sync for FakeSync<T> {}
