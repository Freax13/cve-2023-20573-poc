use core::{
    arch::asm,
    cell::LazyCell,
    sync::atomic::{AtomicBool, Ordering},
};

use log::info;
use x86_64::{
    registers::rflags::{self, RFlags},
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame},
};

use crate::{exception::vc::vmm_communication_exception_handler, FakeSync};

mod vc;

pub fn init() {
    static IDT: FakeSync<LazyCell<InterruptDescriptorTable>> = FakeSync::new(LazyCell::new(|| {
        let mut idt = InterruptDescriptorTable::new();

        idt.vmm_communication_exception
            .set_handler_fn(vmm_communication_exception_handler);
        idt.debug.set_handler_fn(debug_handler);

        idt
    }));

    IDT.load();
}

pub fn run_debuggee() -> ! {
    // Enable the trap flag.
    let mut flags = rflags::read();
    flags |= RFlags::TRAP_FLAG;
    unsafe {
        rflags::write(flags);
    }

    debuggee();
}

static FLIPFLOP: AtomicBool = AtomicBool::new(false);

extern "x86-interrupt" fn debug_handler(frame: InterruptStackFrame) {
    #[allow(clippy::fn_to_numeric_cast)]
    let nop_addr = debuggee as u64;
    let jmp_addr = nop_addr + 1;

    if frame.instruction_pointer.as_u64() == nop_addr {
        info!("nop");
        let prev = FLIPFLOP.swap(true, Ordering::SeqCst);
        if prev {
            info!("last instruction was also nop");
        }
    } else if frame.instruction_pointer.as_u64() == jmp_addr {
        info!("jmp");
        let prev = FLIPFLOP.swap(false, Ordering::SeqCst);
        if !prev {
            info!("last instruction was also jmp");
        }
    }
}

#[naked]
extern "C" fn debuggee() -> ! {
    unsafe {
        asm!("2:", "nop", "jmp 2b", options(noreturn));
    }
}
