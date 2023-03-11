use core::{
    arch::asm,
    cell::{LazyCell, RefCell, UnsafeCell},
    ptr::NonNull,
};

use bit_field::BitField;
use bytemuck::{offset_of, NoUninit};
use snp_types::{
    ghcb::{
        msr_protocol::{GhcbInfo, GhcbProtocolMsr, TerminateReasonCode},
        Ghcb, ProtocolVersion,
    },
    intercept::VMEXIT_IOIO,
};
use volatile::{map_field_mut, VolatilePtr};
use x86_64::structures::paging::PhysFrame;

use crate::{pa_of, FakeSync};

/// Initialize a GHCB and pass it to the closure.
pub fn with_ghcb<R>(f: impl FnOnce(&mut VolatilePtr<'static, Ghcb>) -> R) -> Result<R, GhcbInUse> {
    static GHCB: FakeSync<LazyCell<RefCell<VolatilePtr<'static, Ghcb>>>> =
        FakeSync::new(LazyCell::new(|| {
            #[link_section = ".shared"]
            static GHCB_STORAGE: FakeSync<UnsafeCell<Ghcb>> =
                FakeSync::new(UnsafeCell::new(Ghcb::ZERO));

            let address = pa_of!(GHCB_STORAGE);
            let address = PhysFrame::from_start_address(address).unwrap();

            register_ghcb(address);

            let mut msr = GhcbProtocolMsr::MSR;
            unsafe {
                msr.write(u64::from(GhcbInfo::GhcbGuestPhysicalAddress { address }));
            }

            RefCell::new(unsafe {
                VolatilePtr::new_read_write(NonNull::from(&GHCB_STORAGE).cast())
            })
        }));

    let res = GHCB.try_borrow_mut();
    let mut ghcb = res.map_err(|_| GhcbInUse(()))?;
    Ok(f(&mut ghcb))
}

#[derive(Debug)]
pub struct GhcbInUse(());

fn register_ghcb(request_address: PhysFrame) {
    let mut msr = GhcbProtocolMsr::MSR;

    // Write the request.
    let request = u64::from(GhcbInfo::RegisterGhcbGpaRequest {
        address: request_address,
    });
    unsafe { msr.write(request) }

    // Execute the request.
    vmgexit();

    // Read the response.
    let response = GhcbInfo::try_from(unsafe { msr.read() }).unwrap();

    // Verify the response.
    let GhcbInfo::RegisterGhcbGpaResponse { address: response_address } = response else { panic!("unexpected response: {response:?}") };
    assert_eq!(Some(request_address), response_address);
}

fn vmgexit() {
    // LLVM doesn't support the `vmgexit` instruction
    unsafe { asm!("rep vmmcall", options(nostack, preserves_flags)) }
}

/// A macro to write to a field of the GHCB and also mark it in the valid
/// bitmap.
macro_rules! ghcb_write {
    ($ghcb:ident.$field:ident = $value:expr) => {{
        map_field_mut!($ghcb.$field).write($value);
        let bit_offset = offset_of!(Ghcb::ZERO, Ghcb, $field);
        map_field_mut!($ghcb.valid_bitmap).update(|value| {
            value.set_bit(bit_offset / 8, true);
        });
    }};
}

pub fn ioio_write(port: u16, value: u32) {
    with_ghcb(|ghcb| {
        ghcb.write(Ghcb::ZERO);
        map_field_mut!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        let mut sw_exit_info1 = 0;
        sw_exit_info1.set_bit(0, false); // OUT instruction
        sw_exit_info1.set_bit(6, true); // 32-bit operand size
        sw_exit_info1.set_bits(16..=31, u64::from(port));

        ghcb_write!(ghcb.sw_exit_code = VMEXIT_IOIO);
        ghcb_write!(ghcb.sw_exit_info1 = sw_exit_info1);
        ghcb_write!(ghcb.sw_exit_info2 = 0);
        ghcb_write!(ghcb.rax = u64::from(value));

        vmgexit();
    })
    .unwrap();
}

pub fn exit() -> ! {
    let mut msr = GhcbProtocolMsr::MSR;

    loop {
        // Write the request.
        let request = u64::from(GhcbInfo::TerminationRequest {
            reason_code: TerminateReasonCode::GENERAL_TERMINATION_REQUEST,
        });
        unsafe {
            msr.write(request);
        }

        vmgexit();
    }
}
