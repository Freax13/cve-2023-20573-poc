use std::{
    fs::OpenOptions,
    mem::size_of,
    num::NonZeroUsize,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::OpenOptionsExt,
    },
    ptr::NonNull,
};

use anyhow::{ensure, Context, Result};
use bitflags::bitflags;
use bytemuck::{pod_read_unaligned, Pod, Zeroable};
use nix::{
    errno::Errno,
    ioctl_none, ioctl_readwrite, ioctl_write_int_bad, ioctl_write_ptr,
    libc::O_SYNC,
    request_code_none,
    sys::mman::{MapFlags, ProtFlags},
};
use snp_types::{guest_policy::GuestPolicy, PageType, VmplPermissions};
use tracing::debug;
use volatile::VolatilePtr;

use crate::{kvm::hidden::KvmCpuid2, slot::Slot};

const KVMIO: u8 = 0xAE;

pub struct KvmHandle {
    fd: OwnedFd,
}

impl KvmHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/kvm")
            .context("failed to open /dev/kvm")?;
        let fd = OwnedFd::from(file);

        ioctl_write_int_bad!(kvm_get_api_version, request_code_none!(KVMIO, 0x00));
        let res = unsafe { kvm_get_api_version(fd.as_raw_fd(), 0) };
        let version = res.context("failed to execute get_api_version")?;
        debug!(version, "determined kvm version");
        ensure!(version >= 12, "unsupported kvm api version ({version})");

        ioctl_write_int_bad!(kvm_get_vcpu_mmap_size, request_code_none!(KVMIO, 0x04));
        let res = unsafe { kvm_get_vcpu_mmap_size(fd.as_raw_fd(), 0) };
        let vcpu_mmap_size = res.context("failed to query vcpu mmap size")?;
        ensure!(
            usize::try_from(vcpu_mmap_size).unwrap() >= size_of::<KvmRun>(),
            "unexpected vcpu mmap size: got {vcpu_mmap_size}, expected {}",
            size_of::<KvmRun>()
        );

        Ok(Self { fd })
    }

    pub fn create_vm(&self, protected: bool) -> Result<VmHandle> {
        debug!("creating vm");

        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), i32::from(protected)) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }

    pub fn get_supported_cpuid(&self) -> Result<Box<[KvmCpuidEntry2]>> {
        const MAX_ENTRIES: usize = 256;
        let mut buffer = KvmCpuid2::<MAX_ENTRIES> {
            nent: MAX_ENTRIES as u32,
            _padding: 0,
            entries: [KvmCpuidEntry2 {
                function: 0,
                index: 0,
                flags: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: [0; 3],
            }; MAX_ENTRIES],
        };

        ioctl_readwrite!(kvm_get_supported_cpuid, KVMIO, 0x05, KvmCpuid2<0>);
        let res = unsafe {
            kvm_get_supported_cpuid(
                self.fd.as_raw_fd(),
                &mut buffer as *mut KvmCpuid2<MAX_ENTRIES> as *mut KvmCpuid2<0>,
            )
        };
        res.context("failed to query supported cpuid features")?;

        Ok(Box::from(buffer.entries[..buffer.nent as usize].to_vec()))
    }
}

pub struct VmHandle {
    fd: OwnedFd,
}

impl VmHandle {
    pub fn create_vcpu(&self, id: i32) -> Result<VcpuHandle> {
        debug!(id, "creating vcpu");

        ioctl_write_int_bad!(kvm_create_vcpu, request_code_none!(KVMIO, 0x41));
        let res = unsafe { kvm_create_vcpu(self.fd.as_raw_fd(), id) };
        let raw_fd = res.context("failed to create cpu")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VcpuHandle { fd })
    }

    pub unsafe fn map_private_memory(
        &self,
        slot: u16,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        restricted_fd: Option<BorrowedFd>,
        restricted_offset: u64,
    ) -> Result<()> {
        debug!("mapping private memory");

        let region = KvmUserspaceMemoryRegion2 {
            region: KvmUserspaceMemoryRegion {
                slot: u32::from(slot),
                flags: KvmUserspaceMemoryRegionFlags::KVM_MEM_PRIVATE,
                guest_phys_addr,
                memory_size,
                userspace_addr,
            },
            restricted_offset,
            restricted_fd,
            _pad1: 0,
            _pad2: [0; 14],
        };

        ioctl_write_ptr!(
            kvm_set_user_memory_region2,
            KVMIO,
            0x49,
            KvmUserspaceMemoryRegion2
        );
        let res = unsafe { kvm_set_user_memory_region2(self.fd.as_raw_fd(), &region) };
        res.context("failed to map private memory")?;

        Ok(())
    }

    pub unsafe fn map_encrypted_memory(&self, id: u16, slot: &Slot) -> Result<()> {
        debug!(id, guest_phys_addr = %format_args!("{:x?}", slot.gpa()), "mapping private memory");

        let shared_mapping = slot.shared_mapping();
        let restricted_fd = slot.restricted_fd();

        unsafe {
            self.map_private_memory(
                id,
                slot.gpa().start_address().as_u64(),
                u64::try_from(shared_mapping.len().get())?,
                u64::try_from(shared_mapping.as_ptr().as_ptr() as usize)?,
                Some(restricted_fd),
                0,
            )?;
        }

        Ok(())
    }

    pub fn create_irqchip(&self) -> Result<()> {
        debug!("creating irqchip");

        ioctl_none!(kvm_create_irqchip, KVMIO, 0x60);
        let res = unsafe { kvm_create_irqchip(self.fd.as_raw_fd()) };
        res.context("failed to create irqchip")?;

        Ok(())
    }

    unsafe fn memory_encrypt_op<'a>(
        &self,
        payload: KvmSevCmdPayload<'a>,
        sev_handle: Option<&SevHandle>,
    ) -> Result<KvmSevCmdPayload<'a>> {
        debug!("executing memory encryption operation");

        let mut cmd = KvmSevCmd {
            payload,
            error: 0,
            sev_fd: sev_handle.map(|sev_handle| sev_handle.fd.as_fd()),
        };

        ioctl_readwrite!(kvm_memory_encrypt_op, KVMIO, 0xba, u64);
        let res =
            kvm_memory_encrypt_op(self.fd.as_raw_fd(), &mut cmd as *mut KvmSevCmd as *mut u64);
        ensure!(cmd.error == 0);
        res.context("failed to execute memory encryption operation")?;

        Ok(cmd.payload)
    }

    pub fn sev_snp_init(&self) -> Result<()> {
        let mut data = KvmSnpInit {
            flags: KvmSnpInitFlags::KVM_SEV_SNP_RESTRICTED_INJET,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpInit { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to initialize sev snp")?;
        Ok(())
    }

    pub fn sev_snp_launch_start(&self, policy: GuestPolicy, sev_handle: &SevHandle) -> Result<()> {
        debug!("starting snp launch");
        let mut data = KvmSevSnpLaunchStart {
            policy,
            ma_uaddr: 0,
            ma_en: 0,
            imi_en: 0,
            gosvw: [0; 16],
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchStart { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to start sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_launch_update(
        &self,
        start_addr: u64,
        uaddr: u64,
        len: u32,
        page_type: PageType,
        vmpl1_perms: VmplPermissions,
        // FIXME: figure out if we need a sev handle for this operation
        sev_handle: &SevHandle,
    ) -> Result<()> {
        debug!("updating snp launch");

        ensure!(
            start_addr & 0xfff == 0,
            "start address is not properly aligned"
        );
        let start_gfn = start_addr >> 12;

        let mut data = KvmSevSnpLaunchUpdate {
            start_gfn,
            uaddr,
            len,
            imi_page: 0,
            page_type: page_type as u8,
            vmpl3_perms: VmplPermissions::empty(),
            vmpl2_perms: VmplPermissions::empty(),
            vmpl1_perms,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchUpdate { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to update sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_launch_finish(
        &self,
        // FIXME: figure out if we need a sev handle for this operation
        sev_handle: &SevHandle,
        host_data: [u8; 32],
    ) -> Result<()> {
        debug!("finishing snp launch");

        let mut data = KvmSevSnpLaunchFinish {
            id_block_uaddr: 0,
            id_auth_uaddr: 0,
            id_block_en: 0,
            auth_key_en: 0,
            host_data,
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchFinish { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to finish sev snp launch")?;
        Ok(())
    }

    pub fn set_memory_attributes(
        &self,
        address: &mut u64,
        size: &mut u64,
        attributes: KvmMemoryAttributes,
    ) -> Result<()> {
        debug!(?address, ?size, ?attributes, "setting memory attributes");

        let mut data = KvmSetMemoryAttributes {
            address: *address,
            size: *size,
            attributes,
            flags: 0,
        };
        ioctl_readwrite!(
            kvm_set_memory_attributes,
            KVMIO,
            0xd3,
            KvmSetMemoryAttributes
        );
        let res = unsafe { kvm_set_memory_attributes(self.fd.as_raw_fd(), &mut data) };
        res.context("failed to set memory attributes")?;
        *address = data.address;
        *size = data.size;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C, align(4096))]
pub struct Page {
    pub bytes: [u8; 4096],
}

impl Page {
    pub const ZERO: Page = Page { bytes: [0; 4096] };
}

impl Default for Page {
    fn default() -> Self {
        Self::ZERO
    }
}

pub struct VcpuHandle {
    fd: OwnedFd,
}

impl VcpuHandle {
    pub fn set_cpuid(&self, entries: &[KvmCpuidEntry2]) -> Result<()> {
        const MAX_ENTRIES: usize = 256;
        let mut buffer = KvmCpuid2::<MAX_ENTRIES> {
            nent: MAX_ENTRIES as u32,
            _padding: 0,
            entries: [KvmCpuidEntry2 {
                function: 0,
                index: 0,
                flags: 0,
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
                padding: [0; 3],
            }; MAX_ENTRIES],
        };

        buffer.nent = u32::try_from(entries.len()).unwrap();
        buffer.entries[..entries.len()].copy_from_slice(entries);

        ioctl_write_ptr!(kvm_get_supported_cpuid, KVMIO, 0x90, KvmCpuid2<0>);
        let res = unsafe {
            kvm_get_supported_cpuid(
                self.fd.as_raw_fd(),
                &mut buffer as *mut KvmCpuid2<MAX_ENTRIES> as *mut KvmCpuid2<0>,
            )
        };
        res.context("failed to set cpuid")?;

        Ok(())
    }

    pub fn get_kvm_run_block(&self) -> Result<VolatilePtr<KvmRun>> {
        // FIXME: unmap the memory
        let res = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(size_of::<KvmRun>()).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                Some(self.fd.as_fd()),
                0,
            )
        };
        let ptr = res.context("failed to map vcpu kvm_run block")?;
        let ptr = unsafe { VolatilePtr::new_read_write(NonNull::new_unchecked(ptr.cast())) };
        Ok(ptr)
    }

    /// Returns `true` if the cpu ran interrupted or returns `false` if the
    /// thread was interrupted by a signal.
    pub fn run(&self) -> Result<bool> {
        debug!("running vcpu");

        ioctl_write_int_bad!(kvm_run, request_code_none!(KVMIO, 0x80));

        loop {
            let res = unsafe { kvm_run(self.fd.as_raw_fd(), 0) };
            match res {
                Ok(_) => return Ok(true),
                Err(Errno::EAGAIN) => {}
                Err(Errno::EINTR) => return Ok(false),
                Err(e) => return Err(e).context("failed to run vcpu"),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

const KVM_NR_INTERRUPTS: usize = 256;

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; (KVM_NR_INTERRUPTS + 63) / 64],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub ty: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    _padding: u8,
}

impl std::fmt::Debug for KvmSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmSegment")
            .field("base", &self.base)
            .field("limit", &self.limit)
            .field("selector", &self.selector)
            .field("ty", &self.ty)
            .field("present", &self.present)
            .field("dpl", &self.dpl)
            .field("db", &self.db)
            .field("s", &self.s)
            .field("l", &self.l)
            .field("g", &self.g)
            .field("avl", &self.avl)
            .field("unusable", &self.unusable)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    _padding: [u16; 3],
}

impl std::fmt::Debug for KvmDtable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmDtable")
            .field("base", &self.base)
            .field("limit", &self.limit)
            .finish()
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmRun {
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    padding1: [u8; 6],

    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,

    pub cr8: u64,
    pub apic_base: u64,

    pub exit_data: [u8; 256],

    pub kvm_valid_regs: u64,
    pub kvm_dirty_regs: u64,
    pub regs: KvmSyncRegs,

    padding2: [u8; 1744],

    space_for_data: [u8; 4096],
}

impl KvmRun {
    pub fn exit(&self) -> KvmExit {
        match self.exit_reason {
            0 => KvmExit::Unknown(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitUnknown>()],
            )),
            2 => KvmExit::Io(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitIo>()],
            )),
            5 => KvmExit::Hlt,
            6 => KvmExit::Mmio(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMmio>()],
            )),
            8 => KvmExit::Shutdown,
            9 => KvmExit::FailEntry(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitFailEntry>()],
            )),
            10 => KvmExit::Interrupted,
            17 => KvmExit::Internal(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitInternalError>()],
            )),
            24 => KvmExit::SystemEvent(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitSystemEvent>()],
            )),
            38 => KvmExit::MemoryFault(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitMemoryFault>()],
            )),
            50 => KvmExit::Vmgexit(pod_read_unaligned(
                &self.exit_data[..size_of::<KvmExitVmgexit>()],
            )),
            exit_reason => KvmExit::Other { exit_reason },
        }
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmSyncRegs {
    pub regs: KvmRegs,
    pub sregs: KvmSregs,
    pub events: KvmVcpuEvents,
    _padding: [u8; 1528],
}

impl std::fmt::Debug for KvmSyncRegs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmSyncRegs")
            .field("regs", &self.regs)
            .field("sregs", &self.sregs)
            .field("events", &self.events)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmVcpuEvents {
    pub exception: KvmVcpuEventsException,
    pub interrupt: KvmVcpuEventsInterrupt,
    pub nmi: KvmVcpuEventsNmi,
    pub sipi_vector: u32,
    pub flags: u32,
    pub smi: KvmVcpuEventsSmi,
    reserved: [u8; 27],
    pub exception_has_payload: u8,
    pub exception_payload: u64,
}

impl std::fmt::Debug for KvmVcpuEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmVcpuEvents")
            .field("exception", &self.exception)
            .field("interrupt", &self.interrupt)
            .field("nmi", &self.nmi)
            .field("sipi_vector", &self.sipi_vector)
            .field("flags", &self.flags)
            .field("smi", &self.smi)
            .field("exception_has_payload", &self.exception_has_payload)
            .field("exception_payload", &self.exception_payload)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsException {
    pub injected: u8,
    pub nr: u8,
    pub has_error_code: u8,
    pub pending: u8,
    pub error_code: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsInterrupt {
    pub injected: u8,
    pub nr: u8,
    pub soft: u8,
    pub shadow: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsNmi {
    pub injected: u8,
    pub pending: u8,
    pub masked: u8,
    pub pad: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsSmi {
    pub smm: u8,
    pub pending: u8,
    pub smm_inside_nmi: u8,
    pub latched_init: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum KvmExit {
    Unknown(KvmExitUnknown),
    Io(KvmExitIo),
    Hlt,
    Mmio(KvmExitMmio),
    Shutdown,
    FailEntry(KvmExitFailEntry),
    Interrupted,
    Internal(KvmExitInternalError),
    SystemEvent(KvmExitSystemEvent),
    MemoryFault(KvmExitMemoryFault),
    Vmgexit(KvmExitVmgexit),
    Other { exit_reason: u32 },
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitUnknown {
    pub hardware_exit_reason: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    /// relative to kvm_run start
    pub data_offset: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitDebug {
    pub exception: u32,
    pub pad: u32,
    pub pc: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitFailEntry {
    pub hardware_entry_failure_reason: u64,
    pub cpu: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitInternalError {
    pub suberror: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitSystemEvent {
    pub ty: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMemoryFault {
    pub flags: KvmExitMemoryFaultFlags,
    pub gpa: u64,
    pub size: u64,
}

bitflags! {
    #[derive(Pod, Zeroable)]
    #[repr(transparent)]
    pub struct KvmExitMemoryFaultFlags: u64 {
        const PRIVATE = 1 << 0;
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitVmgexit {
    pub ghcb_msr: u64,
    pub error: u8,
}

mod hidden {
    use super::KvmCpuidEntry2;

    #[repr(C)]
    pub struct KvmCpuid2<const N: usize> {
        pub nent: u32,
        pub _padding: u32,
        pub entries: [KvmCpuidEntry2; N],
    }
}

#[repr(C)]
pub struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: KvmUserspaceMemoryRegionFlags,
    guest_phys_addr: u64,
    /// bytes
    memory_size: u64,
    /// start of the userspace allocated memory
    userspace_addr: u64,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmUserspaceMemoryRegionFlags: u32 {
        const KVM_MEM_LOG_DIRTY_PAGES = 1 << 0;
        const KVM_MEM_READONLY = 1 << 1;
        const KVM_MEM_PRIVATE = 1 << 2;
    }
}

#[repr(C)]
pub struct KvmUserspaceMemoryRegion2<'a> {
    region: KvmUserspaceMemoryRegion,
    restricted_offset: u64,
    restricted_fd: Option<BorrowedFd<'a>>,
    _pad1: u32,
    _pad2: [u64; 14],
}

pub struct SevHandle {
    fd: OwnedFd,
}

impl SevHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/sev")
            .context("failed to open /dev/sev")?;
        let fd = OwnedFd::from(file);
        Ok(Self { fd })
    }
}

#[repr(C)]
struct KvmSevCmd<'a, 'b> {
    pub payload: KvmSevCmdPayload<'a>,
    pub error: u32,
    pub sev_fd: Option<BorrowedFd<'b>>,
}

#[allow(clippy::enum_variant_names)]
#[repr(C, u32)]
// FIXME: Figure out which ones need `&mut T` and which ones need `&T`
pub enum KvmSevCmdPayload<'a> {
    KvmSevSnpInit { data: &'a mut KvmSnpInit } = 22,
    KvmSevSnpLaunchStart { data: &'a mut KvmSevSnpLaunchStart } = 23,
    KvmSevSnpLaunchUpdate { data: &'a mut KvmSevSnpLaunchUpdate } = 24,
    KvmSevSnpLaunchFinish { data: &'a mut KvmSevSnpLaunchFinish } = 25,
}

#[repr(C)]
pub struct KvmSnpInit {
    pub flags: KvmSnpInitFlags,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmSnpInitFlags: u64 {
        const KVM_SEV_SNP_RESTRICTED_INJET = 1 << 0;
        const KVM_SEV_SNP_RESTRICTED_TIMER_INJET = 1 << 1;
    }
}

#[repr(C)]
pub struct KvmSevSnpLaunchStart {
    /// Guest policy to use.
    pub policy: GuestPolicy,
    /// userspace address of migration agent
    pub ma_uaddr: u64,
    /// 1 if the migtation agent is enabled
    pub ma_en: u8,
    /// set IMI to 1.
    pub imi_en: u8,
    /// guest OS visible workarounds
    pub gosvw: [u8; 16],
    pub _pad: [u8; 6],
}

#[repr(C)]
pub struct KvmSevSnpLaunchUpdate {
    /// Guest page number to start from.
    pub start_gfn: u64,
    /// userspace address need to be encrypted
    pub uaddr: u64,
    /// length of memory region
    pub len: u32,
    /// 1 if memory is part of the IMI
    pub imi_page: u8,
    /// page type
    pub page_type: u8,
    /// VMPL3 permission mask
    pub vmpl3_perms: VmplPermissions,
    /// VMPL2 permission mask
    pub vmpl2_perms: VmplPermissions,
    /// VMPL1 permission mask
    pub vmpl1_perms: VmplPermissions,
}

#[repr(C)]
pub struct KvmSevSnpLaunchFinish {
    id_block_uaddr: u64,
    id_auth_uaddr: u64,
    id_block_en: u8,
    auth_key_en: u8,
    host_data: [u8; 32],
    _pad: [u8; 6],
}

#[repr(C)]
pub struct KvmSetMemoryAttributes {
    address: u64,
    size: u64,
    attributes: KvmMemoryAttributes,
    flags: u64,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmMemoryAttributes: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const PRIVATE = 1 << 3;
    }
}
