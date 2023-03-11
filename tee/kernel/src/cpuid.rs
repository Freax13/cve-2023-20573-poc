use core::cell::UnsafeCell;

use snp_types::cpuid::CpuidPage;

use crate::FakeSync;

#[no_mangle]
#[link_section = ".cpuid_page"]
static CPUID_PAGE: FakeSync<UnsafeCell<CpuidPage>> =
    FakeSync::new(UnsafeCell::new(CpuidPage::zero()));
