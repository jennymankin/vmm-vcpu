// Copyright 2018-2019 CrowdStrike, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Cloudbase Solutions Srl
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem::size_of;

///
/// Single MSR to be read/written
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct MsrEntry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}

#[cfg(unix)]
pub use kvm_bindings::kvm_msr_entry as MsrEntry;

///
/// Array of MSR entries
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct MsrEntries {
    pub nmsrs: u32,
    pub pad: u32,
    pub entries: __IncompleteArrayField<MsrEntry>,
}

#[cfg(unix)]
pub use kvm_bindings::kvm_msrs as MsrEntries;

///
/// Standard registers (general purpose plus instruction pointer and flags)
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct StandardRegisters {
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

#[cfg(unix)]
pub use kvm_bindings::kvm_regs as StandardRegisters;

///
/// Special registers (segment, task, descriptor table, control, and additional
/// registers, plus the interrupt bitmap)
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct SpecialRegisters {
    pub cs: SegmentRegister,
    pub ds: SegmentRegister,
    pub es: SegmentRegister,
    pub fs: SegmentRegister,
    pub gs: SegmentRegister,
    pub ss: SegmentRegister,
    pub tr: SegmentRegister,
    pub ldt: SegmentRegister,
    pub gdt: DescriptorTable,
    pub idt: DescriptorTable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4usize],
}

#[cfg(unix)]
pub use kvm_bindings::kvm_sregs as SpecialRegisters;

///
/// Segment register (used for CS, DS, ES, FS, GS, SS)
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct SegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[cfg(unix)]
pub use kvm_bindings::kvm_segment as SegmentRegister;

///
/// Descriptor Table
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct DescriptorTable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3usize],
}

#[cfg(unix)]
pub use kvm_bindings::kvm_dtable as DescriptorTable;

///
/// Floating Point Unit State
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct FpuState {
    pub fpr: [[u8; 16usize]; 8usize],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16usize]; 16usize],
    pub mxcsr: u32,
    pub pad2: u32,
}

#[cfg(unix)]
pub use kvm_bindings::kvm_fpu as FpuState;

///
/// Entry describing a CPUID feature/leaf. Features can be set as responses to
/// the CPUID instruction.
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct CpuIdEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3usize],
}

#[cfg(unix)]
use kvm_bindings::kvm_cpuid_entry2 as CpuIdEntry2;

///
/// Array of CpuId2 entries, each of which describing a feature/leaf to be set
///
#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Default)]
pub struct CpuId2 {
    pub nent: u32,
    pub padding: u32,
    pub entries: __IncompleteArrayField<CpuIdEntry2>,
}

#[cfg(unix)]
use kvm_bindings::kvm_cpuid2 as CpuId2;

/// Windows definition of the LAPIC state, the set of memory mapped registers
/// that describe the Local APIC. Windows-based VMMs require 4KB of memory to
/// describe the LAPIC state, or the Windows APIs will fail, even though the
/// architecture-specified space requirement is only 1KB.
#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LapicState {
    pub regs: [::std::os::raw::c_char; 4096usize],
}

#[cfg(windows)]
impl Default for LapicState {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

#[cfg(windows)]
impl ::std::fmt::Debug for LapicState {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.regs[..].fmt(fmt)
    }
}

#[test]
fn vcpu_test_layout_lapic_state() {
    assert_eq!(
        ::std::mem::size_of::<LapicState>(),
        4096usize,
        concat!("Size of: ", stringify!(LapicState))
    );
    assert_eq!(
        ::std::mem::align_of::<LapicState>(),
        1usize,
        concat!("Alignment of ", stringify!(LapicState))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<LapicState>())).regs as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(LapicState),
            "::",
            stringify!(regs)
        )
    );
}

/// Unix definition of the LAPIC state, the set of memory mapped registers that
/// describe the Local APIC. Unix-based VMMs only require 1KB of memory to
/// describe the LAPIC state.
#[cfg(unix)]
pub use kvm_bindings::kvm_lapic_state as LapicState;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// Wrapper for `CpuId2` which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
pub struct CpuId {
    /// Wrapper over `CpuId2` from which we only use the first element.
    cpuid: Vec<CpuId2>,
    // Number of `CpuIdEntry2` structs at the end of CpuId2.
    allocated_len: usize,
}

impl Clone for CpuId {
    fn clone(&self) -> Self {
        let mut cpuid = Vec::with_capacity(self.cpuid.len());
        for _ in 0..self.cpuid.len() {
            cpuid.push(CpuId2::default());
        }

        let num_bytes = self.cpuid.len() * size_of::<CpuId2>();

        let src_byte_slice =
            unsafe { std::slice::from_raw_parts(self.cpuid.as_ptr() as *const u8, num_bytes) };

        let dst_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(cpuid.as_mut_ptr() as *mut u8, num_bytes) };

        dst_byte_slice.copy_from_slice(src_byte_slice);

        CpuId {
            cpuid,
            allocated_len: self.allocated_len,
        }
    }
}

#[cfg(test)]
impl PartialEq for CpuId {
    fn eq(&self, other: &CpuId) -> bool {
        let entries: &[CpuIdEntry2] =
            unsafe { self.cpuid[0].entries.as_slice(self.allocated_len) };
        let other_entries: &[CpuIdEntry2] =
            unsafe { self.cpuid[0].entries.as_slice(other.allocated_len) };
        self.allocated_len == other.allocated_len && entries == other_entries
    }
}

impl CpuId {
    /// Creates a new `CpuId` structure that can contain at most `array_len` KVM CPUID entries.
    ///
    /// # Arguments
    ///
    /// * `array_len` - Maximum number of CPUID entries.
    ///
    pub fn new(array_len: usize) -> CpuId {
        let mut cpuid = vec_with_array_field::<CpuId2, CpuIdEntry2>(array_len);
        cpuid[0].nent = array_len as u32;

        CpuId {
            cpuid,
            allocated_len: array_len,
        }
    }

    /// Get the mutable entries slice so they can be modified before passing to the VCPU.
    ///
    pub fn mut_entries_slice(&mut self) -> &mut [CpuIdEntry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.cpuid[0].nent as usize > self.allocated_len {
            self.cpuid[0].nent = self.allocated_len as u32;
        }
        let nent = self.cpuid[0].nent as usize;
        unsafe { self.cpuid[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_ptr(&self) -> *const CpuId2 {
        &self.cpuid[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_mut_ptr(&mut self) -> *mut CpuId2 {
        &mut self.cpuid[0]
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);

#[cfg(windows)]
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }
    #[inline]
    pub unsafe fn as_ptr(&self) -> *const T {
        ::std::mem::transmute(self)
    }
    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        ::std::mem::transmute(self)
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}

#[cfg(windows)]
impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}

#[cfg(windows)]
impl<T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}
