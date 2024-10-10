// SPDX-FileCopyrightText: Copyright 2024 Gloria G.
// SPDX-License-Identifier: BSD-2-Clause

// Documentation sourced from:
//  - https://wiki.osdev.org/MZ
//  - https://wiki.osdev.org/PE
//  - https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

/// MZ

#[repr(C, align(1))]
pub struct MZHeader {
    pub magic: u16,
    pub extra_bytes: u16,
    pub pages: u16,
    pub relocation_count: u16,
    pub header_size: u16,
    pub allocation_minimum: u16,
    pub allocation_maximum: u16,
    pub initial_ss: u16,
    pub initial_sp: u16,
    pub checksum: u16,
    pub initial_ip: u16,
    pub initial_cs: u16,
    pub relocation_table_offset: u16,
    pub overlay: u16,
}

// Starts right after the MZ header, ignoring the overlay table
#[repr(C, align(1))]
pub struct MZPEExtension {
    pub reserved_1: u64,
    pub oem_identifier: u16,
    pub oem_info: u16,
    pub reserved_2: [u8; 20],
    pub pe_header_start: u32
}

pub const MZ_MAGIC: u16 = 0x5a4d; // MZ

/// COFF

#[repr(C, align(1))]
pub struct COFFHeader {
	pub magic: u32,
	pub machine: u16,
	pub section_count: u16,
	pub timestamp: u32,
	pub symbol_table_address: u32,
	pub symbol_count: u32,
	pub optional_header_size: u16,
	pub characteristics: u16
}

pub const COFF_MAGIC: u32 = 0x00004550; // PE\0\0

/// PE32 / PE32+

#[allow(dead_code)]
#[repr(C, align(1))]
pub struct PE32OptionalHeader {
	pub magic: u16,
	pub linker_version_major: u8,
	pub linker_version_minor: u8,
	pub code_size: u32,
	pub initialized_data_size: u32,
	pub uninitialized_data_size: u32,
	pub entry_point_address: u32,
	pub code_base_address: u32,
	pub data_base_address: u32, // NOT USED IN PE32+ !!
	pub image_base_address: u32, // PE32+: u64
	pub section_alignment: u32,
	pub file_alignment: u32,
	pub os_version_major: u16,
	pub os_version_minor: u16,
	pub image_version_major: u16,
	pub image_version_minor: u16,
	pub subsystem_version_major: u16,
	pub subsystem_version_minor: u16,
	pub win32_version: u32,
	pub image_size: u32,
	pub header_size: u32,
	pub checksum: u32,
	pub subsystem: u16,
	pub dll_characteristics: u16,
	pub stack_reserve_size: u32, // PE32+: u64
	pub stack_commit_size: u32, // PE32+: u64
	pub heap_reserve_size: u32, // PE32+: u64
	pub heap_commit_size: u32, // PE32+: u64
	pub loader_flags: u32,
	pub directory_count: u32
}

#[repr(C, align(1))]
pub struct COFFSection {
    pub name: [u8; 8],
    pub size: u32,
    pub address: u32,
    pub raw_data_size: u32,
    pub raw_data_address: u32,
    pub relocation_address: u32,
    pub debug_info_address: u32,
    pub relocation_count: u16,
    pub debug_info_count: u16,
    pub characteristics: u32
}

#[repr(C, align(1))]
pub struct PEOptionalDirectoryTable {
    pub address: u32,
    pub size: u32
}

#[repr(C, align(1))]
pub struct PEDirectoryImportTable {
    pub lookup_address: u32,
    pub timestamp: u32,
    pub forwarder_chain: u32,
    pub name_address: u32,
    pub thunk_address: u32
}

pub const PE_OPTIONAL_32_MAGIC: u16 = 0x010b;
pub const PE_OPTIONAL_32_PLUS_MAGIC: u16 = 0x020b;
