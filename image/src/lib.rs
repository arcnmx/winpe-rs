//#![deny(missing_docs)]
#![doc(html_root_url = "http://arcnmx.github.io/winpe-rs/")]

extern crate pod;
extern crate byteorder_pod;

use std::{str, slice, mem};
use std::ffi::CStr;
use pod::Pod;
use pod::packed::{Unaligned, Packed};
use byteorder_pod::unaligned::Le;
use byteorder_pod::EndianConvert;

pub const DOS_SIGNATURE: u16 = 0x5a4d;
pub const OS2_SIGNATURE: u16 = 0x454e;
pub const OS2_SIGNATURE_LE: u16 = 0x454c;
pub const VXD_SIGNATURE: u16 = 0x454c;
pub const NT_SIGNATURE: u32 = 0x4550;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DosHeader {
    pub magic: Le<u16>,
    pub cblp: Le<u16>,
    pub cp: Le<u16>,
    pub crlc: Le<u16>,
    pub cparhdr: Le<u16>,
    pub minalloc: Le<u16>,
    pub maxalloc: Le<u16>,
    pub ss: Le<u16>,
    pub sp: Le<u16>,
    pub csum: Le<u16>,
    pub ip: Le<u16>,
    pub cs: Le<u16>,
    pub lfarlc: Le<u16>,
    pub ovno: Le<u16>,
    pub res: [Le<u16>; 4],
    pub oemid: Le<u16>,
    pub oeminfo: Le<u16>,
    pub res2: [Le<u16>; 10],
    pub lfanew: Le<u32>,
}

unsafe impl Pod for DosHeader { }
unsafe impl Unaligned for DosHeader { }
unsafe impl Packed for DosHeader { }

impl DosHeader {
    pub fn magic(&self) -> u16 {
        self.magic.get()
    }

    pub fn cblp(&self) -> u16 {
        self.cblp.get()
    }

    pub fn cp(&self) -> u16 {
        self.cp.get()
    }

    pub fn crlc(&self) -> u16 {
        self.crlc.get()
    }

    pub fn cparhdr(&self) -> u16 {
        self.cparhdr.get()
    }

    pub fn minalloc(&self) -> u16 {
        self.minalloc.get()
    }

    pub fn maxalloc(&self) -> u16 {
        self.maxalloc.get()
    }

    pub fn ss(&self) -> u16 {
        self.ss.get()
    }

    pub fn sp(&self) -> u16 {
        self.sp.get()
    }

    pub fn csum(&self) -> u16 {
        self.csum.get()
    }

    pub fn ip(&self) -> u16 {
        self.ip.get()
    }

    pub fn cs(&self) -> u16 {
        self.cs.get()
    }

    pub fn lfarlc(&self) -> u16 {
        self.lfarlc.get()
    }

    pub fn ovno(&self) -> u16 {
        self.ovno.get()
    }

    pub fn res(&self, index: usize) -> Option<u16> {
        self.res.get(index).map(Le::get)
    }

    pub fn oemid(&self) -> u16 {
        self.oemid.get()
    }

    pub fn oeminfo(&self) -> u16 {
        self.oeminfo.get()
    }

    pub fn res2(&self, index: usize) -> Option<u16> {
        self.res2.get(index).map(Le::get)
    }

    pub fn lfanew(&self) -> u32 {
        self.lfanew.get()
    }
}

pub const FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
pub const FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
pub const FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;
pub const FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const FILE_BYTES_REVERSED_LO: u16 = 0x0080;
pub const FILE_32BIT_MACHINE: u16 = 0x0100;
pub const FILE_DEBUG_STRIPPED: u16 = 0x0200;
pub const FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
pub const FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
pub const FILE_SYSTEM: u16 = 0x1000;
pub const FILE_DLL: u16 = 0x2000;
pub const FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
pub const FILE_BYTES_REVERSED_HI: u16 = 0x8000;

pub const FILE_MACHINE_UNKNOWN: u16 = 0;
pub const FILE_MACHINE_I386: u16 = 0x014c;
pub const FILE_MACHINE_R3000: u16 = 0x0162;
pub const FILE_MACHINE_R4000: u16 = 0x0166;
pub const FILE_MACHINE_R10000: u16 = 0x0168;
pub const FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
pub const FILE_MACHINE_ALPHA: u16 = 0x0184;
pub const FILE_MACHINE_SH3: u16 = 0x01a2;
pub const FILE_MACHINE_SH3DSP: u16 = 0x01a3;
pub const FILE_MACHINE_SH3E: u16 = 0x01a4;
pub const FILE_MACHINE_SH4: u16 = 0x01a6;
pub const FILE_MACHINE_SH5: u16 = 0x01a8;
pub const FILE_MACHINE_ARM: u16 = 0x01c0;
pub const FILE_MACHINE_ARMV7: u16 = 0x01c4;
pub const FILE_MACHINE_ARMNT: u16 = 0x01c4;
pub const FILE_MACHINE_THUMB: u16 = 0x01c2;
pub const FILE_MACHINE_AM33: u16 = 0x01d3;
pub const FILE_MACHINE_POWERPC: u16 = 0x01f0;
pub const FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
pub const FILE_MACHINE_IA64: u16 = 0x0200;
pub const FILE_MACHINE_MIPS16: u16 = 0x0266;
pub const FILE_MACHINE_ALPHA64: u16 = 0x0284;
pub const FILE_MACHINE_MIPSFPU: u16 = 0x0366;
pub const FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
pub const FILE_MACHINE_AXP64: u16 = FILE_MACHINE_ALPHA64;
pub const FILE_MACHINE_TRICORE: u16 = 0x0520;
pub const FILE_MACHINE_CEF: u16 = 0x0cef;
pub const FILE_MACHINE_EBC: u16 = 0x0ebc;
pub const FILE_MACHINE_AMD64: u16 = 0x8664;
pub const FILE_MACHINE_M32R: u16 = 0x9041;
pub const FILE_MACHINE_CEE: u16 = 0xc0ee;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileHeader {
    pub machine: Le<u16>,
    pub number_of_sections: Le<u16>,
    pub time_date_stamp: Le<u32>,
    pub pointer_to_symbol_table: Le<u32>, 
    pub number_of_symbols: Le<u32>,
    pub size_of_optional_header: Le<u16>,
    pub characteristics: Le<u16>,
}

unsafe impl Pod for FileHeader { }
unsafe impl Unaligned for FileHeader { }
unsafe impl Packed for FileHeader { }

impl FileHeader {
    pub fn machine(&self) -> u16 {
        self.machine.get()
    }

    pub fn number_of_sections(&self) -> u16 {
        self.number_of_sections.get()
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp.get()
    }

    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.pointer_to_symbol_table.get()
    }

    pub fn number_of_symbols(&self) -> u32 {
        self.number_of_symbols.get()
    }

    pub fn size_of_optional_header(&self) -> u16 {
        self.size_of_optional_header.get()
    }

    pub fn characteristics(&self) -> u16 {
        self.characteristics.get()
    }
}

pub const NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DataDirectory {
    pub virtual_address: Le<u32>,
    pub size: Le<u32>,
}

unsafe impl Pod for DataDirectory { }
unsafe impl Unaligned for DataDirectory { }
unsafe impl Packed for DataDirectory { }

impl DataDirectory {
    pub fn virtual_address(&self) -> u32 {
        self.virtual_address.get()
    }

    pub fn size(&self) -> u32 {
        self.size.get()
    }
}

pub const NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
pub const NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
pub const ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OptionalHeader<T: EndianConvert> {
    pub magic: Le<u16>,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: Le<u32>,
    pub size_of_initialized_data: Le<u32>,
    pub size_of_uninitialized_data: Le<u32>,
    pub address_of_entry_point: Le<u32>,
    pub base_of_code: Le<u32>,
    pub base_of_data: Le<u32>,
    pub image_base: Le<u32>,
    pub section_alignment: Le<u32>,
    pub file_alignment: Le<u32>,
    pub major_operating_system_version: Le<u16>,
    pub minor_operating_system_version: Le<u16>,
    pub major_image_version: Le<u16>,
    pub minor_image_version: Le<u16>,
    pub major_subsystem_version: Le<u16>,
    pub minor_subsystem_version: Le<u16>,
    pub win32_version_value: Le<u32>,
    pub size_of_image: Le<u32>,
    pub size_of_headers: Le<u32>,
    pub check_sum: Le<u32>,
    pub subsystem: Le<u16>,
    pub dll_characteristics: Le<u16>,
    pub size_of_stack_reserve: Le<T>,
    pub size_of_stack_commit: Le<T>,
    pub size_of_heap_reserve: Le<T>,
    pub size_of_heap_commit: Le<T>,
    pub loader_flags: Le<u32>,
    pub number_of_rva_and_sizes: Le<u32>,
}

unsafe impl<T: EndianConvert + Pod> Pod for OptionalHeader<T> { }
unsafe impl<T: EndianConvert + Unaligned> Unaligned for OptionalHeader<T> { }
unsafe impl<T: EndianConvert + Packed> Packed for OptionalHeader<T> { }

pub type OptionalHeader32 = OptionalHeader<u32>;
pub type OptionalHeader64 = OptionalHeader<u64>;

impl<T: EndianConvert> OptionalHeader<T> {
    pub fn magic(&self) -> u16 {
        self.magic.get()
    }

    pub fn major_linker_version(&self) -> u8 {
        self.major_linker_version
    }

    pub fn minor_linker_version(&self) -> u8 {
        self.minor_linker_version
    }

    pub fn size_of_code(&self) -> u32 {
        self.size_of_code.get()
    }

    pub fn size_of_initialized_data(&self) -> u32 {
        self.size_of_initialized_data.get()
    }

    pub fn size_of_uninitialized_data(&self) -> u32 {
        self.size_of_uninitialized_data.get()
    }

    pub fn address_of_entry_point(&self) -> u32 {
        self.address_of_entry_point.get()
    }

    pub fn base_of_code(&self) -> u32 {
        self.base_of_code.get()
    }

    pub fn section_alignment(&self) -> u32 {
        self.section_alignment.get()
    }

    pub fn file_alignment(&self) -> u32 {
        self.file_alignment.get()
    }

    pub fn major_operating_system_version(&self) -> u16 {
        self.major_operating_system_version.get()
    }

    pub fn minor_operating_system_version(&self) -> u16 {
        self.minor_operating_system_version.get()
    }

    pub fn major_image_version(&self) -> u16 {
        self.major_image_version.get()
    }

    pub fn minor_image_version(&self) -> u16 {
        self.minor_image_version.get()
    }

    pub fn major_subsystem_version(&self) -> u16 {
        self.major_subsystem_version.get()
    }

    pub fn minor_subsystem_version(&self) -> u16 {
        self.minor_subsystem_version.get()
    }

    pub fn win32_version_value(&self) -> u32 {
        self.win32_version_value.get()
    }

    pub fn size_of_image(&self) -> u32 {
        self.size_of_image.get()
    }

    pub fn size_of_headers(&self) -> u32 {
        self.size_of_headers.get()
    }

    pub fn check_sum(&self) -> u32 {
        self.check_sum.get()
    }

    pub fn subsystem(&self) -> u16 {
        self.subsystem.get()
    }

    pub fn dll_characteristics(&self) -> u16 {
        self.dll_characteristics.get()
    }

    pub fn size_of_stack_reserve(&self) -> T {
        self.size_of_stack_reserve.get()
    }

    pub fn size_of_stack_commit(&self) -> T {
        self.size_of_stack_commit.get()
    }

    pub fn size_of_heap_reserve(&self) -> T {
        self.size_of_heap_reserve.get()
    }

    pub fn size_of_heap_commit(&self) -> T {
        self.size_of_heap_commit.get()
    }

    pub fn loader_flags(&self) -> u32 {
        self.loader_flags.get()
    }

    pub fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes.get()
    }

    pub unsafe fn data_directory(&self) -> &[DataDirectory] {
        slice::from_raw_parts(
            (self as *const _).offset(1) as *const _,
            self.number_of_rva_and_sizes() as usize,
        )
    }
}

impl OptionalHeader<u32> {
    pub fn base_of_data(&self) -> u32 {
        self.base_of_data.get()
    }

    pub fn image_base(&self) -> u32 {
        self.image_base.get()
    }
}

impl OptionalHeader<u64> {
    pub fn image_base(&self) -> u64 {
        self.base_of_data.get() as u64 |
            ((self.image_base.get() as u64) << 32)
    }
}

pub const SUBSYSTEM_UNKNOWN: u16 = 0;
pub const SUBSYSTEM_NATIVE: u16 = 1;
pub const SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const SUBSYSTEM_WINDOWS_CUI: u16 = 3;
pub const SUBSYSTEM_OS2_CUI: u16 = 5;
pub const SUBSYSTEM_POSIX_CUI: u16 = 7;
pub const SUBSYSTEM_NATIVE_WINDOWS: u16 = 8;
pub const SUBSYSTEM_WINDOWS_CE_GUI: u16 = 9;
pub const SUBSYSTEM_EFI_APPLICATION: u16 = 10;
pub const SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
pub const SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
pub const SUBSYSTEM_EFI_ROM: u16 = 13;
pub const SUBSYSTEM_XBOX: u16 = 14;
pub const SUBSYSTEM_WINDOWS_BOOT_APPLICATION: u16 = 16;

pub const DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
pub const DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
pub const DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
pub const DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
pub const DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
pub const DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
pub const DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

pub const DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const DIRECTORY_ENTRY_TLS: usize = 9;
pub const DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const DIRECTORY_ENTRY_IAT: usize = 12;
pub const DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NtHeaders<T> {
    pub signature: Le<u32>,
    pub file_header: FileHeader,
    pub optional_header: T,
}

unsafe impl<T: Pod> Pod for NtHeaders<T> { }
unsafe impl<T: Unaligned> Unaligned for NtHeaders<T> { }
unsafe impl<T: Packed> Packed for NtHeaders<T> { }

pub type NtHeaders32 = NtHeaders<OptionalHeader32>;
pub type NtHeaders64 = NtHeaders<OptionalHeader64>;

impl<T> NtHeaders<T> {
    pub fn signature(&self) -> u32 {
        self.signature.get()
    }

    pub fn file_header(&self) -> &FileHeader {
        &self.file_header
    }

    pub fn optional_header(&self) -> &T {
        &self.optional_header
    }

    pub unsafe fn section_headers(&self) -> &[SectionHeader] {
        slice::from_raw_parts(
            (
                (self as *const _ as usize) +
                mem::size_of::<u32>() +
                mem::size_of::<FileHeader>() +
                self.file_header().size_of_optional_header() as usize
            ) as *const _,
            self.file_header().number_of_sections() as usize,
        )
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SectionHeader {
    pub name: [u8; SIZEOF_SHORT_NAME],
    pub virtual_size_physical_address: Le<u32>,
    pub virtual_address: Le<u32>,
    pub size_of_raw_data: Le<u32>,
    pub pointer_to_raw_data: Le<u32>,
    pub pointer_to_relocations: Le<u32>,
    pub pointer_to_linenumbers: Le<u32>,
    pub number_of_relocations: Le<u16>,
    pub number_of_linenumbers: Le<u16>,
    pub characteristics: Le<u32>,
}

unsafe impl Pod for SectionHeader { }
unsafe impl Unaligned for SectionHeader { }
unsafe impl Packed for SectionHeader { }

impl SectionHeader {
    pub fn name(&self) -> Result<&str, str::Utf8Error> {
        //str::from_utf8(self.name.split(|c| c == 0).next().unwrap())
        let len = self.name.iter().take_while(|&&c| c != 0).count();
        str::from_utf8(&self.name[..len])
    }

    pub fn virtual_size(&self) -> u32 {
        self.virtual_size_physical_address.get()
    }

    pub fn physical_address(&self) -> u32 {
        self.virtual_size_physical_address.get()
    }

    pub fn virtual_address(&self) -> u32 {
        self.virtual_address.get()
    }

    pub fn size_of_raw_data(&self) -> u32 {
        self.size_of_raw_data.get()
    }

    pub fn pointer_to_raw_data(&self) -> u32 {
        self.pointer_to_raw_data.get()
    }

    pub fn pointer_to_relocations(&self) -> u32 {
        self.pointer_to_relocations.get()
    }

    pub fn pointer_to_linenumbers(&self) -> u32 {
        self.pointer_to_linenumbers.get()
    }

    pub fn number_of_relocations(&self) -> u16 {
        self.number_of_relocations.get()
    }

    pub fn number_of_linenumbers(&self) -> u16 {
        self.number_of_linenumbers.get()
    }

    pub fn characteristics(&self) -> u32 {
        self.characteristics.get()
    }
}

pub const SIZEOF_SHORT_NAME: usize = 8;

pub const SCN_TYPE_NO_PAD: u32 = 0x00000008;

pub const SCN_CNT_CODE: u32 = 0x00000020;
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const SCN_LNK_OTHER: u32 = 0x00000100;
pub const SCN_LNK_INFO: u32 = 0x00000200;
pub const SCN_LNK_REMOVE: u32 = 0x00000800;
pub const SCN_LNK_COMDAT: u32 = 0x00001000;
pub const SCN_NO_DEFER_SPEC_EXC: u32 = 0x00004000;
pub const SCN_GPREL: u32 = 0x00008000;
pub const SCN_MEM_FARDATA: u32 = 0x00008000;
pub const SCN_MEM_PURGEABLE: u32 = 0x00020000;
pub const SCN_MEM_16BIT: u32 = 0x00020000;
pub const SCN_MEM_LOCKED: u32 = 0x00040000;
pub const SCN_MEM_PRELOAD: u32 = 0x00080000;

pub const SCN_ALIGN_1BYTES: u32 = 0x00100000;
pub const SCN_ALIGN_2BYTES: u32 = 0x00200000;
pub const SCN_ALIGN_4BYTES: u32 = 0x00300000;
pub const SCN_ALIGN_8BYTES: u32 = 0x00400000;
pub const SCN_ALIGN_16BYTES: u32 = 0x00500000;
pub const SCN_ALIGN_32BYTES: u32 = 0x00600000;
pub const SCN_ALIGN_64BYTES: u32 = 0x00700000;
pub const SCN_ALIGN_128BYTES: u32 = 0x00800000;
pub const SCN_ALIGN_256BYTES: u32 = 0x00900000;
pub const SCN_ALIGN_512BYTES: u32 = 0x00A00000;
pub const SCN_ALIGN_1024BYTES: u32 = 0x00B00000;
pub const SCN_ALIGN_2048BYTES: u32 = 0x00C00000;
pub const SCN_ALIGN_4096BYTES: u32 = 0x00D00000;
pub const SCN_ALIGN_8192BYTES: u32 = 0x00E00000;

pub const SCN_ALIGN_MASK: u32 = 0x00F00000;

pub const SCN_LNK_NRELOC_OVFL: u32 = 0x01000000;
pub const SCN_MEM_DISCARDABLE: u32 = 0x02000000;
pub const SCN_MEM_NOT_CACHED: u32 = 0x04000000;
pub const SCN_MEM_NOT_PAGED: u32 = 0x08000000;
pub const SCN_MEM_SHARED: u32 = 0x10000000;
pub const SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const SCN_MEM_READ: u32 = 0x40000000;
pub const SCN_MEM_WRITE: u32 = 0x80000000;

pub const SCN_SCALE_INDEX: u32 = 0x00000001;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Relocation {
    pub virtual_address_reloc_count: Le<u32>,
    pub symbol_table_index: Le<u32>,
    pub kind: Le<u16>,
}

unsafe impl Pod for Relocation { }
unsafe impl Unaligned for Relocation { }
unsafe impl Packed for Relocation { }

impl Relocation {
    pub fn virtual_address(&self) -> u32 {
        self.virtual_address_reloc_count.get()
    }

    pub fn reloc_count(&self) -> u32 {
        self.virtual_address_reloc_count.get()
    }

    pub fn symbol_table_index(&self) -> u32 {
        self.symbol_table_index.get()
    }

    pub fn kind(&self) -> u16 {
        self.kind.get()
    }
}

pub const REL_I386_ABSOLUTE: u16 = 0x0000;
pub const REL_I386_DIR16: u16 = 0x0001;
pub const REL_I386_REL16: u16 = 0x0002;
pub const REL_I386_DIR32: u16 = 0x0006;
pub const REL_I386_DIR32NB: u16 = 0x0007;
pub const REL_I386_SEG12: u16 = 0x0009;
pub const REL_I386_SECTION: u16 = 0x000A;
pub const REL_I386_SECREL: u16 = 0x000B;
pub const REL_I386_TOKEN: u16 = 0x000C;
pub const REL_I386_SECREL7: u16 = 0x000D;
pub const REL_I386_REL32: u16 = 0x0014;

pub const REL_MIPS_ABSOLUTE: u16 = 0x0000;
pub const REL_MIPS_REFHALF: u16 = 0x0001;
pub const REL_MIPS_REFWORD: u16 = 0x0002;
pub const REL_MIPS_JMPADDR: u16 = 0x0003;
pub const REL_MIPS_REFHI: u16 = 0x0004;
pub const REL_MIPS_REFLO: u16 = 0x0005;
pub const REL_MIPS_GPREL: u16 = 0x0006;
pub const REL_MIPS_LITERAL: u16 = 0x0007;
pub const REL_MIPS_SECTION: u16 = 0x000A;
pub const REL_MIPS_SECREL: u16 = 0x000B;
pub const REL_MIPS_SECRELLO: u16 = 0x000C;
pub const REL_MIPS_SECRELHI: u16 = 0x000D;
pub const REL_MIPS_TOKEN: u16 = 0x000E;
pub const REL_MIPS_JMPADDR16: u16 = 0x0010;
pub const REL_MIPS_REFWORDNB: u16 = 0x0022;
pub const REL_MIPS_PAIR: u16 = 0x0025;

pub const REL_ALPHA_ABSOLUTE: u16 = 0x0000;
pub const REL_ALPHA_REFLONG: u16 = 0x0001;
pub const REL_ALPHA_REFQUAD: u16 = 0x0002;
pub const REL_ALPHA_GPREL32: u16 = 0x0003;
pub const REL_ALPHA_LITERAL: u16 = 0x0004;
pub const REL_ALPHA_LITUSE: u16 = 0x0005;
pub const REL_ALPHA_GPDISP: u16 = 0x0006;
pub const REL_ALPHA_BRADDR: u16 = 0x0007;
pub const REL_ALPHA_HINT: u16 = 0x0008;
pub const REL_ALPHA_INLINE_REFLONG: u16 = 0x0009;
pub const REL_ALPHA_REFHI: u16 = 0x000A;
pub const REL_ALPHA_REFLO: u16 = 0x000B;
pub const REL_ALPHA_PAIR: u16 = 0x000C;
pub const REL_ALPHA_MATCH: u16 = 0x000D;
pub const REL_ALPHA_SECTION: u16 = 0x000E;
pub const REL_ALPHA_SECREL: u16 = 0x000F;
pub const REL_ALPHA_REFLONGNB: u16 = 0x0010;
pub const REL_ALPHA_SECRELLO: u16 = 0x0011;
pub const REL_ALPHA_SECRELHI: u16 = 0x0012;
pub const REL_ALPHA_REFQ3: u16 = 0x0013;
pub const REL_ALPHA_REFQ2: u16 = 0x0014;
pub const REL_ALPHA_REFQ1: u16 = 0x0015;
pub const REL_ALPHA_GPRELLO: u16 = 0x0016;
pub const REL_ALPHA_GPRELHI: u16 = 0x0017;

pub const REL_PPC_ABSOLUTE: u16 = 0x0000;
pub const REL_PPC_ADDR64: u16 = 0x0001;
pub const REL_PPC_ADDR32: u16 = 0x0002;
pub const REL_PPC_ADDR24: u16 = 0x0003;
pub const REL_PPC_ADDR16: u16 = 0x0004;
pub const REL_PPC_ADDR14: u16 = 0x0005;
pub const REL_PPC_REL24: u16 = 0x0006;
pub const REL_PPC_REL14: u16 = 0x0007;
pub const REL_PPC_TOCREL16: u16 = 0x0008;
pub const REL_PPC_TOCREL14: u16 = 0x0009;
pub const REL_PPC_ADDR32NB: u16 = 0x000A;
pub const REL_PPC_SECREL: u16 = 0x000B;
pub const REL_PPC_SECTION: u16 = 0x000C;
pub const REL_PPC_IFGLUE: u16 = 0x000D;
pub const REL_PPC_IMGLUE: u16 = 0x000E;
pub const REL_PPC_SECREL16: u16 = 0x000F;
pub const REL_PPC_REFHI: u16 = 0x0010;
pub const REL_PPC_REFLO: u16 = 0x0011;
pub const REL_PPC_PAIR: u16 = 0x0012;
pub const REL_PPC_SECRELLO: u16 = 0x0013;
pub const REL_PPC_SECRELHI: u16 = 0x0014;
pub const REL_PPC_GPREL: u16 = 0x0015;
pub const REL_PPC_TOKEN: u16 = 0x0016;
pub const REL_PPC_TYPEMASK: u16 = 0x00FF;
pub const REL_PPC_NEG: u16 = 0x0100;
pub const REL_PPC_BRTAKEN: u16 = 0x0200;
pub const REL_PPC_BRNTAKEN: u16 = 0x0400;
pub const REL_PPC_TOCDEFN: u16 = 0x0800;

pub const REL_SH3_ABSOLUTE: u16 = 0x0000;
pub const REL_SH3_DIRECT16: u16 = 0x0001;
pub const REL_SH3_DIRECT32: u16 = 0x0002;
pub const REL_SH3_DIRECT8: u16 = 0x0003;
pub const REL_SH3_DIRECT8_WORD: u16 = 0x0004;
pub const REL_SH3_DIRECT8_LONG: u16 = 0x0005;
pub const REL_SH3_DIRECT4: u16 = 0x0006;
pub const REL_SH3_DIRECT4_WORD: u16 = 0x0007;
pub const REL_SH3_DIRECT4_LONG: u16 = 0x0008;
pub const REL_SH3_PCREL8_WORD: u16 = 0x0009;
pub const REL_SH3_PCREL8_LONG: u16 = 0x000A;
pub const REL_SH3_PCREL12_WORD: u16 = 0x000B;
pub const REL_SH3_STARTOF_SECTION: u16 = 0x000C;
pub const REL_SH3_SIZEOF_SECTION: u16 = 0x000D;
pub const REL_SH3_SECTION: u16 = 0x000E;
pub const REL_SH3_SECREL: u16 = 0x000F;
pub const REL_SH3_DIRECT32_NB: u16 = 0x0010;
pub const REL_SH3_GPREL4_LONG: u16 = 0x0011;
pub const REL_SH3_TOKEN: u16 = 0x0012;

pub const REL_SHM_PCRELPT: u16 = 0x0013;
pub const REL_SHM_REFLO: u16 = 0x0014;
pub const REL_SHM_REFHALF: u16 = 0x0015;
pub const REL_SHM_RELLO: u16 = 0x0016;
pub const REL_SHM_RELHALF: u16 = 0x0017;
pub const REL_SHM_PAIR: u16 = 0x0018;

pub const REL_SH_NOMODE: u16 = 0x8000;

pub const REL_ARM_ABSOLUTE: u16 = 0x0000;
pub const REL_ARM_ADDR32: u16 = 0x0001;
pub const REL_ARM_ADDR32NB: u16 = 0x0002;
pub const REL_ARM_BRANCH24: u16 = 0x0003;
pub const REL_ARM_BRANCH11: u16 = 0x0004;
pub const REL_ARM_TOKEN: u16 = 0x0005;
pub const REL_ARM_GPREL12: u16 = 0x0006;
pub const REL_ARM_GPREL7: u16 = 0x0007;
pub const REL_ARM_BLX24: u16 = 0x0008;
pub const REL_ARM_BLX11: u16 = 0x0009;
pub const REL_ARM_SECTION: u16 = 0x000E;
pub const REL_ARM_SECREL: u16 = 0x000F;
pub const REL_ARM_MOV32A: u16 = 0x0010;
pub const REL_ARM_MOV32: u16 = 0x0010;
pub const REL_ARM_MOV32T: u16 = 0x0011;
pub const REL_THUMB_MOV32: u16 = 0x0011;
pub const REL_ARM_BRANCH20T: u16 = 0x0012;
pub const REL_THUMB_BRANCH20: u16 = 0x0012;
pub const REL_ARM_BRANCH24T: u16 = 0x0014;
pub const REL_THUMB_BRANCH24: u16 = 0x0014;
pub const REL_ARM_BLX23T: u16 = 0x0015;
pub const REL_THUMB_BLX23: u16 = 0x0015;

pub const REL_AM_ABSOLUTE: u16 = 0x0000;
pub const REL_AM_ADDR32: u16 = 0x0001;
pub const REL_AM_ADDR32NB: u16 = 0x0002;
pub const REL_AM_CALL32: u16 = 0x0003;
pub const REL_AM_FUNCINFO: u16 = 0x0004;
pub const REL_AM_REL32_1: u16 = 0x0005;
pub const REL_AM_REL32_2: u16 = 0x0006;
pub const REL_AM_SECREL: u16 = 0x0007;
pub const REL_AM_SECTION: u16 = 0x0008;
pub const REL_AM_TOKEN: u16 = 0x0009;

pub const REL_AMD64_ABSOLUTE: u16 = 0x0000;
pub const REL_AMD64_ADDR64: u16 = 0x0001;
pub const REL_AMD64_ADDR32: u16 = 0x0002;
pub const REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const REL_AMD64_REL32: u16 = 0x0004;
pub const REL_AMD64_REL32_1: u16 = 0x0005;
pub const REL_AMD64_REL32_2: u16 = 0x0006;
pub const REL_AMD64_REL32_3: u16 = 0x0007;
pub const REL_AMD64_REL32_4: u16 = 0x0008;
pub const REL_AMD64_REL32_5: u16 = 0x0009;
pub const REL_AMD64_SECTION: u16 = 0x000A;
pub const REL_AMD64_SECREL: u16 = 0x000B;
pub const REL_AMD64_SECREL7: u16 = 0x000C;
pub const REL_AMD64_TOKEN: u16 = 0x000D;
pub const REL_AMD64_SREL32: u16 = 0x000E;
pub const REL_AMD64_PAIR: u16 = 0x000F;
pub const REL_AMD64_SSPAN32: u16 = 0x0010;

pub const REL_IA64_ABSOLUTE: u16 = 0x0000;
pub const REL_IA64_IMM14: u16 = 0x0001;
pub const REL_IA64_IMM22: u16 = 0x0002;
pub const REL_IA64_IMM64: u16 = 0x0003;
pub const REL_IA64_DIR32: u16 = 0x0004;
pub const REL_IA64_DIR64: u16 = 0x0005;
pub const REL_IA64_PCREL21B: u16 = 0x0006;
pub const REL_IA64_PCREL21M: u16 = 0x0007;
pub const REL_IA64_PCREL21F: u16 = 0x0008;
pub const REL_IA64_GPREL22: u16 = 0x0009;
pub const REL_IA64_LTOFF22: u16 = 0x000A;
pub const REL_IA64_SECTION: u16 = 0x000B;
pub const REL_IA64_SECREL22: u16 = 0x000C;
pub const REL_IA64_SECREL64I: u16 = 0x000D;
pub const REL_IA64_SECREL32: u16 = 0x000E;

pub const REL_IA64_DIR32NB: u16 = 0x0010;
pub const REL_IA64_SREL14: u16 = 0x0011;
pub const REL_IA64_SREL22: u16 = 0x0012;
pub const REL_IA64_SREL32: u16 = 0x0013;
pub const REL_IA64_UREL32: u16 = 0x0014;
pub const REL_IA64_PCREL60X: u16 = 0x0015;
pub const REL_IA64_PCREL60B: u16 = 0x0016;
pub const REL_IA64_PCREL60F: u16 = 0x0017;
pub const REL_IA64_PCREL60I: u16 = 0x0018;
pub const REL_IA64_PCREL60M: u16 = 0x0019;
pub const REL_IA64_IMMGPREL64: u16 = 0x001A;
pub const REL_IA64_TOKEN: u16 = 0x001B;
pub const REL_IA64_GPREL32: u16 = 0x001C;
pub const REL_IA64_ADDEND: u16 = 0x001F;

pub const REL_CEF_ABSOLUTE: u16 = 0x0000;
pub const REL_CEF_ADDR32: u16 = 0x0001;
pub const REL_CEF_ADDR64: u16 = 0x0002;
pub const REL_CEF_ADDR32NB: u16 = 0x0003;
pub const REL_CEF_SECTION: u16 = 0x0004;
pub const REL_CEF_SECREL: u16 = 0x0005;
pub const REL_CEF_TOKEN: u16 = 0x0006;

pub const REL_CEE_ABSOLUTE: u16 = 0x0000;
pub const REL_CEE_ADDR32: u16 = 0x0001;
pub const REL_CEE_ADDR64: u16 = 0x0002;
pub const REL_CEE_ADDR32NB: u16 = 0x0003;
pub const REL_CEE_SECTION: u16 = 0x0004;
pub const REL_CEE_SECREL: u16 = 0x0005;
pub const REL_CEE_TOKEN: u16 = 0x0006;

pub const REL_M32R_ABSOLUTE: u16 = 0x0000;
pub const REL_M32R_ADDR32: u16 = 0x0001;
pub const REL_M32R_ADDR32NB: u16 = 0x0002;
pub const REL_M32R_ADDR24: u16 = 0x0003;
pub const REL_M32R_GPREL16: u16 = 0x0004;
pub const REL_M32R_PCREL24: u16 = 0x0005;
pub const REL_M32R_PCREL16: u16 = 0x0006;
pub const REL_M32R_PCREL8: u16 = 0x0007;
pub const REL_M32R_REFHALF: u16 = 0x0008;
pub const REL_M32R_REFHI: u16 = 0x0009;
pub const REL_M32R_REFLO: u16 = 0x000A;
pub const REL_M32R_PAIR: u16 = 0x000B;
pub const REL_M32R_SECTION: u16 = 0x000C;
pub const REL_M32R_SECREL32: u16 = 0x000D;
pub const REL_M32R_TOKEN: u16 = 0x000E;

pub const REL_EBC_ABSOLUTE: u16 = 0x0000;
pub const REL_EBC_ADDR32NB: u16 = 0x0001;
pub const REL_EBC_REL32: u16 = 0x0002;
pub const REL_EBC_SECTION: u16 = 0x0003;
pub const REL_EBC_SECREL: u16 = 0x0004;

pub const REL_BASED_ABSOLUTE: u8 = 0x0;
pub const REL_BASED_HIGH: u8 = 0x1;
pub const REL_BASED_LOW: u8 = 0x2;
pub const REL_BASED_HIGHLOW: u8 = 0x3;
pub const REL_BASED_HIGHADJ: u8 = 0x4;
pub const REL_BASED_MIPS_JMPADDR: u8 = 0x5;
pub const REL_BASED_ARM_MOV32: u8 = 0x5;
pub const REL_BASED_THUMB_MOV32: u8 = 0x7;
pub const REL_BASED_MIPS_JMPADDR16: u8 = 0x9;
pub const REL_BASED_IA64_IMM64: u8 = 0x9;
pub const REL_BASED_DIR64: u8 = 0xa;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BaseRelocation {
    pub virtual_address: Le<u32>,
    pub size_of_block: Le<u32>,
}

unsafe impl Pod for BaseRelocation { }
unsafe impl Unaligned for BaseRelocation { }
unsafe impl Packed for BaseRelocation { }

impl BaseRelocation {
    pub fn virtual_address(&self) -> u32 {
        self.virtual_address.get()
    }

    pub fn size_of_block(&self) -> u32 {
        self.size_of_block.get()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BaseRelocationEntry {
    pub kind_offset: Le<u16>,
}

unsafe impl Pod for BaseRelocationEntry { }
unsafe impl Unaligned for BaseRelocationEntry { }
unsafe impl Packed for BaseRelocationEntry { }

impl BaseRelocationEntry {
    pub fn kind(&self) -> u8 {
        (self.kind_offset.get() >> 12) as u8
    }

    pub fn offset(&self) -> u16 {
        self.kind_offset.get() & 0x0fff
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImportDescriptor {
    pub characteristics_original_first_thunk: Le<u32>,
    pub time_date_stamp: Le<u32>,
    pub forwarder_chain: Le<u32>,
    pub name: Le<u32>,
    pub first_thunk: Le<u32>,
}

unsafe impl Pod for ImportDescriptor { }
unsafe impl Unaligned for ImportDescriptor { }
unsafe impl Packed for ImportDescriptor { }

impl ImportDescriptor {
    pub fn characteristics(&self) -> u32 {
        self.characteristics_original_first_thunk.get()
    }

    pub fn original_first_thunk(&self) -> u32 {
        self.characteristics_original_first_thunk.get()
    }

    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp.get()
    }

    pub fn forwarder_chain(&self) -> u32 {
        self.forwarder_chain.get()
    }

    pub fn name(&self) -> u32 {
        self.name.get()
    }

    pub fn first_thunk(&self) -> u32 {
        self.first_thunk.get()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThunkData<T: EndianConvert> {
    pub data: Le<T>,
}

unsafe impl<T: EndianConvert> Pod for ThunkData<T> { }
unsafe impl<T: EndianConvert> Unaligned for ThunkData<T> { }
unsafe impl<T: EndianConvert> Packed for ThunkData<T> { }

pub type ThunkData32 = ThunkData<u32>;
pub type ThunkData64 = ThunkData<u64>;

impl<T: EndianConvert> ThunkData<T> {
    pub fn forwarder_string(&self) -> T {
        self.data.get()
    }

    pub fn function(&self) -> T {
        self.data.get()
    }

    pub fn ordinal(&self) -> T {
        self.data.get()
    }

    pub fn address_of_data(&self) -> T {
        self.data.get()
    }

    pub fn is_ordinal(&self) -> bool where u64: From<T> {
        let v: u64 = self.ordinal().into();
        (v & (1 << (mem::size_of::<T>() * 8 - 1))) != 0
    }

    pub fn ordinal16(&self) -> u16 where u64: From<T> {
        let v: u64 = self.ordinal().into();
        v as _
    }
}

impl From<ThunkData32> for ThunkData64 {
    fn from(t: ThunkData32) -> Self {
        let data = (t.data.get() & 0x7fffffff) as u64;
        let data = if t.is_ordinal() {
            data | (1 << 63)
        } else {
            data
        };

        ThunkData64 {
            data: data.into(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImportByName {
    pub hint: Le<u16>,
}

unsafe impl Pod for ImportByName { }
unsafe impl Unaligned for ImportByName { }
unsafe impl Packed for ImportByName { }

impl ImportByName {
    pub fn hint(&self) -> u16 {
        self.hint.get()
    }

    pub unsafe fn name(&self) -> &CStr {
        CStr::from_ptr((self as *const _).offset(1) as *const _)
    }
}

#[test]
fn sizes() {
    unimplemented!()
}
