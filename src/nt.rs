use std::borrow::Cow;
use std::mem::{transmute, size_of};
use std::ffi::CString;
use image::{self, NtHeaders32, NtHeaders64};

#[repr(usize)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DirectoryEntry {
    Export = image::DIRECTORY_ENTRY_EXPORT,
    Import = image::DIRECTORY_ENTRY_IMPORT,
    Resource = image::DIRECTORY_ENTRY_RESOURCE,
    Exception = image::DIRECTORY_ENTRY_EXCEPTION,
    Security = image::DIRECTORY_ENTRY_SECURITY,
    BaseReloc = image::DIRECTORY_ENTRY_BASERELOC,
    Debug = image::DIRECTORY_ENTRY_DEBUG,
    Architecture = image::DIRECTORY_ENTRY_ARCHITECTURE,
    GlobalPtr = image::DIRECTORY_ENTRY_GLOBALPTR,
    Tls = image::DIRECTORY_ENTRY_TLS,
    LoadConfig = image::DIRECTORY_ENTRY_LOAD_CONFIG,
    BoundImport = image::DIRECTORY_ENTRY_BOUND_IMPORT,
    Iat = image::DIRECTORY_ENTRY_IAT,
    DelayImport = image::DIRECTORY_ENTRY_DELAY_IMPORT,
    ComDescriptor = image::DIRECTORY_ENTRY_COM_DESCRIPTOR,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ImportSymbol {
    Ordinal(u16),
    Name {
        ordinal_hint: u16,
        name: CString,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Relocation {
    pub kind: RelocationKind,
    pub address: u32,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RelocationKind {
    Absolute = image::REL_BASED_ABSOLUTE,
    High = image::REL_BASED_HIGH,
    Low = image::REL_BASED_LOW,
    HighLow = image::REL_BASED_HIGHLOW,
    HighAdj = image::REL_BASED_HIGHADJ,
    MipsJmpAddrArmMov32 = image::REL_BASED_MIPS_JMPADDR,
    ThumbMov32 = image::REL_BASED_THUMB_MOV32,
    MipsJmpAddr16Ia64Imm64 = image::REL_BASED_MIPS_JMPADDR16,
    Dir64 = image::REL_BASED_DIR64,
}

impl RelocationKind {
    pub fn from_kind(v: u8) -> Option<Self> {
        if v <= 0xa && v != 6 && v != 8 {
            Some(unsafe { transmute(v) })
        } else {
            None
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NtKind {
    Win32,
    Win64,
}

impl NtKind {
    #[inline]
    pub fn size_of_optional_header(&self) -> usize {
        match *self {
            NtKind::Win32 => size_of::<image::OptionalHeader32>(),
            NtKind::Win64 => size_of::<image::OptionalHeader64>(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NtHeaders<'a> {
    Win32(Cow<'a, NtHeaders32>),
    Win64(Cow<'a, NtHeaders64>),
}

impl<'a> NtHeaders<'a> {
    #[inline]
    pub fn kind(&self) -> NtKind {
        match *self {
            NtHeaders::Win32(..) => NtKind::Win32,
            NtHeaders::Win64(..) => NtKind::Win64,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.file_header().number_of_sections() as usize * size_of::<image::SectionHeader>() +
            self.file_header().size_of_optional_header() as usize +
            size_of::<image::FileHeader>() +
            size_of::<u32>()
    }

    #[inline]
    pub fn signature(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.signature(),
            NtHeaders::Win64(ref nt) => nt.signature(),
        }
    }

    #[inline]
    pub fn file_header(&self) -> &image::FileHeader {
        match *self {
            NtHeaders::Win32(ref nt) => nt.file_header(),
            NtHeaders::Win64(ref nt) => nt.file_header(),
        }
    }

    #[inline]
    pub fn optional_header_32(&self) -> Option<&image::OptionalHeader32> {
        match *self {
            NtHeaders::Win32(ref nt) => Some(nt.optional_header()),
            NtHeaders::Win64(..) => None,
        }
    }

    #[inline]
    pub fn optional_header_64(&self) -> Option<&image::OptionalHeader64> {
        match *self {
            NtHeaders::Win32(..) => None,
            NtHeaders::Win64(ref nt) => Some(nt.optional_header()),
        }
    }

    #[inline]
    pub fn magic(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().magic(),
            NtHeaders::Win64(ref nt) => nt.optional_header().magic(),
        }
    }

    #[inline]
    pub fn major_linker_version(&self) -> u8 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().major_linker_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().major_linker_version(),
        }
    }

    #[inline]
    pub fn minor_linker_version(&self) -> u8 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().minor_linker_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().minor_linker_version(),
        }
    }

    #[inline]
    pub fn size_of_code(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_code(),
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_code(),
        }
    }

    #[inline]
    pub fn size_of_initialized_data(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_initialized_data(),
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_initialized_data(),
        }
    }

    #[inline]
    pub fn size_of_uninitialized_data(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_uninitialized_data(),
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_uninitialized_data(),
        }
    }

    #[inline]
    pub fn address_of_entry_point(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().address_of_entry_point(),
            NtHeaders::Win64(ref nt) => nt.optional_header().address_of_entry_point(),
        }
    }

    #[inline]
    pub fn base_of_code(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().base_of_code(),
            NtHeaders::Win64(ref nt) => nt.optional_header().base_of_code(),
        }
    }

    #[inline]
    pub fn section_alignment(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().section_alignment(),
            NtHeaders::Win64(ref nt) => nt.optional_header().section_alignment(),
        }
    }

    #[inline]
    pub fn file_alignment(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().file_alignment(),
            NtHeaders::Win64(ref nt) => nt.optional_header().file_alignment(),
        }
    }

    #[inline]
    pub fn major_operating_system_version(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().major_operating_system_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().major_operating_system_version(),
        }
    }

    #[inline]
    pub fn minor_operating_system_version(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().minor_operating_system_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().minor_operating_system_version(),
        }
    }

    #[inline]
    pub fn major_image_version(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().major_image_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().major_image_version(),
        }
    }

    #[inline]
    pub fn minor_image_version(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().minor_image_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().minor_image_version(),
        }
    }

    #[inline]
    pub fn major_subsystem_version(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().major_subsystem_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().major_subsystem_version(),
        }
    }

    #[inline]
    pub fn minor_subsystem_version(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().minor_subsystem_version(),
            NtHeaders::Win64(ref nt) => nt.optional_header().minor_subsystem_version(),
        }
    }

    #[inline]
    pub fn win32_version_value(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().win32_version_value(),
            NtHeaders::Win64(ref nt) => nt.optional_header().win32_version_value(),
        }
    }

    #[inline]
    pub fn size_of_image(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_image(),
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_image(),
        }
    }

    #[inline]
    pub fn size_of_headers(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_headers(),
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_headers(),
        }
    }

    #[inline]
    pub fn check_sum(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().check_sum(),
            NtHeaders::Win64(ref nt) => nt.optional_header().check_sum(),
        }
    }

    #[inline]
    pub fn subsystem(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().subsystem(),
            NtHeaders::Win64(ref nt) => nt.optional_header().subsystem(),
        }
    }

    #[inline]
    pub fn dll_characteristics(&self) -> u16 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().dll_characteristics(),
            NtHeaders::Win64(ref nt) => nt.optional_header().dll_characteristics(),
        }
    }

    #[inline]
    pub fn size_of_stack_reserve(&self) -> u64 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_stack_reserve() as u64,
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_stack_reserve(),
        }
    }

    #[inline]
    pub fn size_of_stack_commit(&self) -> u64 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_stack_commit() as u64,
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_stack_commit(),
        }
    }

    #[inline]
    pub fn size_of_heap_reserve(&self) -> u64 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_heap_reserve() as u64,
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_heap_reserve(),
        }
    }

    #[inline]
    pub fn size_of_heap_commit(&self) -> u64 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().size_of_heap_commit() as u64,
            NtHeaders::Win64(ref nt) => nt.optional_header().size_of_heap_commit(),
        }
    }

    #[inline]
    pub fn loader_flags(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().loader_flags(),
            NtHeaders::Win64(ref nt) => nt.optional_header().loader_flags(),
        }
    }

    #[inline]
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().number_of_rva_and_sizes(),
            NtHeaders::Win64(ref nt) => nt.optional_header().number_of_rva_and_sizes(),
        }
    }

    #[inline]
    pub fn base_of_data(&self) -> Option<u32> {
        match *self {
            NtHeaders::Win32(ref nt) => Some(nt.optional_header().base_of_data()),
            NtHeaders::Win64(..) => None,
        }
    }

    #[inline]
    pub fn image_base(&self) -> u64 {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().image_base() as u64,
            NtHeaders::Win64(ref nt) => nt.optional_header().image_base(),
        }
    }

    #[inline]
    pub unsafe fn data_directory(&self) -> &[image::DataDirectory] {
        match *self {
            NtHeaders::Win32(ref nt) => nt.optional_header().data_directory(),
            NtHeaders::Win64(ref nt) => nt.optional_header().data_directory(),
        }
    }

    #[inline]
    pub unsafe fn section_headers(&self) -> &[image::SectionHeader] {
        match *self {
            NtHeaders::Win32(ref nt) => nt.section_headers(),
            NtHeaders::Win64(ref nt) => nt.section_headers(),
        }
    }
}
