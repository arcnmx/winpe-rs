use std::io::{self, Read};
use std::mem::{self, size_of};
use std::ffi::CStr;
use std::borrow::Cow;
use std::slice;
use std::cmp;
use pod::{Pod, PodReadExt};
use byteorder_pod::unaligned::Le;
use result::OptionResultExt;
use nt::{NtHeaders, NtKind};
use image;

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

#[derive(Debug, Clone)]
pub struct View<'a> {
    data: &'a [u8],
}

impl<'a> View<'a> {
    pub unsafe fn from_base(ptr: *const u8) -> io::Result<Self> {
        let view = try!(View::new(slice::from_raw_parts(ptr, 0x1000)));
        let len = view.nt_headers().size_of_image();

        Ok(View {
            data: slice::from_raw_parts(ptr, len as usize),
        })
    }

    pub unsafe fn from_base_unchecked(ptr: *const u8) -> Self {
        let view = View {
            data: slice::from_raw_parts(ptr, 0x1000),
        };
        let len = view.nt_headers().size_of_image();

        View {
            data: slice::from_raw_parts(ptr, len as usize),
        }
    }

    pub fn new(data: &'a [u8]) -> io::Result<Self> {
        validate_headers(data).map(|_| View {
            data: data,
        })
    }

    pub fn kind(&self) -> NtKind {
        let header: &FileHeader = Pod::try_merge(&self.data[self.dos_header().lfanew() as usize..]).unwrap();
        match header.optional_magic.get() {
            image::NT_OPTIONAL_HDR32_MAGIC => NtKind::Win32,
            image::NT_OPTIONAL_HDR64_MAGIC => NtKind::Win64,
            _ => unreachable!("unexpected NT magic"),
        }
    }

    pub fn pe_offset(&self) -> usize {
        self.dos_header().lfanew() as usize
    }

    pub fn dos_header(&self) -> &image::DosHeader {
        Pod::try_merge(self.data).unwrap()
    }

    pub fn dos_stub(&self) -> &[u8] {
        &self.data[size_of::<image::DosHeader>()..self.pe_offset()]
    }

    pub fn nt_headers(&self) -> NtHeaders<'a> {
        match self.kind() {
            NtKind::Win32 => NtHeaders::Win32(Cow::Borrowed(
                Pod::try_merge(&self.data[self.pe_offset()..]).unwrap()
            )),
            NtKind::Win64 => NtHeaders::Win64(Cow::Borrowed(
                Pod::try_merge(&self.data[self.pe_offset()..]).unwrap()
            )),
        }
    }

    pub fn data_directories(&self) -> &[image::DataDirectory] {
        // WARNING: this is only safe because nt_headers() never returns an owned pointer
        unsafe {
            mem::transmute(self.nt_headers().data_directory())
        }
    }

    pub fn section_headers(&self) -> &[image::SectionHeader] {
        // WARNING: this is only safe because nt_headers() never returns an owned pointer
        unsafe {
            mem::transmute(self.nt_headers().section_headers())
        }
    }

    pub fn data_directory(&self, index: DirectoryEntry) -> Option<&image::DataDirectory> {
        self.data_directories().get(index as usize)
    }

    pub fn section(&self, header: &image::SectionHeader) -> Option<&[u8]> {
        self.segment(header.virtual_address(), header.virtual_size())
    }

    pub fn data(&self, dir: &image::DataDirectory) -> Option<&[u8]> {
        self.segment(dir.virtual_address(), dir.size())
    }

    pub fn segment(&self, rva: u32, size: u32) -> Option<&[u8]> {
        // TODO: verify that we're actually inside a section, don't cross them, etc?
        let len = self.data.len();
        let rva = rva as usize;
        let end = rva + size as usize;
        if rva <= len && end <= len {
            Some(&self.data[rva..end])
        } else {
            None
        }
    }

    pub fn segment_from(&self, rva: u32) -> Option<&[u8]> {
        // TODO: verify that we're actually inside a section, don't cross them, etc?
        let len = self.data.len();
        let rva = rva as usize;
        if rva <= len {
            Some(&self.data[rva..])
        } else {
            None
        }
    }

    pub fn c_str(&self, rva: u32) -> Option<&CStr> {
        // TODO: this is not safe
        self.segment_from(rva).map(|d| unsafe { CStr::from_ptr(d.as_ptr() as _) })
    }

    pub fn relocations(&self) -> Option<RelocationIterator<&[u8]>> {
        self.data_directory(DirectoryEntry::BaseReloc).and_then(|data|
            self.data(data)
        ).map(RelocationIterator::new)
    }

    pub fn imports(&self) -> Option<ImportIterator<&[u8]>> {
        self.data_directory(DirectoryEntry::Import).and_then(|data|
            self.data(data)
        ).map(ImportIterator::new)
    }

    pub fn import_table(&'a self, desc: &image::ImportDescriptor) -> Option<ImportTableIterator<'a, &'a [u8]>> {
        let address = desc.original_first_thunk();

        self.segment_from(address).map(|data| ImportTableIterator::new(data, self.clone()))
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_headers<R: io::Read>(mut r: R) -> io::Result<()> {
    let dos: image::DosHeader = try!(r.read_pod());

    if dos.magic() != image::DOS_SIGNATURE {
        return Err(invalid_data("bad DOS header magic"))
    }

    let dos_stub_len = try!((dos.lfanew() as usize).checked_sub(size_of::<image::DosHeader>())
        .ok_or_else(|| invalid_data("bad PE header offset"))
    );

    let dos_stub_len = dos_stub_len as u64;
    if try!(io::copy(&mut r.by_ref().take(dos_stub_len), &mut io::sink())) != dos_stub_len {
        return Err(invalid_data("PE header offset past EOF"))
    }

    let header: FileHeader = try!(r.read_pod());

    if header.signature.get() != image::NT_SIGNATURE {
        return Err(invalid_data("bad NT header magic"))
    }

    let nt = match header.optional_magic.get() {
        image::NT_OPTIONAL_HDR32_MAGIC => {
            let mut nt: image::NtHeaders32 = Pod::zeroed();
            {
                let (buf, remaining) = nt.as_bytes_mut().split_at_mut(size_of::<FileHeader>());
                *Pod::merge_mut(buf).unwrap() = header;
                try!(r.read_exact(remaining));
            }

            NtHeaders::Win32(Cow::Owned(nt))
        },
        image::NT_OPTIONAL_HDR64_MAGIC => {
            let mut nt: image::NtHeaders64 = Pod::zeroed();
            {
                let (buf, remaining) = nt.as_bytes_mut().split_at_mut(size_of::<FileHeader>());
                *Pod::merge_mut(buf).unwrap() = header;
                try!(r.read_exact(remaining));
            }

            NtHeaders::Win64(Cow::Owned(nt))
        },
        _ => return Err(invalid_data("bad NT optional header magic")),
    };

    for _ in 0..nt.number_of_rva_and_sizes() {
        try!(r.read_pod::<image::DataDirectory>());
    }

    let read_len = nt.kind().size_of_optional_header() + nt.number_of_rva_and_sizes() as usize * size_of::<image::DataDirectory>();
    let stored_len = nt.file_header().size_of_optional_header() as usize;
    let trailing = try!(stored_len.checked_sub(read_len)
        .ok_or_else(|| invalid_data("bad SizeOfOptionalHeader"))
    );

    let trailing = trailing as u64;
    if try!(io::copy(&mut r.by_ref().take(trailing), &mut io::sink())) != trailing {
        return Err(invalid_data("trailing data directory EOF"))
    }

    let section_len = nt.file_header().number_of_sections() as usize;

    let image_size = try!((0..section_len).map(|_|
        r.read_pod::<image::SectionHeader>().and_then(|sec| sec.virtual_address().checked_add(sec.virtual_size())
            .ok_or_else(|| invalid_data("bad section VirtualSize"))
        )
    ).fold(Ok(nt.size_of_headers() as _),
        |max, s| max.and_then(|max| s.map(|s| cmp::max(max, s)))
    ));

    if image_size > nt.size_of_image() {
        return Err(invalid_data("invalid SizeOfImage"))
    }

    let read_len = nt.len() + dos.lfanew() as usize;
    let stored_len = nt.size_of_headers() as usize;
    let trailing = try!(stored_len.checked_sub(read_len)
        .ok_or_else(|| invalid_data("bad SizeOfHeaders"))
    );

    let trailing = trailing as u64;
    if try!(io::copy(&mut r.by_ref().take(trailing), &mut io::sink())) != trailing {
        return Err(invalid_data("trailing header data EOF"))
    }

    Ok(())
}

#[repr(C)]
struct FileHeader {
    signature: Le<u32>,
    file_header: image::FileHeader,
    optional_magic: Le<u16>,
}

unsafe impl Pod for FileHeader { }

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
    fn from_kind(v: u8) -> Option<Self> {
        if v <= 0xa && v != 6 && v != 8 {
            Some(unsafe { mem::transmute(v) })
        } else {
            None
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Relocation {
    pub kind: RelocationKind,
    pub address: u32,
}

pub struct RelocationIterator<R> {
    base: u32,
    size: u32,
    read: R,
}

impl<R> RelocationIterator<R> {
    pub fn new(relocations: R) -> Self {
        RelocationIterator {
            base: 1,
            size: 0,
            read: relocations
        }
    }
}

impl<R: Read> RelocationIterator<R> {
    fn try_next(&mut self) -> io::Result<Option<Relocation>> {
        loop {
            match try!(self.read.by_ref().take(self.size as u64).read_pod_or_none::<image::BaseRelocationEntry>()) {
                Some(reloc) => {
                    self.size -= size_of::<image::BaseRelocationEntry>() as u32;
                    return Ok(Some(Relocation {
                        kind: try!(RelocationKind::from_kind(reloc.kind())
                            .ok_or_else(|| invalid_data("bad relocation kind"))
                        ),
                        address: self.base + reloc.offset() as u32,
                    }))
                },
                None => {
                    match try!(self.read.read_pod_or_none::<image::BaseRelocation>()) {
                        Some(reloc) => {
                            self.base = reloc.virtual_address();
                            if self.base == 0 {
                                return Ok(None)
                            }

                            self.size = try!(reloc.size_of_block().checked_sub(size_of::<image::BaseRelocation>() as _)
                                .ok_or_else(|| invalid_data("bad relocation block size"))
                            );
                        },
                        None => {
                            // TODO: should this error if not zero-terminated?
                            return Ok(None)
                        },
                    }
                },
            }
        }
    }
}

impl<R: Read> Iterator for RelocationIterator<R> {
    type Item = io::Result<Relocation>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.base == 0 {
            return None
        }

        let res = self.try_next();
        if res.as_ref().map(Option::is_none).unwrap_or(true) {
            self.base = 0
        }
        res.invert()
    }
}


pub struct ImportIterator<R> {
    fuse: bool,
    read: R,
}

impl<R> ImportIterator<R> {
    pub fn new(imports: R) -> Self {
        ImportIterator {
            fuse: false,
            read: imports,
        }
    }
}

impl<R: Read> ImportIterator<R> {
    fn try_next(&mut self) -> io::Result<Option<image::ImportDescriptor>> {
        match try!(self.read.read_pod_or_none::<image::ImportDescriptor>()) {
            Some(import) if import.name() == 0 => Ok(None),
            Some(import) => Ok(Some(import)),
            // TODO: should this error if not zero-terminated?
            None => Ok(None),
        }
    }
}

impl<R: Read> Iterator for ImportIterator<R> {
    type Item = io::Result<image::ImportDescriptor>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fuse {
            return None
        }

        let res = self.try_next();
        if res.as_ref().map(Option::is_none).unwrap_or(true) {
            self.fuse = true
        }
        res.invert()
    }
}

pub struct ImportTableIterator<'a, R> {
    fuse: bool,
    read: R,
    view: View<'a>,
}

impl<'a, R> ImportTableIterator<'a, R> {
    pub fn new(imports: R, view: View<'a>) -> Self {
        ImportTableIterator {
            fuse: false,
            read: imports,
            view: view,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ImportSymbol<'a> {
    Ordinal(u16),
    Name {
        ordinal_hint: u16,
        name: &'a CStr,
    },
}

impl<'a, R: Read> ImportTableIterator<'a, R> {
    fn try_next(&mut self) -> io::Result<Option<ImportSymbol<'a>>> {
        let value = try!(match self.view.kind() {
            NtKind::Win32 => self.read.read_pod::<image::ThunkData32>().map(From::from),
            NtKind::Win64 => self.read.read_pod::<image::ThunkData64>(),
        });

        Ok(if value.address_of_data() == 0 {
            None
        } else if value.is_ordinal() {
            Some(ImportSymbol::Ordinal(value.ordinal16()))
        } else {
            let data: &image::ImportByName = try!(
                self.view.segment(value.address_of_data() as u32, size_of::<image::ImportByName>() as _)
                .and_then(Pod::merge)
                .ok_or_else(|| invalid_data("bad import address"))
            );

            Some(ImportSymbol::Name {
                ordinal_hint: data.hint(),
                // TODO: very unsafe..!
                name: unsafe { mem::transmute(data.name()) },
            })
        })
    }
}

impl<'a, R: Read> Iterator for ImportTableIterator<'a, R> {
    type Item = io::Result<ImportSymbol<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fuse {
            return None
        }

        let res = self.try_next();
        if res.as_ref().map(Option::is_none).unwrap_or(true) {
            self.fuse = true
        }
        res.invert()
    }
}
