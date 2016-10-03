use std::io;
use std::ffi::CString;
use {nt, image, parse};

pub trait PeHeaders {
    fn kind(&self) -> nt::NtKind;
    fn dos_header(&self) -> &image::DosHeader;
    fn dos_stub(&self) -> &[u8];
    fn nt_headers(&self) -> nt::NtHeaders;
    fn directory_headers(&self) -> &[image::DataDirectory];
    fn section_headers(&self) -> &[image::SectionHeader];

    fn directory_header(&self, index: nt::DirectoryEntry) -> Option<&image::DataDirectory> {
        self.directory_headers().get(index as usize)
            .and_then(|dir| if dir.is_empty() {
                None
            } else {
                Some(dir)
            })
    }

    fn find_section(&self, rva: u32) -> Option<&image::SectionHeader> {
        self.section_headers().into_iter()
            .filter(|s| s.contains_virtual_address(rva))
            .max_by_key(|&s| s.virtual_address())
    }
}

pub trait PeRead: PeHeaders {
    type Read: io::Read;

    fn section_segment(&self, section: &image::SectionHeader, offset: u32, size: u32) -> io::Result<Self::Read>;

    fn segment(&self, rva: u32, size: u32) -> io::Result<Self::Read> {
        self.find_section(rva)
            .ok_or_else(|| parse::invalid_data("rva not found in image"))
            .and_then(|section| {
                let offset = rva - section.virtual_address();
                let remaining = section.virtual_size() - offset;
                if size > remaining {
                    Err(parse::invalid_data("segment reaches beyond section end"))
                } else {
                    self.section_segment(section, offset, size)
                }
            })
    }

    fn segment_from(&self, rva: u32) -> io::Result<Self::Read> {
        self.find_section(rva)
            .ok_or_else(|| parse::invalid_data("rva not found in image"))
            .and_then(|section| {
                let offset = rva - section.virtual_address();
                self.section_segment(section, offset, section.virtual_size() - offset)
            })
    }

    fn read_cstring(&self, rva: u32) -> io::Result<CString> {
        use std::io::Read;

        self.segment_from(rva)
            .and_then(|bytes| {
                let mut data = Vec::new();
                for byte in bytes.bytes() {
                    let byte = try!(byte);

                    if byte == 0 {
                        return Ok(
                            unsafe {
                                CString::from_vec_unchecked(data)
                            }
                        )
                    }

                    data.push(byte)
                }

                Err(parse::invalid_data("cstring not null terminated"))
            })
    }

    fn section(&self, section: &image::SectionHeader) -> io::Result<Self::Read> {
        self.section_segment(section, 0, section.virtual_size())
    }

    fn directory(&self, dir: &image::DataDirectory) -> io::Result<Self::Read> {
        self.segment(dir.virtual_address(), dir.size())
    }

    fn relocations(&self) -> io::Result<parse::RelocationIterator<Self::Read>> {
        self.directory_header(nt::DirectoryEntry::BaseReloc)
            .ok_or_else(|| parse::invalid_data("relocation segment not found"))
            .and_then(|data| self.directory(data))
            .map(parse::RelocationIterator::new)
    }

    fn imports(&self) -> io::Result<parse::ImportIterator<Self::Read>> {
        self.directory_header(nt::DirectoryEntry::Import)
            .ok_or_else(|| parse::invalid_data("import segment not found"))
            .and_then(|data| self.directory(data))
            .map(parse::ImportIterator::new)
    }

    fn import_table(&self, desc: &image::ImportDescriptor) -> io::Result<parse::ImportTableIterator<Self::Read, &Self>> {
        let address = desc.original_first_thunk();
        let address = if address == 0 {
            desc.first_thunk()
        } else {
            address
        };

        self.segment_from(address).map(|data| parse::ImportTableIterator::new(data, self))
    }
}

pub trait PeWrite<'a>: PeHeaders {
    type Write: io::Write + 'a;

    fn write_section(&'a mut self, section: &image::SectionHeader, offset: u32) -> io::Result<Self::Write>;
}

impl<'a, T: PeRead + ?Sized> PeRead for &'a T {
    type Read = T::Read;

    fn section_segment(&self, section: &image::SectionHeader, offset: u32, size: u32) -> io::Result<Self::Read> {
        (**self).section_segment(section, offset, size)
    }
}

impl<'a, T: PeWrite<'a> + ?Sized> PeWrite<'a> for &'a mut T {
    type Write = T::Write;

    fn write_section(&'a mut self, section: &image::SectionHeader, offset: u32) -> io::Result<Self::Write> {
        (**self).write_section(section, offset)
    }
}

impl<'a, T: PeHeaders + ?Sized> PeHeaders for &'a T {
    fn kind(&self) -> nt::NtKind {
        (**self).kind()
    }

    fn dos_header(&self) -> &image::DosHeader {
        (**self).dos_header()
    }

    fn dos_stub(&self) -> &[u8] {
        (**self).dos_stub()
    }

    fn nt_headers(&self) -> nt::NtHeaders {
        (**self).nt_headers()
    }

    fn directory_headers(&self) -> &[image::DataDirectory] {
        (**self).directory_headers()
    }

    fn section_headers(&self) -> &[image::SectionHeader] {
        (**self).section_headers()
    }
}

impl<'a, T: PeHeaders + ?Sized> PeHeaders for &'a mut T {
    fn kind(&self) -> nt::NtKind {
        (**self).kind()
    }

    fn dos_header(&self) -> &image::DosHeader {
        (**self).dos_header()
    }

    fn dos_stub(&self) -> &[u8] {
        (**self).dos_stub()
    }

    fn nt_headers(&self) -> nt::NtHeaders {
        (**self).nt_headers()
    }

    fn directory_headers(&self) -> &[image::DataDirectory] {
        (**self).directory_headers()
    }

    fn section_headers(&self) -> &[image::SectionHeader] {
        (**self).section_headers()
    }
}
