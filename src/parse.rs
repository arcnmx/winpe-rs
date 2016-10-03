use std::io::{self, Read};
use std::mem::size_of;
use std::borrow::Cow;
use std::cmp;
use pod::{Pod, PodReadExt, PodWriteExt};
use byteorder_pod::unaligned::Le;
use result::OptionResultExt;
use {nt, image, traits};

pub fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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
    fn try_next(&mut self) -> io::Result<Option<nt::Relocation>> {
        loop {
            match try!(self.read.by_ref().take(self.size as u64).read_pod_or_none::<image::BaseRelocationEntry>()) {
                Some(reloc) => {
                    self.size -= size_of::<image::BaseRelocationEntry>() as u32;
                    return Ok(Some(nt::Relocation {
                        kind: try!(nt::RelocationKind::from_kind(reloc.kind())
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
    type Item = io::Result<nt::Relocation>;

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

pub struct ImportTableIterator<R, T> {
    fuse: bool,
    read: R,
    view: T,
}

impl<R, T> ImportTableIterator<R, T> {
    pub fn new(imports: R, view: T) -> Self {
        ImportTableIterator {
            fuse: false,
            read: imports,
            view: view,
        }
    }
}

impl<R: Read, T: traits::PeRead> ImportTableIterator<R, T> {
    fn try_next(&mut self) -> io::Result<Option<nt::ImportSymbol>> {
        let value = try!(match self.view.kind() {
            nt::NtKind::Win32 => self.read.read_pod::<image::ThunkData32>().map(From::from),
            nt::NtKind::Win64 => self.read.read_pod::<image::ThunkData64>(),
        });

        Ok(if value.address_of_data() == 0 {
            None
        } else if value.is_ordinal() {
            Some(nt::ImportSymbol::Ordinal(value.ordinal16()))
        } else {
            let data: image::ImportByName = try!(
                self.view.segment(value.address_of_data() as u32, size_of::<image::ImportByName>() as _)
                .and_then(|mut r| r.read_pod())
            );

            Some(nt::ImportSymbol::Name {
                ordinal_hint: data.hint(),
                name: try!(self.view.read_cstring(value.address_of_data() as u32 + size_of::<image::ImportByName>() as u32)),
            })
        })
    }
}

impl<R: Read, T: traits::PeRead> Iterator for ImportTableIterator<R, T> {
    type Item = io::Result<nt::ImportSymbol>;

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

pub fn validate_headers<R: io::Read>(mut r: R) -> io::Result<()> {
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

            nt::NtHeaders::Win32(Cow::Owned(nt))
        },
        image::NT_OPTIONAL_HDR64_MAGIC => {
            let mut nt: image::NtHeaders64 = Pod::zeroed();
            {
                let (buf, remaining) = nt.as_bytes_mut().split_at_mut(size_of::<FileHeader>());
                *Pod::merge_mut(buf).unwrap() = header;
                try!(r.read_exact(remaining));
            }

            nt::NtHeaders::Win64(Cow::Owned(nt))
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

pub fn read_headers<R: io::Read>(mut r: R) -> io::Result<(image::DosHeader, Vec<u8>, nt::NtHeaders<'static>, Vec<image::DataDirectory>, Vec<image::SectionHeader>)> {
    let dos: image::DosHeader = try!(r.read_pod());

    if dos.magic() != image::DOS_SIGNATURE {
        return Err(invalid_data("bad DOS header magic"))
    }

    let dos_stub_len = try!((dos.lfanew() as usize).checked_sub(size_of::<image::DosHeader>())
        .ok_or_else(|| invalid_data("bad PE header offset"))
    );

    let dos_stub_len = dos_stub_len;
    let mut dos_stub = Vec::new();
    if try!(r.by_ref().take(dos_stub_len as u64).read_to_end(&mut dos_stub)) != dos_stub_len as usize {
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

            nt::NtHeaders::Win32(Cow::Owned(nt))
        },
        image::NT_OPTIONAL_HDR64_MAGIC => {
            let mut nt: image::NtHeaders64 = Pod::zeroed();
            {
                let (buf, remaining) = nt.as_bytes_mut().split_at_mut(size_of::<FileHeader>());
                *Pod::merge_mut(buf).unwrap() = header;
                try!(r.read_exact(remaining));
            }

            nt::NtHeaders::Win64(Cow::Owned(nt))
        },
        _ => return Err(invalid_data("bad NT optional header magic")),
    };

    let data_directories = try!((0..nt.number_of_rva_and_sizes()).map(|_|
        r.read_pod::<image::DataDirectory>()
    ).collect::<Result<Vec<_>, _>>());

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

    let sections = try!((0..section_len).map(|_|
        r.read_pod::<image::SectionHeader>()
    ).collect::<Result<Vec<_>, _>>());

    let image_size = try!(sections.iter()
        .map(|sec| sec.virtual_address().checked_add(sec.virtual_size())
            .ok_or_else(|| invalid_data("bad section VirtualSize"))
        )
        .fold(Ok(nt.size_of_headers() as _),
            |max, s| max.and_then(|max| s.map(|s| cmp::max(max, s)))
        )
    );

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

    Ok((dos, dos_stub, nt, data_directories, sections))
}

pub fn write_pe<R: traits::PeRead + ?Sized, W: io::Write>(read: &R, mut write: W, raw: bool) -> io::Result<()> {
    try!(write.write_pod(read.dos_header()));

    try!(write.write_all(read.dos_stub()));

    try!(match read.nt_headers() {
        nt::NtHeaders::Win32(ref headers) => write.write_pod(&**headers),
        nt::NtHeaders::Win64(ref headers) => write.write_pod(&**headers),
    });

    for header in read.directory_headers() {
        try!(write.write_pod(header));
    }

    for header in read.section_headers() {
        try!(write.write_pod(header));
    }

    let mut pos = read.dos_header().lfanew() + read.nt_headers().len() as u32;

    let mut sections: Vec<_> = read.section_headers().into_iter().collect();
    sections.sort_by_key(|s| if raw { s.pointer_to_raw_data() } else { s.virtual_address() });
    for section in read.section_headers() {
        let offset = if raw { section.pointer_to_raw_data() } else { section.virtual_address() };
        let size = if raw { section.size_of_raw_data() } else { section.virtual_size() };
        if offset == 0 && size == 0 {
            continue
        }

        println!("{:08x} with {:08x} size", offset, size);
        let padding = try!(offset.checked_sub(pos)
            .ok_or_else(|| invalid_data("bad section offset"))
        );

        if try!(io::copy(&mut io::repeat(0).take(padding as u64), &mut write)) != padding as u64 {
            return Err(invalid_data("failed to pad section"))
        }

        pos += padding;

        if size > 0 {
            let mut segment = try!(read.section_segment(section, 0, size));
            if try!(io::copy(&mut segment, &mut write)) != size as u64 {
                return Err(invalid_data("failed to copy section"))
            }
            pos += size;
        }
    }

    Ok(())
}

#[repr(C)]
pub struct FileHeader {
    pub signature: Le<u32>,
    pub file_header: image::FileHeader,
    pub optional_magic: Le<u16>,
}

unsafe impl Pod for FileHeader { }
