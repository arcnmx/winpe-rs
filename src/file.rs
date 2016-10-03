use std::io::{self, Read};
use {image, nt, parse, traits};

pub struct File<R> {
    read: R,
    dos: image::DosHeader,
    dos_stub: Vec<u8>,
    nt: nt::NtHeaders<'static>,
    data_directories: Vec<image::DataDirectory>,
    sections: Vec<image::SectionHeader>,
}

impl<R: io::Read> File<R> {
    pub fn new(mut read: R) -> io::Result<Self> {
        let (dos, dos_stub, nt, dirs, sections) = try!(parse::read_headers(&mut read));

        Ok(File {
            read: read,
            dos: dos,
            dos_stub: dos_stub,
            nt: nt,
            data_directories: dirs,
            sections: sections,
        })
    }
}

impl<R> traits::PeHeaders for File<R> {
    fn kind(&self) -> nt::NtKind {
        self.nt.kind()
    }

    fn dos_header(&self) -> &image::DosHeader {
        &self.dos
    }

    fn dos_stub(&self) -> &[u8] {
        &self.dos_stub
    }

    fn nt_headers(&self) -> nt::NtHeaders {
        use std::borrow::{Borrow, Cow};

        match self.nt {
            nt::NtHeaders::Win32(ref nt) => nt::NtHeaders::Win32(Cow::Borrowed(nt.borrow())),
            nt::NtHeaders::Win64(ref nt) => nt::NtHeaders::Win64(Cow::Borrowed(nt.borrow())),
        }
    }

    fn directory_headers(&self) -> &[image::DataDirectory] {
        &self.data_directories
    }

    fn section_headers(&self) -> &[image::SectionHeader] {
        &self.sections
    }
}

/*impl<'a, R: io::Read + io::Seek> traits::PeRead for File<&'a mut R> {
    type Read = io::Take<&'a mut R>;

    fn section_segment(&self, section: &image::SectionHeader, offset: u32, size: u32) -> io::Result<Self::Read> {
        if section.pointer_to_raw_data() == 0 && section.size_of_raw_data() == 0 {
            // Ok(io::repeat(0).take(section.size_of_raw_data() as u64))
            unimplemented!()
        } else {
            section.pointer_to_raw_data().checked_add(offset)
                .ok_or_else(|| parse::invalid_data("bad segment rva"))
                .and_then(|offset| self.read.seek(io::SeekFrom::Start(offset as u64)))
                .map(|_| self.read.take(size as u64))
        }
    }
}*/
