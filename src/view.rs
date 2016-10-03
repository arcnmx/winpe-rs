use std::mem::{self, size_of};
use std::borrow::Cow;
use std::{slice, io};
use pod::Pod;
use traits::{PeHeaders, PeRead, PeWrite};
use {image, parse, nt};

#[derive(Debug, Clone)]
pub struct View<T> {
    data: T,
}

impl<'a, T: From<&'a [u8]>> View<T> {
    pub unsafe fn from_base(ptr: *const u8) -> io::Result<Self> {
        let view = try!(View::new(slice::from_raw_parts(ptr, 0x1000)));
        let len = view.nt_headers().size_of_image();

        Ok(View {
            data: slice::from_raw_parts(ptr, len as usize).into(),
        })
    }

    pub unsafe fn from_base_unchecked(ptr: *const u8) -> Self {
        let view = View {
            data: slice::from_raw_parts(ptr, 0x1000),
        };
        let len = view.nt_headers().size_of_image();

        View {
            data: slice::from_raw_parts(ptr, len as usize).into(),
        }
    }
}

impl<T: AsRef<[u8]>> View<T> {
    pub fn new(data: T) -> io::Result<Self> {
        parse::validate_headers(data.as_ref()).map(|_| View {
            data: data,
        })
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    fn pe_offset(&self) -> usize {
        self.dos_header().lfanew() as usize
    }

    pub fn to_ref(&self) -> View<&[u8]> {
        View {
            data: self.data(),
        }
    }
}

impl<T: AsMut<[u8]>> View<T> {
    pub fn to_mut(&mut self) -> View<&mut [u8]> {
        View {
            data: self.data.as_mut(),
        }
    }
}

impl<T: AsRef<[u8]>> PeHeaders for View<T> {
    fn kind(&self) -> nt::NtKind {
        let header: &parse::FileHeader = Pod::try_merge(&self.data()[self.dos_header().lfanew() as usize..]).unwrap();
        match header.optional_magic.get() {
            image::NT_OPTIONAL_HDR32_MAGIC => nt::NtKind::Win32,
            image::NT_OPTIONAL_HDR64_MAGIC => nt::NtKind::Win64,
            _ => unreachable!("unexpected NT magic"),
        }
    }

    fn dos_header(&self) -> &image::DosHeader {
        Pod::try_merge(self.data()).unwrap()
    }

    fn dos_stub(&self) -> &[u8] {
        &self.data()[size_of::<image::DosHeader>()..self.pe_offset()]
    }

    fn nt_headers(&self) -> nt::NtHeaders {
        match self.kind() {
            nt::NtKind::Win32 => nt::NtHeaders::Win32(Cow::Borrowed(
                Pod::try_merge(&self.data()[self.pe_offset()..]).unwrap()
            )),
            nt::NtKind::Win64 => nt::NtHeaders::Win64(Cow::Borrowed(
                Pod::try_merge(&self.data()[self.pe_offset()..]).unwrap()
            )),
        }
    }

    fn directory_headers(&self) -> &[image::DataDirectory] {
        // WARNING: this is only safe because nt_headers() never returns an owned pointer
        unsafe {
            mem::transmute(self.nt_headers().data_directory())
        }
    }

    fn section_headers(&self) -> &[image::SectionHeader] {
        // WARNING: this is only safe because nt_headers() never returns an owned pointer
        unsafe {
            mem::transmute(self.nt_headers().section_headers())
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized + 'a> PeRead for View<&'a T> {
    type Read = &'a [u8];

    fn section_segment(&self, section: &image::SectionHeader, offset: u32, size: u32) -> io::Result<Self::Read> {
        let data = self.data.as_ref();
        let len = data.len();

        section.virtual_address().checked_add(offset).and_then(|start|
            start.checked_add(size).map(|end| (start as usize, end as usize))
        ).and_then(|(start, end)| if start <= len && end <= len {
            Some(&data[start..end])
        } else {
            None
        }).ok_or_else(|| parse::invalid_data("bad segment rva"))
    }
}

impl<'a, T: AsMut<[u8]> + AsRef<[u8]> + ?Sized + 'a> PeWrite<'a> for View<&'a mut T> {
    type Write = &'a mut [u8];

    fn write_section(&'a mut self, section: &image::SectionHeader, offset: u32) -> io::Result<Self::Write> {
        let data = self.data.as_mut();
        let len = data.len();

        section.virtual_address().checked_add(offset).and_then(|start|
            section.virtual_address().checked_add(section.virtual_size()).map(|end| (start as usize, end as usize))
        ).and_then(move |(start, end)| if start <= len && end <= len {
            Some(&mut data[start..end])
        } else {
            None
        }).ok_or_else(|| parse::invalid_data("bad segment rva"))
    }
}

/*pub fn c_str(&self, rva: u32) -> Option<&CStr> {
    // TODO: this is not safe
    self.segment_from(rva).map(|d| unsafe { CStr::from_ptr(d.as_ptr() as _) })
}*/
