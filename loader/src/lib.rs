#[cfg(windows)] extern crate kernel32;
#[cfg(windows)] extern crate winapi;
#[macro_use] extern crate bitflags;
extern crate winpe;

#[cfg(windows)]
pub fn view_current_process() -> Result<winpe::View<'static>, u32> {
    use std::ptr;

    unsafe {
        let handle = kernel32::GetModuleHandleA(ptr::null_mut());

        if handle.is_null() {
            Err(kernel32::GetLastError())
        } else {
            Ok(winpe::View::from_base_unchecked(handle as _))
        }
    }
}

bitflags! {
    pub flags MemoryProtection: u32 {
        const MEMORY_PROTECTION_NONE = 0x0000,
        const MEMORY_PROTECTION_READ = 0x0001,
        const MEMORY_PROTECTION_WRITE = 0x0002,
        const MEMORY_PROTECTION_EXECUTE = 0x0004,
        const MEMORY_PROTECTION_COPY = 0x0008,
        const MEMORY_PROTECTION_GUARD = 0x0010,
        const MEMORY_PROTECTION_NOCACHE = 0x0020,
        const MEMORY_PROTECTION_WRITECOMBINE = 0x0040,
        const MEMORY_PROTECTION_TARGETS = 0x0080,

        const MEMORY_PROTECTION_RX = MEMORY_PROTECTION_READ.bits | MEMORY_PROTECTION_EXECUTE.bits,
        const MEMORY_PROTECTION_RW = MEMORY_PROTECTION_READ.bits | MEMORY_PROTECTION_WRITE.bits,
        const MEMORY_PROTECTION_RWX = MEMORY_PROTECTION_RW.bits | MEMORY_PROTECTION_EXECUTE.bits,
    }
}

#[cfg(windows)]
impl MemoryProtection {
    pub fn into_windows(&self) -> Option<u32> {
        use winapi::winnt as p;

        Some(match *self & (MEMORY_PROTECTION_RWX | MEMORY_PROTECTION_COPY) {
            MEMORY_PROTECTION_EXECUTE => p::PAGE_EXECUTE,
            MEMORY_PROTECTION_RX => p::PAGE_EXECUTE_READ,
            MEMORY_PROTECTION_RWX => p::PAGE_EXECUTE_READWRITE,
            MEMORY_PROTECTION_NONE => p::PAGE_NOACCESS,
            MEMORY_PROTECTION_READ => p::PAGE_READONLY,
            MEMORY_PROTECTION_RW => p::PAGE_READWRITE,
            s if s == MEMORY_PROTECTION_RWX | MEMORY_PROTECTION_COPY => p::PAGE_EXECUTE_WRITECOPY,
            s if s == MEMORY_PROTECTION_WRITE | MEMORY_PROTECTION_COPY => p::PAGE_WRITECOPY,
            _ => return None,
        } | if self.contains(MEMORY_PROTECTION_TARGETS) {
            p::PAGE_TARGETS_INVALID
        } else {
            0
        } | match *self & (MEMORY_PROTECTION_NOCACHE | MEMORY_PROTECTION_WRITECOMBINE | MEMORY_PROTECTION_GUARD) {
            MEMORY_PROTECTION_GUARD => p::PAGE_GUARD,
            MEMORY_PROTECTION_NOCACHE => p::PAGE_NOCACHE,
            MEMORY_PROTECTION_WRITECOMBINE => p::PAGE_WRITECOMBINE,
            s if s.is_empty() => 0,
            _ => return None,
        })
    }

    pub fn from_windows(win: u32) -> Option<Self> {
        use winapi::winnt as p;

        Some(match win & 0xff {
            p::PAGE_EXECUTE => MEMORY_PROTECTION_EXECUTE,
            p::PAGE_EXECUTE_READ => MEMORY_PROTECTION_RX,
            p::PAGE_EXECUTE_READWRITE => MEMORY_PROTECTION_RW,
            p::PAGE_EXECUTE_WRITECOPY => MEMORY_PROTECTION_RWX | MEMORY_PROTECTION_COPY,
            p::PAGE_NOACCESS => MEMORY_PROTECTION_NONE,
            p::PAGE_READONLY => MEMORY_PROTECTION_READ,
            p::PAGE_READWRITE => MEMORY_PROTECTION_RW,
            p::PAGE_WRITECOPY => MEMORY_PROTECTION_RW | MEMORY_PROTECTION_COPY,
            _ => return None,
        } | if win & p::PAGE_TARGETS_INVALID != 0 {
            MEMORY_PROTECTION_TARGETS
        } else {
            Self::empty()
        } | match win & 0xf00 {
            p::PAGE_GUARD => MEMORY_PROTECTION_GUARD,
            p::PAGE_NOCACHE => MEMORY_PROTECTION_NOCACHE,
            p::PAGE_WRITECOMBINE => MEMORY_PROTECTION_WRITECOMBINE,
            0 => Self::empty(),
            _ => return None,
        })
    }
}

#[cfg(windows)]
pub unsafe fn virtual_protect(addr: *const u8, len: usize, protection: MemoryProtection) -> Result<Option<MemoryProtection>, u32> {
    // TODO: optionally use NtVirtualProtect

    let protection = try!(protection.into_windows().ok_or(0u32));

    let mut old: u32 = 0;
    let ret = kernel32::VirtualProtect(addr as _, len as u32, protection, &mut old as *mut _);

    if ret == 0 {
        Err(kernel32::GetLastError())
    } else {
        Ok(MemoryProtection::from_windows(old))
    }
}

pub fn protect_dll(view: winpe::View) -> Result<(), u32> {
    for section in view.section_headers() {
        let chars = section.characteristics();
        let mut protection = MemoryProtection::empty();
        if (chars & winpe::image::SCN_MEM_EXECUTE) != 0 {
            protection = protection | MEMORY_PROTECTION_EXECUTE
        }
        if (chars & winpe::image::SCN_MEM_READ) != 0 {
            protection = protection | MEMORY_PROTECTION_READ
        }
        if (chars & winpe::image::SCN_MEM_WRITE) != 0 {
            protection = protection | MEMORY_PROTECTION_WRITE
        }

        let section = try!(view.section(section).ok_or(0u32));

        unsafe {
            try!(virtual_protect(section.as_ptr(), section.len(), protection));
        }
    }

    Ok(())
}

pub fn resolve_imports(view: winpe::View) -> Result<(), u32> {
    for import in view.imports().unwrap() {
        let import = import.unwrap();
        println!("import: {:?}", import);
        println!("import name: {:?}", view.c_str(import.name()).unwrap());

        for import in view.import_table(&import).unwrap() {
            let import = import.unwrap();
            println!("\timport_table: {:?}", import);
        }
    }

    Ok(())
}

pub fn resolve_relocations(view: winpe::View) -> Result<(), u32> {
    for relocation in view.relocations().unwrap() {
        let relocation = relocation.unwrap();
        println!("reloc: {:?}", relocation);
        view.segment_from(relocation.address).unwrap();

    }

    Ok(())
}

/*pub fn relocate_base(relocation: winpe::Relocation, delta: u64) -> () {
    match relocation.kind {
        winpe::RelocationKind::Absolute => (),
        winpe::RelocationKind::Low => {
            unimplemented!()
        },
        winpe::RelocationKind::High => {
            unimplemented!()
        },
        winpe::RelocationKind::HighAdj => {
            unimplemented!()
        },
        winpe::RelocationKind::HighLow => {
            unimplemented!()
        },
        winpe::RelocationKind::Dir64 => {
            unimplemented!()
        },
        _ => unimplemented!(),
    }
}*/

#[cfg(test)]
mod tests {
    use winpe;
    use super::*;

    #[test]
    #[cfg(windows)]
    fn check_self() {
        use kernel32;
        use std::ptr;

        unsafe {
            let handle = kernel32::GetModuleHandleA(ptr::null_mut());

            assert!(!handle.is_null());
            winpe::View::from_base(handle as _).unwrap();
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_data() {
        let view = view_current_process().unwrap();

        println!("{:#?}", view.nt_headers());
        println!("{:#?}", view.data_directories());

        resolve_imports(view.clone()).unwrap();
        resolve_relocations(view.clone()).unwrap();
    }
}
