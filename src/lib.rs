//#![deny(missing_docs)]
#![doc(html_root_url = "http://arcnmx.github.io/winpe-rs/")]

extern crate pod;
extern crate byteorder_pod;
extern crate result;

pub extern crate winpe_image as image;

mod traits;
mod nt;
mod parse;
mod view;
mod file;

pub use traits::{PeHeaders, PeRead, PeWrite};
pub use parse::{write_pe, RelocationIterator, ImportIterator, ImportTableIterator};
pub use nt::{NtKind, NtHeaders, DirectoryEntry, ImportSymbol, Relocation, RelocationKind};
pub use view::View;
pub use file::File;
