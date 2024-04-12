#![no_std]

#[repr(C)]
#[derive(Debug)]
pub struct RenameEvent{
    pub uid: u32,
    pub pid: u32,
    pub o_filename: [u8; 4096],
    pub n_filename: [u8; 4096],
}

