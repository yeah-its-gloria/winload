// SPDX-FileCopyrightText: Copyright 2024 Gloria G.
// SPDX-License-Identifier: BSD-2-Clause

use std::{fs::File, io::{self, Read, Seek}, mem, path::Path, result::Result};

use crate::{format::{COFFHeader, COFFSection, MZHeader, MZPEExtension, PE32OptionalHeader, PEDirectoryImportTable, PEOptionalDirectoryTable, COFF_MAGIC, MZ_MAGIC}, utilities::read_struct};

#[derive(Debug)]
pub enum Component {
    MZHeader,
    COFFHeader,
    PEOptionalHeader
}

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    InvalidMagic(Component),
    MalformedSize(Component),
    Unsupported
}

#[derive(Debug)]
pub enum MachineType {
    Unknown,
    AMD64,
    ARM32,
    ARM64,
    ARM32NT,
    EFI,
    I386,
}

#[derive(Debug)]
pub enum Subsystem {
    Unknown,
    Native,
    GUI,
    Console,
    EFIApplication,
    EFIBootServiceDriver,
    EFIRuntimeDriver,
    EFIImageROM,
}

pub struct PELoader {
    file: File,
    mz_header: MZHeader,
    mz_pe_extension: MZPEExtension,
    coff_header: COFFHeader,
    pe_optional_header: PE32OptionalHeader,
    optional_is_plus: bool,
    data_directory: Vec<PEOptionalDirectoryTable>,
    sections: Vec<COFFSection>,
    import_table: Vec<PEDirectoryImportTable>,
    import_dll_names: Vec<String>
}

impl COFFSection {
    fn resolve(&self, rva: u32) -> Option<u32> {
        if rva >= self.address && rva <= self.address + self.size {
            Some(rva - self.address + self.raw_data_address)
        } else {
            None
        }
    }
}

impl PELoader {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => { return Err(Error::IO(e)); }
        };

        let mz_header = match read_struct::<MZHeader, File>(&mut file) {
            Ok(h) => h,
            Err(e) => { return Err(Error::IO(e)); }
        };

        if mz_header.magic != MZ_MAGIC {
            return Err(Error::InvalidMagic(Component::MZHeader))
        }

        let mz_pe_extension = match read_struct::<MZPEExtension, File>(&mut file) {
            Ok(e) => e,
            Err(e) => { return Err(Error::IO(e)); }
        };

        match file.seek(io::SeekFrom::Start(mz_pe_extension.pe_header_start.into())) {
            Ok(_) => { },
            Err(e) => { return Err(Error::IO(e)); }
        }

        let coff_header = match read_struct::<COFFHeader, File>(&mut file) {
            Ok(h) => h,
            Err(e) => { return Err(Error::IO(e)); }
        };

        if coff_header.magic != COFF_MAGIC {
            return Err(Error::InvalidMagic(Component::COFFHeader))
        }

        if (coff_header.optional_header_size as usize) < mem::size_of::<PE32OptionalHeader>() || (coff_header.optional_header_size as usize) > 240 {
            return Err(Error::Unsupported)
        }

        let pe_optional_header = match read_struct::<PE32OptionalHeader, File>(&mut file) {
            Ok(h) => h,
            Err(e) => { return Err(Error::IO(e)); } 
        };

        let optional_is_plus = match pe_optional_header.magic {
            pe_optional_32_magic => false,
            pe_optional_32_plus_magic => true,

            _ => { return Err(Error::InvalidMagic(Component::PEOptionalHeader)); }
        };

        if optional_is_plus {
            panic!("PE32+ unimplemented") // TODO: implement PE32+
        }

        if coff_header.optional_header_size as usize - pe_optional_header.directory_count as usize * mem::size_of::<PEOptionalDirectoryTable>() != mem::size_of::<PE32OptionalHeader>() {
            return Err(Error::MalformedSize(Component::PEOptionalHeader))
        }

        let mut data_directory = Vec::<PEOptionalDirectoryTable>::with_capacity(pe_optional_header.directory_count as usize);
        for _ in 0 .. pe_optional_header.directory_count {
            let entry = read_struct::<PEOptionalDirectoryTable, File>(&mut file).unwrap(); // TODO: handle errors gracefully

            // ...

            data_directory.push(entry);
        }

        let mut sections = Vec::<COFFSection>::with_capacity(coff_header.section_count as usize);
        for _ in 0 .. coff_header.section_count {
            let entry = read_struct::<COFFSection, File>(&mut file).unwrap(); // TODO: handle errors gracefully

            // ...

            sections.push(entry);
        }

        let mut address: Option<u32> = None;
        for section in &sections {
            address = section.resolve(data_directory[1].address);
            if address.is_some() {
                break
            }
        }

        file.seek(io::SeekFrom::Start(address.unwrap() as u64)).unwrap();

        let mut import_table = Vec::<PEDirectoryImportTable>::with_capacity(data_directory[1].size as usize / mem::size_of::<PEDirectoryImportTable>());
        for _ in 0 .. data_directory[1].size as usize / mem::size_of::<PEDirectoryImportTable>() {
            let entry = read_struct::<PEDirectoryImportTable, File>(&mut file).unwrap();
            if entry.lookup_address == 0 {
                continue;
            }

            import_table.push(entry);
        }

        let mut import_dll_names = Vec::<String>::new();
        for import in &import_table {
            address = None;
            for section in &sections {
                address = section.resolve(import.name_address);
                if address.is_some() {
                    break
                }
            }

            file.seek(io::SeekFrom::Start(address.unwrap() as u64)).unwrap();

            let mut buf = vec![0u8; 32];
            file.read_exact(&mut buf).unwrap();

            buf.truncate(buf.iter().position(|v| *v == 0x00).unwrap_or(buf.len()));

            let name = String::from_utf8(buf).unwrap();
            import_dll_names.push(name);
        }

        Ok(PELoader { file, mz_header, mz_pe_extension, coff_header, pe_optional_header, optional_is_plus, data_directory, sections, import_table, import_dll_names })
    }

    pub fn get_machine_type(&self) -> MachineType {
        match self.coff_header.machine {
            0x0000 => MachineType::Unknown,

            0x014c => MachineType::I386,
            0x8664 => MachineType::AMD64,

            0x01c0 => MachineType::ARM32,
            0x01c4 => MachineType::ARM32NT,
            0xaa64 => MachineType::ARM64,
            
            0x0ebc => MachineType::EFI,

            u => panic!("Unknown machine type {}", u)
        }
    }

    pub fn get_subsystem(&self) -> Subsystem {
        match self.pe_optional_header.subsystem {
            0 => Subsystem::Unknown,

            1 => Subsystem::Native,
            2 => Subsystem::GUI,
            3 => Subsystem::Console,

            10 => Subsystem::EFIApplication,
            11 => Subsystem::EFIBootServiceDriver,
            12 => Subsystem::EFIRuntimeDriver,
            13 => Subsystem::EFIImageROM,

            u => panic!("Unknown subsystem {}", u)
        }
    }

    pub fn get_import_dll_names(&self) -> Vec<String> {
        self.import_dll_names.clone()
    }
}
