// SPDX-FileCopyrightText: Copyright 2024 Gloria G.
// SPDX-License-Identifier: BSD-2-Clause

mod format;
mod loader;
mod utilities;

use std::env;

use loader::PELoader;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = if args.len() > 1 { args[1].clone() } else { "test.exe".to_string() };

    let exe = PELoader::new(path).unwrap();

    println!("Machine: {:?}, Subsystem: {:?}", exe.get_machine_type(), exe.get_subsystem());

    for import in exe.get_import_dll_names() {
        println!("Imports: {}", import)
    }
}
