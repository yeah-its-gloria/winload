// SPDX-FileCopyrightText: Copyright 2024 Gloria G.
// SPDX-License-Identifier: BSD-2-Clause

use std::{io, mem, slice};

// Reads any type implementing std::io::Read into a structure of type T.
pub fn read_struct<T, R: io::Read>(read: &mut R) -> io::Result<T> {
    unsafe {
        let mut data = mem::zeroed::<T>();
        let buffer = slice::from_raw_parts_mut(&mut data as *mut T as *mut u8, mem::size_of::<T>());

        match read.read_exact(buffer) {
            Ok(()) => Ok(data),
            Err(e) => { mem::forget(data); Err(e) }
        }
    }
}