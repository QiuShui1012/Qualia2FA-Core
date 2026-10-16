// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! The import readers, fed arbitrary bytes.
//!
//! An export is the one input that arrives as a **whole file the user picked**, and it is
//! written by another program: a truncated download, a half-copied file or a hostile file from
//! somewhere else all look the same to the reader. What this target checks is that none of them
//! can take the process down.
//!
//! Every format is tried on every input, since the format is chosen by the user or guessed from
//! the content, and a mismatch must be an error rather than a surprise.
//!
//! # Why the leak check is not here
//!
//! "No value from the export reaches a report" is pinned by unit tests that feed a **distinctive**
//! secret and assert the reason does not contain it. Trying to check it here means asking whether
//! a line of the input appears in a reason, and that question has a false positive built in: a
//! line that happens to be a fragment of one of this reader's own messages ("ry could not be read"
//! inside "the entry could not be read") is not a leak, and a target that fails on it teaches the
//! next reader to distrust the check rather than the code.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::import::{self, ImportFormat};

fuzz_target!(|data: &[u8]| {
    // The guess is allowed to answer "I do not know"; it must not panic trying.
    let _ = ImportFormat::detect(data);

    for format in [ImportFormat::Json, ImportFormat::Text, ImportFormat::Html] {
        // A password is offered on every input: an encrypted export that happens to authenticate
        // must be covered too, and one that does not is the ordinary path.
        if let Ok(report) = import::import(data, format, 1_700_000_000, Some(b"test")) {
            assert!(
                report.entries.len() <= import::MAX_ENTRIES,
                "the report holds more entries than the limit allows"
            );
            // A report is also where a reader can disagree with itself: every entry it kept has
            // to carry a position, and the positions have to be distinct, since the interface
            // shows them to the user as "line N".
            let mut positions: Vec<usize> = report.entries.iter().map(|e| e.position).collect();
            positions.sort_unstable();
            let count = positions.len();
            positions.dedup();
            assert_eq!(
                positions.len(),
                count,
                "two imported entries claim the same position"
            );
        }
    }
});
