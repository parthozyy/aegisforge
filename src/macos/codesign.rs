use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use crate::macos::command::SystemCommandRunner;
use crate::macos::command::{NativeCommandError, NativeCommandOutput, NativeCommandRunner};
use crate::macos::entitlements::{EntitlementEntry, EntitlementSource};
use crate::scanner::result::{DiagnosticKind, ScanDiagnostic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodeSignatureTargetKind {
    MachOFile,
    ApplicationBundle,
}

#[cfg(test)]
mod architecture_tests {
    use std::cell::RefCell;
    #[cfg(unix)]
    use std::fs::{self, File, OpenOptions};
    use std::io;
    #[cfg(unix)]
    use std::io::{Seek, SeekFrom};
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum ByteOrder {
        Big,
        Little,
    }

    impl ByteOrder {
        fn write_i32(self, destination: &mut [u8], value: i32) {
            destination.copy_from_slice(&match self {
                Self::Big => value.to_be_bytes(),
                Self::Little => value.to_le_bytes(),
            });
        }

        fn write_u32(self, destination: &mut [u8], value: u32) {
            destination.copy_from_slice(&match self {
                Self::Big => value.to_be_bytes(),
                Self::Little => value.to_le_bytes(),
            });
        }

        fn write_u64(self, destination: &mut [u8], value: u64) {
            destination.copy_from_slice(&match self {
                Self::Big => value.to_be_bytes(),
                Self::Little => value.to_le_bytes(),
            });
        }
    }

    fn thin_header(is_64: bool, order: ByteOrder, cpu_type: i32, cpu_subtype: i32) -> Vec<u8> {
        let header_len = if is_64 { 32 } else { 28 };
        let magic = match (is_64, order) {
            (false, ByteOrder::Big) => [0xfe, 0xed, 0xfa, 0xce],
            (false, ByteOrder::Little) => [0xce, 0xfa, 0xed, 0xfe],
            (true, ByteOrder::Big) => [0xfe, 0xed, 0xfa, 0xcf],
            (true, ByteOrder::Little) => [0xcf, 0xfa, 0xed, 0xfe],
        };
        let mut bytes = vec![0_u8; header_len];
        bytes[..4].copy_from_slice(&magic);
        order.write_i32(&mut bytes[4..8], cpu_type);
        order.write_i32(&mut bytes[8..12], cpu_subtype);
        bytes
    }

    fn fat_magic(is_64: bool, order: ByteOrder) -> [u8; 4] {
        match (is_64, order) {
            (false, ByteOrder::Big) => [0xca, 0xfe, 0xba, 0xbe],
            (false, ByteOrder::Little) => [0xbe, 0xba, 0xfe, 0xca],
            (true, ByteOrder::Big) => [0xca, 0xfe, 0xba, 0xbf],
            (true, ByteOrder::Little) => [0xbf, 0xba, 0xfe, 0xca],
        }
    }

    #[derive(Clone)]
    struct FatFixtureEntry {
        cpu_type: i32,
        cpu_subtype: i32,
        offset: u64,
        size: u64,
        align: u32,
        reserved: u32,
        inner: Vec<u8>,
    }

    fn fat_file(is_64: bool, order: ByteOrder, entries: &[FatFixtureEntry]) -> Vec<u8> {
        let entry_size = if is_64 { 32 } else { 20 };
        let table_end = 8 + entry_size * entries.len();
        let file_len = entries.iter().fold(table_end, |current, entry| {
            let end = usize::try_from(entry.offset)
                .expect("fixture offset fits usize")
                .checked_add(entry.inner.len())
                .expect("fixture range fits usize");
            current.max(end)
        });
        let mut bytes = vec![0_u8; file_len];
        bytes[..4].copy_from_slice(&fat_magic(is_64, order));
        order.write_u32(
            &mut bytes[4..8],
            u32::try_from(entries.len()).expect("fixture entry count fits u32"),
        );

        for (index, entry) in entries.iter().enumerate() {
            let start = 8 + index * entry_size;
            order.write_i32(&mut bytes[start..start + 4], entry.cpu_type);
            order.write_i32(&mut bytes[start + 4..start + 8], entry.cpu_subtype);
            if is_64 {
                order.write_u64(&mut bytes[start + 8..start + 16], entry.offset);
                order.write_u64(&mut bytes[start + 16..start + 24], entry.size);
                order.write_u32(&mut bytes[start + 24..start + 28], entry.align);
                order.write_u32(&mut bytes[start + 28..start + 32], entry.reserved);
            } else {
                order.write_u32(
                    &mut bytes[start + 8..start + 12],
                    u32::try_from(entry.offset).expect("fat32 fixture offset fits u32"),
                );
                order.write_u32(
                    &mut bytes[start + 12..start + 16],
                    u32::try_from(entry.size).expect("fat32 fixture size fits u32"),
                );
                order.write_u32(&mut bytes[start + 16..start + 20], entry.align);
            }

            let inner_start = usize::try_from(entry.offset).expect("fixture offset fits usize");
            let inner_end = inner_start + entry.inner.len();
            bytes[inner_start..inner_end].copy_from_slice(&entry.inner);
        }

        bytes
    }

    fn fat_header_only(is_64: bool, order: ByteOrder, count: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; 8];
        bytes[..4].copy_from_slice(&fat_magic(is_64, order));
        order.write_u32(&mut bytes[4..8], count);
        bytes
    }

    struct ByteReader {
        bytes: Vec<u8>,
        reads: RefCell<Vec<(u64, usize)>>,
    }

    impl ByteReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                reads: RefCell::new(Vec::new()),
            }
        }
    }

    impl PositionalRead for ByteReader {
        fn file_len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
            self.reads.borrow_mut().push((offset, destination.len()));
            let start = usize::try_from(offset)
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "offset"))?;
            let end = start
                .checked_add(destination.len())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "range"))?;
            let source = self
                .bytes
                .get(start..end)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "range"))?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct SparseReader {
        len: u64,
        segments: Vec<(u64, Vec<u8>)>,
        reads: RefCell<Vec<(u64, usize)>>,
    }

    impl SparseReader {
        fn new(len: u64, segments: Vec<(u64, Vec<u8>)>) -> Self {
            Self {
                len,
                segments,
                reads: RefCell::new(Vec::new()),
            }
        }
    }

    impl PositionalRead for SparseReader {
        fn file_len(&self) -> io::Result<u64> {
            Ok(self.len)
        }

        fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
            self.reads.borrow_mut().push((offset, destination.len()));
            let requested_end = offset
                .checked_add(destination.len() as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "range"))?;
            for (segment_offset, segment) in &self.segments {
                let segment_end = segment_offset + segment.len() as u64;
                if offset >= *segment_offset && requested_end <= segment_end {
                    let start = usize::try_from(offset - segment_offset).expect("relative offset");
                    destination.copy_from_slice(&segment[start..start + destination.len()]);
                    return Ok(());
                }
            }
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "sparse range"))
        }
    }

    fn selection_tuples(selection: &MachOArchitectureSelection) -> Vec<(i32, i32)> {
        selection
            .available
            .iter()
            .map(|architecture| (architecture.cpu_type, architecture.cpu_subtype))
            .collect()
    }

    #[test]
    fn thin_big_endian_32_architecture_is_selected_from_positional_bytes() {
        let reader = ByteReader::new(thin_header(false, ByteOrder::Big, 7, 3));

        let selection = parse_macho_architectures(&reader).expect("thin Mach-O should parse");

        assert_eq!(selection.available.len(), 1);
        assert_eq!(selection.selected.cpu_type, 7);
        assert_eq!(selection.selected.cpu_subtype, 3);
        assert_eq!(*reader.reads.borrow(), vec![(0, 4), (0, 28)]);
    }

    #[test]
    fn all_thin_magic_and_byte_order_forms_preserve_raw_signed_selectors() {
        let cases = [
            (false, ByteOrder::Big, 7, -3, 28),
            (false, ByteOrder::Little, -7, 0x1020_3040, 28),
            (true, ByteOrder::Big, i32::MIN, i32::MAX, 32),
            (true, ByteOrder::Little, 0x0102_0304, -0x0102_0304, 32),
        ];

        for (is_64, order, cpu_type, cpu_subtype, header_len) in cases {
            let reader = ByteReader::new(thin_header(is_64, order, cpu_type, cpu_subtype));
            let selection = parse_macho_architectures(&reader).expect("thin form should parse");
            assert_eq!(selection_tuples(&selection), vec![(cpu_type, cpu_subtype)]);
            assert_eq!(
                selection.selected.codesign_selector(),
                format!("{cpu_type},{cpu_subtype}")
            );
            assert_eq!(*reader.reads.borrow(), vec![(0, 4), (0, header_len)]);
        }
    }

    #[test]
    fn all_fat_magic_forms_accept_independent_inner_orders_and_widths() {
        let cases = [
            (false, ByteOrder::Big, true, ByteOrder::Little, 28_u64),
            (false, ByteOrder::Little, false, ByteOrder::Big, 28_u64),
            (true, ByteOrder::Big, false, ByteOrder::Little, 40_u64),
            (true, ByteOrder::Little, true, ByteOrder::Big, 40_u64),
        ];

        for (fat64, outer_order, thin64, inner_order, offset) in cases {
            let inner = thin_header(thin64, inner_order, -7, i32::MIN);
            let entry = FatFixtureEntry {
                cpu_type: -7,
                cpu_subtype: i32::MIN,
                offset,
                size: inner.len() as u64,
                align: 0,
                reserved: 0,
                inner,
            };
            let selection =
                parse_macho_architectures(&ByteReader::new(fat_file(fat64, outer_order, &[entry])))
                    .expect("fat form should parse");
            assert_eq!(selection_tuples(&selection), vec![(-7, i32::MIN)]);
        }
    }

    #[test]
    fn fat_entry_count_is_bounded_before_any_table_read() {
        for count in [0, 33, u32::MAX] {
            let reader = ByteReader::new(fat_header_only(false, ByteOrder::Big, count));
            assert!(parse_macho_architectures(&reader).is_err());
            assert_eq!(*reader.reads.borrow(), vec![(0, 4), (4, 4)]);
        }
    }

    #[test]
    fn one_and_thirty_two_fat_entries_parse_with_deterministic_signed_sorting() {
        let one_inner = thin_header(false, ByteOrder::Big, 7, 3);
        let one = FatFixtureEntry {
            cpu_type: 7,
            cpu_subtype: 3,
            offset: 28,
            size: 28,
            align: 0,
            reserved: 0,
            inner: one_inner,
        };
        let one_selection =
            parse_macho_architectures(&ByteReader::new(fat_file(false, ByteOrder::Big, &[one])))
                .expect("one-entry fat should parse");
        assert_eq!(one_selection.available.len(), 1);
        assert_eq!(
            one_selection.native_fact_scope(),
            NativeFactScope::SingleArchitecture
        );

        let table_end = 8 + 20 * 32;
        let entries = (0..32)
            .map(|index| {
                let cpu_type = index - 16;
                let cpu_subtype = 31 - index;
                FatFixtureEntry {
                    cpu_type,
                    cpu_subtype,
                    offset: (table_end + index as usize * 28) as u64,
                    size: 28,
                    align: 0,
                    reserved: 0,
                    inner: thin_header(false, ByteOrder::Little, cpu_type, cpu_subtype),
                }
            })
            .rev()
            .collect::<Vec<_>>();
        let selection = parse_macho_architectures(&ByteReader::new(fat_file(
            false,
            ByteOrder::Little,
            &entries,
        )))
        .expect("32-entry fat should parse");
        assert_eq!(selection.available.len(), 32);
        assert_eq!(
            selection.native_fact_scope(),
            NativeFactScope::SelectedArchitecture
        );
        assert_eq!(selection.selected.cpu_type, -16);
        assert!(selection.available.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn duplicate_raw_selectors_are_rejected_but_capability_variants_are_distinct() {
        let table_end = 48_u64;
        let duplicate = [
            FatFixtureEntry {
                cpu_type: 7,
                cpu_subtype: 3,
                offset: table_end,
                size: 28,
                align: 0,
                reserved: 0,
                inner: thin_header(false, ByteOrder::Big, 7, 3),
            },
            FatFixtureEntry {
                cpu_type: 7,
                cpu_subtype: 3,
                offset: table_end + 28,
                size: 28,
                align: 0,
                reserved: 0,
                inner: thin_header(false, ByteOrder::Big, 7, 3),
            },
        ];
        assert!(
            parse_macho_architectures(&ByteReader::new(fat_file(
                false,
                ByteOrder::Big,
                &duplicate,
            )))
            .is_err()
        );

        let capability = (0x8000_0000_u32 | 3) as i32;
        let distinct = [
            duplicate[0].clone(),
            FatFixtureEntry {
                cpu_subtype: capability,
                offset: table_end + 28,
                inner: thin_header(false, ByteOrder::Little, 7, capability),
                ..duplicate[1].clone()
            },
        ];
        let selection =
            parse_macho_architectures(&ByteReader::new(fat_file(false, ByteOrder::Big, &distinct)))
                .expect("capability-bit variant is a distinct raw selector");
        assert_eq!(selection_tuples(&selection), vec![(7, capability), (7, 3)]);
    }

    #[test]
    fn fat_slice_ranges_are_checked_and_half_open_adjacency_is_valid() {
        let valid_entries = [
            FatFixtureEntry {
                cpu_type: 7,
                cpu_subtype: 3,
                offset: 48,
                size: 28,
                align: 0,
                reserved: 0,
                inner: thin_header(false, ByteOrder::Big, 7, 3),
            },
            FatFixtureEntry {
                cpu_type: 12,
                cpu_subtype: 0,
                offset: 76,
                size: 32,
                align: 0,
                reserved: 0,
                inner: thin_header(true, ByteOrder::Little, 12, 0),
            },
        ];
        assert!(
            parse_macho_architectures(&ByteReader::new(fat_file(
                false,
                ByteOrder::Big,
                &valid_entries,
            )))
            .is_ok()
        );

        let invalid_ranges = [
            FatFixtureEntry {
                size: 0,
                ..valid_entries[0].clone()
            },
            FatFixtureEntry {
                size: 3,
                inner: vec![0; 3],
                ..valid_entries[0].clone()
            },
            FatFixtureEntry {
                offset: 27,
                ..valid_entries[0].clone()
            },
            FatFixtureEntry {
                size: 29,
                ..valid_entries[0].clone()
            },
        ];
        for invalid in invalid_ranges {
            assert!(
                parse_macho_architectures(&ByteReader::new(fat_file(
                    false,
                    ByteOrder::Big,
                    &[invalid],
                )))
                .is_err()
            );
        }

        let mut overlapping = valid_entries.clone();
        overlapping[1].offset = 75;
        assert!(
            parse_macho_architectures(&ByteReader::new(fat_file(
                false,
                ByteOrder::Big,
                &overlapping,
            )))
            .is_err()
        );
    }

    #[test]
    fn fat_alignment_and_fat64_reserved_are_strict() {
        let inner = thin_header(false, ByteOrder::Big, 7, 3);
        let base = FatFixtureEntry {
            cpu_type: 7,
            cpu_subtype: 3,
            offset: 40,
            size: 28,
            align: 0,
            reserved: 0,
            inner,
        };
        assert!(
            parse_macho_architectures(&ByteReader::new(fat_file(
                true,
                ByteOrder::Big,
                std::slice::from_ref(&base),
            )))
            .is_ok()
        );

        for invalid in [
            FatFixtureEntry {
                align: 3,
                offset: 41,
                ..base.clone()
            },
            FatFixtureEntry {
                align: 64,
                ..base.clone()
            },
            FatFixtureEntry {
                align: u32::MAX,
                ..base.clone()
            },
            FatFixtureEntry {
                reserved: 1,
                ..base.clone()
            },
        ] {
            assert!(
                parse_macho_architectures(&ByteReader::new(fat_file(
                    true,
                    ByteOrder::Little,
                    &[invalid],
                )))
                .is_err()
            );
        }
    }

    #[test]
    fn fat_inner_headers_are_confined_and_bound_to_exact_raw_outer_selectors() {
        let base = FatFixtureEntry {
            cpu_type: 7,
            cpu_subtype: (0x8000_0000_u32 | 3) as i32,
            offset: 40,
            size: 32,
            align: 0,
            reserved: 0,
            inner: thin_header(true, ByteOrder::Little, 7, (0x8000_0000_u32 | 3) as i32),
        };

        for invalid in [
            FatFixtureEntry {
                inner: vec![0_u8; 32],
                ..base.clone()
            },
            FatFixtureEntry {
                inner: fat_header_only(false, ByteOrder::Big, 1),
                size: 8,
                ..base.clone()
            },
            FatFixtureEntry {
                size: 31,
                inner: base.inner[..31].to_vec(),
                ..base.clone()
            },
            FatFixtureEntry {
                inner: thin_header(true, ByteOrder::Little, 8, base.cpu_subtype),
                ..base.clone()
            },
            FatFixtureEntry {
                inner: thin_header(true, ByteOrder::Little, 7, 3),
                ..base.clone()
            },
        ] {
            assert!(
                parse_macho_architectures(&ByteReader::new(fat_file(
                    true,
                    ByteOrder::Big,
                    &[invalid],
                )))
                .is_err()
            );
        }
    }

    #[test]
    fn parser_reads_only_outer_table_and_fixed_inner_headers() {
        let entries = [
            FatFixtureEntry {
                cpu_type: 7,
                cpu_subtype: 3,
                offset: 48,
                size: 28,
                align: 0,
                reserved: 0,
                inner: thin_header(false, ByteOrder::Big, 7, 3),
            },
            FatFixtureEntry {
                cpu_type: 12,
                cpu_subtype: 0,
                offset: 76,
                size: 32,
                align: 0,
                reserved: 0,
                inner: thin_header(true, ByteOrder::Little, 12, 0),
            },
        ];
        let reader = ByteReader::new(fat_file(false, ByteOrder::Big, &entries));
        parse_macho_architectures(&reader).expect("adjacent exact-size slices should parse");

        assert_eq!(
            *reader.reads.borrow(),
            vec![
                (0, 4),
                (4, 4),
                (8, 40),
                (48, 4),
                (48, 28),
                (76, 4),
                (76, 32)
            ]
        );
    }

    #[test]
    fn truncated_and_unknown_inputs_fail_before_any_out_of_range_read() {
        let shorter_than_magic = ByteReader::new(vec![0xfe, 0xed, 0xfa]);
        assert!(parse_macho_architectures(&shorter_than_magic).is_err());
        assert!(shorter_than_magic.reads.borrow().is_empty());

        let unknown = ByteReader::new(vec![0, 1, 2, 3]);
        assert!(parse_macho_architectures(&unknown).is_err());
        assert_eq!(*unknown.reads.borrow(), vec![(0, 4)]);

        let mut short_thin64 = thin_header(true, ByteOrder::Big, 7, 3);
        short_thin64.pop();
        let short_thin64 = ByteReader::new(short_thin64);
        assert!(parse_macho_architectures(&short_thin64).is_err());
        assert_eq!(*short_thin64.reads.borrow(), vec![(0, 4)]);

        let short_table = ByteReader::new(fat_header_only(false, ByteOrder::Big, 1));
        assert!(parse_macho_architectures(&short_table).is_err());
        assert_eq!(*short_table.reads.borrow(), vec![(0, 4), (4, 4)]);

        let full_inner = thin_header(true, ByteOrder::Little, 12, 0);
        let short_slice = FatFixtureEntry {
            cpu_type: 12,
            cpu_subtype: 0,
            offset: 40,
            size: 31,
            align: 0,
            reserved: 0,
            inner: full_inner[..31].to_vec(),
        };
        let reader = ByteReader::new(fat_file(true, ByteOrder::Big, &[short_slice]));
        assert!(parse_macho_architectures(&reader).is_err());
        assert_eq!(
            *reader.reads.borrow(),
            vec![(0, 4), (4, 4), (8, 32), (40, 4)]
        );
    }

    #[test]
    fn sparse_fat64_ranges_use_checked_u64_arithmetic_and_alignment() {
        let high_offset = 1_u64 << 63;
        let inner = thin_header(false, ByteOrder::Big, 7, 3);
        let entry = FatFixtureEntry {
            cpu_type: 7,
            cpu_subtype: 3,
            offset: high_offset,
            size: 28,
            align: 63,
            reserved: 0,
            inner: inner.clone(),
        };
        let table = fat_file(
            true,
            ByteOrder::Big,
            &[FatFixtureEntry {
                offset: 40,
                inner: Vec::new(),
                ..entry.clone()
            }],
        );
        let table = table[..40].to_vec();
        let mut table = table;
        ByteOrder::Big.write_u64(&mut table[16..24], high_offset);
        let reader = SparseReader::new(high_offset + 28, vec![(0, table), (high_offset, inner)]);
        assert!(parse_macho_architectures(&reader).is_ok());

        let overflow_offset = u64::MAX - 10;
        let mut overflow_table = fat_header_only(true, ByteOrder::Big, 1);
        overflow_table.resize(40, 0);
        ByteOrder::Big.write_i32(&mut overflow_table[8..12], 7);
        ByteOrder::Big.write_i32(&mut overflow_table[12..16], 3);
        ByteOrder::Big.write_u64(&mut overflow_table[16..24], overflow_offset);
        ByteOrder::Big.write_u64(&mut overflow_table[24..32], 28);
        let overflow_reader = SparseReader::new(u64::MAX, vec![(0, overflow_table)]);
        assert!(parse_macho_architectures(&overflow_reader).is_err());
        assert_eq!(
            *overflow_reader.reads.borrow(),
            vec![(0, 4), (4, 4), (8, 32)]
        );
    }

    #[cfg(unix)]
    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    struct TestDirectory(PathBuf);

    #[cfg(unix)]
    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aegisforge-architecture-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory should be created");
            Self(path)
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_file_handle_ignores_path_replacement_and_preserves_cursor() {
        use std::os::unix::fs::OpenOptionsExt;

        let directory = TestDirectory::new();
        let target = directory.0.join("target");
        let moved = directory.0.join("original");
        fs::write(&target, thin_header(false, ByteOrder::Big, 7, 3))
            .expect("original should be written");
        let mut retained = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&target)
            .expect("original should open without following links");
        retained
            .seek(SeekFrom::Start(10))
            .expect("cursor should advance");
        fs::rename(&target, &moved).expect("original should move");
        fs::write(&target, thin_header(false, ByteOrder::Little, 12, 0))
            .expect("replacement should be written");

        let retained_selection =
            parse_macho_architectures(&retained).expect("retained handle should parse");
        let replacement = File::open(&target).expect("replacement should open");
        let replacement_selection =
            parse_macho_architectures(&replacement).expect("replacement should parse");

        assert_eq!(selection_tuples(&retained_selection), vec![(7, 3)]);
        assert_eq!(selection_tuples(&replacement_selection), vec![(12, 0)]);
        assert_eq!(
            retained
                .stream_position()
                .expect("cursor should be readable"),
            10
        );
    }
}

impl CodeSignatureTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachOFile => "MACH_O_FILE",
            Self::ApplicationBundle => "APPLICATION_BUNDLE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePresence {
    Signed,
    Unsigned,
    Unknown,
}

impl SignaturePresence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "SIGNED",
            Self::Unsigned => "UNSIGNED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCheckStatus {
    Passed,
    Failed,
    NotApplicable,
    Unavailable,
    Error,
}

impl NativeCheckStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Unavailable => "UNAVAILABLE",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    AdHoc,
    CertificateBacked,
    Unknown,
}

impl SignatureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdHoc => "AD_HOC",
            Self::CertificateBacked => "CERTIFICATE_BACKED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFactScope {
    #[cfg_attr(not(test), allow(dead_code))]
    AllArchitectures,
    #[cfg_attr(not(test), allow(dead_code))]
    SingleArchitecture,
    #[cfg_attr(not(test), allow(dead_code))]
    SelectedArchitecture,
    Unknown,
}

#[cfg_attr(not(test), allow(dead_code))]
impl NativeFactScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllArchitectures => "ALL_ARCHITECTURES",
            Self::SingleArchitecture => "SINGLE_ARCHITECTURE",
            Self::SelectedArchitecture => "SELECTED_ARCHITECTURE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodeSignatureArchitecture {
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    #[cfg_attr(not(test), allow(dead_code))]
    pub display_label: String,
}

impl PartialEq for CodeSignatureArchitecture {
    fn eq(&self, other: &Self) -> bool {
        (self.cpu_type, self.cpu_subtype) == (other.cpu_type, other.cpu_subtype)
    }
}

impl Eq for CodeSignatureArchitecture {}

impl PartialOrd for CodeSignatureArchitecture {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CodeSignatureArchitecture {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.cpu_type, self.cpu_subtype).cmp(&(other.cpu_type, other.cpu_subtype))
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl CodeSignatureArchitecture {
    pub fn new(cpu_type: i32, cpu_subtype: i32) -> Self {
        use goblin::mach::constants::cputype::{CPU_SUBTYPE_MASK, get_arch_name_from_types};

        let lookup_subtype = (cpu_subtype as u32) & !CPU_SUBTYPE_MASK;
        let display_label = get_arch_name_from_types(cpu_type as u32, lookup_subtype)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("cpu_type={cpu_type},cpu_subtype={cpu_subtype}"));

        Self {
            cpu_type,
            cpu_subtype,
            display_label,
        }
    }

    pub fn codesign_selector(&self) -> String {
        format!("{},{}", self.cpu_type, self.cpu_subtype)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
trait PositionalRead {
    fn file_len(&self) -> io::Result<u64>;
    fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()>;
}

#[cfg(unix)]
impl PositionalRead for std::fs::File {
    fn file_len(&self) -> io::Result<u64> {
        self.metadata().map(|metadata| metadata.len())
    }

    fn read_exact_at(&self, offset: u64, destination: &mut [u8]) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, destination, offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
struct MachOArchitectureSelection {
    selected: CodeSignatureArchitecture,
    available: Vec<CodeSignatureArchitecture>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl MachOArchitectureSelection {
    fn native_fact_scope(&self) -> NativeFactScope {
        if self.available.len() == 1 {
            NativeFactScope::SingleArchitecture
        } else {
            NativeFactScope::SelectedArchitecture
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MachOByteOrder {
    Big,
    Little,
}

impl MachOByteOrder {
    fn i32(self, bytes: &[u8]) -> i32 {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Big => i32::from_be_bytes(bytes),
            Self::Little => i32::from_le_bytes(bytes),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Big => u32::from_be_bytes(bytes),
            Self::Little => u32::from_le_bytes(bytes),
        }
    }

    fn u64(self, bytes: &[u8]) -> u64 {
        let bytes = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        match self {
            Self::Big => u64::from_be_bytes(bytes),
            Self::Little => u64::from_le_bytes(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MachOContainer {
    Thin {
        order: MachOByteOrder,
        header_len: usize,
    },
    Fat {
        order: MachOByteOrder,
        entry_len: usize,
    },
}

fn classify_macho_magic(magic: [u8; 4]) -> Option<MachOContainer> {
    match magic {
        [0xfe, 0xed, 0xfa, 0xce] => Some(MachOContainer::Thin {
            order: MachOByteOrder::Big,
            header_len: 28,
        }),
        [0xce, 0xfa, 0xed, 0xfe] => Some(MachOContainer::Thin {
            order: MachOByteOrder::Little,
            header_len: 28,
        }),
        [0xfe, 0xed, 0xfa, 0xcf] => Some(MachOContainer::Thin {
            order: MachOByteOrder::Big,
            header_len: 32,
        }),
        [0xcf, 0xfa, 0xed, 0xfe] => Some(MachOContainer::Thin {
            order: MachOByteOrder::Little,
            header_len: 32,
        }),
        [0xca, 0xfe, 0xba, 0xbe] => Some(MachOContainer::Fat {
            order: MachOByteOrder::Big,
            entry_len: 20,
        }),
        [0xbe, 0xba, 0xfe, 0xca] => Some(MachOContainer::Fat {
            order: MachOByteOrder::Little,
            entry_len: 20,
        }),
        [0xca, 0xfe, 0xba, 0xbf] => Some(MachOContainer::Fat {
            order: MachOByteOrder::Big,
            entry_len: 32,
        }),
        [0xbf, 0xba, 0xfe, 0xca] => Some(MachOContainer::Fat {
            order: MachOByteOrder::Little,
            entry_len: 32,
        }),
        _ => None,
    }
}

fn read_macho_range<R: PositionalRead>(
    reader: &R,
    file_len: u64,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), String> {
    let length = u64::try_from(destination.len())
        .map_err(|_| "Mach-O read length is not representable".to_string())?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "Mach-O read range overflowed".to_string())?;
    if end > file_len {
        return Err("Mach-O read range extends beyond the retained file".to_string());
    }
    reader
        .read_exact_at(offset, destination)
        .map_err(|error| format!("failed to read retained Mach-O bytes: {error}"))
}

#[derive(Debug, Clone, Copy)]
struct FatArchitectureEntry {
    cpu_type: i32,
    cpu_subtype: i32,
    offset: u64,
    size: u64,
    end: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_macho_architectures<R: PositionalRead>(
    reader: &R,
) -> Result<MachOArchitectureSelection, String> {
    let file_len = reader
        .file_len()
        .map_err(|error| format!("failed to inspect retained Mach-O length: {error}"))?;
    let mut magic = [0_u8; 4];
    read_macho_range(reader, file_len, 0, &mut magic)?;
    let container = classify_macho_magic(magic)
        .ok_or_else(|| "retained file does not have a supported Mach-O magic".to_string())?;

    match container {
        MachOContainer::Thin { order, header_len } => {
            let mut header = [0_u8; 32];
            read_macho_range(reader, file_len, 0, &mut header[..header_len])?;
            let architecture =
                CodeSignatureArchitecture::new(order.i32(&header[4..8]), order.i32(&header[8..12]));
            Ok(MachOArchitectureSelection {
                selected: architecture.clone(),
                available: vec![architecture],
            })
        }
        MachOContainer::Fat { order, entry_len } => {
            parse_fat_macho_architectures(reader, file_len, order, entry_len)
        }
    }
}

fn parse_fat_macho_architectures<R: PositionalRead>(
    reader: &R,
    file_len: u64,
    order: MachOByteOrder,
    entry_len: usize,
) -> Result<MachOArchitectureSelection, String> {
    const MAX_ARCHITECTURES: usize = 32;
    const MAX_TABLE_BYTES: usize = MAX_ARCHITECTURES * 32;

    let mut count_bytes = [0_u8; 4];
    read_macho_range(reader, file_len, 4, &mut count_bytes)?;
    let count = usize::try_from(order.u32(&count_bytes))
        .map_err(|_| "fat Mach-O architecture count is not representable".to_string())?;
    if !(1..=MAX_ARCHITECTURES).contains(&count) {
        return Err(format!(
            "fat Mach-O architecture count must be in 1..={MAX_ARCHITECTURES}"
        ));
    }

    let table_bytes = entry_len
        .checked_mul(count)
        .ok_or_else(|| "fat Mach-O table length overflowed".to_string())?;
    let table_end = 8_u64
        .checked_add(
            u64::try_from(table_bytes)
                .map_err(|_| "fat Mach-O table length is not representable".to_string())?,
        )
        .ok_or_else(|| "fat Mach-O table range overflowed".to_string())?;
    if table_end > file_len {
        return Err("fat Mach-O table extends beyond the retained file".to_string());
    }

    let mut table = [0_u8; MAX_TABLE_BYTES];
    read_macho_range(reader, file_len, 8, &mut table[..table_bytes])?;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * entry_len;
        let encoded = &table[start..start + entry_len];
        let cpu_type = order.i32(&encoded[0..4]);
        let cpu_subtype = order.i32(&encoded[4..8]);
        let (offset, size, align) = if entry_len == 20 {
            (
                u64::from(order.u32(&encoded[8..12])),
                u64::from(order.u32(&encoded[12..16])),
                order.u32(&encoded[16..20]),
            )
        } else {
            let reserved = order.u32(&encoded[28..32]);
            if reserved != 0 {
                return Err("fat64 Mach-O architecture has a nonzero reserved field".to_string());
            }
            (
                order.u64(&encoded[8..16]),
                order.u64(&encoded[16..24]),
                order.u32(&encoded[24..28]),
            )
        };

        if size == 0 {
            return Err("fat Mach-O architecture slice is empty".to_string());
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "fat Mach-O architecture range overflowed".to_string())?;
        if offset < table_end {
            return Err("fat Mach-O architecture overlaps its table".to_string());
        }
        if end > file_len {
            return Err("fat Mach-O architecture extends beyond the retained file".to_string());
        }
        let alignment = 1_u64
            .checked_shl(align)
            .ok_or_else(|| "fat Mach-O architecture alignment is invalid".to_string())?;
        if offset % alignment != 0 {
            return Err("fat Mach-O architecture offset is misaligned".to_string());
        }

        entries.push(FatArchitectureEntry {
            cpu_type,
            cpu_subtype,
            offset,
            size,
            end,
        });
    }

    let mut ranges = entries
        .iter()
        .map(|entry| (entry.offset, entry.end))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    if ranges.windows(2).any(|range| range[1].0 < range[0].1) {
        return Err("fat Mach-O architecture slices overlap".to_string());
    }

    let mut selectors = BTreeSet::new();
    let mut architectures = Vec::with_capacity(count);
    for entry in entries {
        if entry.size < 4 {
            return Err("fat Mach-O architecture is too small for a magic".to_string());
        }
        let mut inner_magic = [0_u8; 4];
        read_macho_range(reader, file_len, entry.offset, &mut inner_magic)?;
        let (inner_order, inner_header_len) = match classify_macho_magic(inner_magic) {
            Some(MachOContainer::Thin { order, header_len }) => (order, header_len),
            _ => return Err("fat Mach-O entry does not contain a thin Mach-O".to_string()),
        };
        if entry.size
            < u64::try_from(inner_header_len)
                .map_err(|_| "Mach-O header length is not representable".to_string())?
        {
            return Err("fat Mach-O slice is smaller than its thin header".to_string());
        }

        let mut inner_header = [0_u8; 32];
        read_macho_range(
            reader,
            file_len,
            entry.offset,
            &mut inner_header[..inner_header_len],
        )?;
        let inner_cpu_type = inner_order.i32(&inner_header[4..8]);
        let inner_cpu_subtype = inner_order.i32(&inner_header[8..12]);
        if (entry.cpu_type, entry.cpu_subtype) != (inner_cpu_type, inner_cpu_subtype) {
            return Err("fat Mach-O selector does not match its inner thin header".to_string());
        }
        if !selectors.insert((entry.cpu_type, entry.cpu_subtype)) {
            return Err("fat Mach-O contains a duplicate raw architecture selector".to_string());
        }
        architectures.push(CodeSignatureArchitecture::new(
            entry.cpu_type,
            entry.cpu_subtype,
        ));
    }

    architectures.sort();
    let selected = architectures
        .first()
        .cloned()
        .ok_or_else(|| "fat Mach-O has no architecture to select".to_string())?;
    Ok(MachOArchitectureSelection {
        selected,
        available: architectures,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignatureInspection {
    pub target: PathBuf,
    pub target_kind: CodeSignatureTargetKind,
    pub native_fact_scope: NativeFactScope,
    pub selected_architecture: Option<CodeSignatureArchitecture>,
    pub available_architectures: Vec<CodeSignatureArchitecture>,
    pub presence: SignaturePresence,
    pub verification_status: NativeCheckStatus,
    pub metadata_status: NativeCheckStatus,
    pub der_entitlements_status: NativeCheckStatus,
    pub entitlements_status: NativeCheckStatus,
    pub entitlement_source: Option<EntitlementSource>,
    pub entitlements: Vec<EntitlementEntry>,
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    pub authorities: Vec<String>,
    pub signature_kind: SignatureKind,
    pub hardened_runtime: Option<bool>,
    pub verification_detail: Option<String>,
    pub diagnostics: Vec<ScanDiagnostic>,
}

impl CodeSignatureInspection {
    pub fn unknown(target: PathBuf, target_kind: CodeSignatureTargetKind) -> Self {
        Self {
            target,
            target_kind,
            native_fact_scope: NativeFactScope::Unknown,
            selected_architecture: None,
            available_architectures: Vec::new(),
            presence: SignaturePresence::Unknown,
            verification_status: NativeCheckStatus::Error,
            metadata_status: NativeCheckStatus::Error,
            der_entitlements_status: NativeCheckStatus::Error,
            entitlements_status: NativeCheckStatus::Error,
            entitlement_source: None,
            entitlements: Vec::new(),
            identifier: None,
            team_identifier: None,
            authorities: Vec::new(),
            signature_kind: SignatureKind::Unknown,
            hardened_runtime: None,
            verification_detail: None,
            diagnostics: Vec::new(),
        }
    }
}

pub trait CodeSignatureInspector {
    fn inspect(
        &self,
        target: &Path,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection;
}

pub struct CodesignInspector<R: NativeCommandRunner> {
    runner: R,
}

impl<R: NativeCommandRunner> CodesignInspector<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: NativeCommandRunner> CodeSignatureInspector for CodesignInspector<R> {
    fn inspect(
        &self,
        target: &Path,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection {
        let target_identity = match validate_target(target, target_kind) {
            Ok(identity) => identity,
            Err(message) => {
                return failed_target_inspection(
                    target,
                    target_kind,
                    format!("code-signature target validation failed: {message}"),
                );
            }
        };

        let verify_arguments = [
            OsString::from("--verify"),
            OsString::from("--verbose=4"),
            target.as_os_str().to_os_string(),
        ];
        let display_arguments = [
            OsString::from("-d"),
            OsString::from("--verbose=4"),
            target.as_os_str().to_os_string(),
        ];
        let program = Path::new("/usr/bin/codesign");

        let verification_output = self.runner.run(program, &verify_arguments);
        if let Err(message) = revalidate_target(target, target_kind, &target_identity) {
            return failed_target_inspection(target, target_kind, message);
        }

        let metadata_output = self.runner.run(program, &display_arguments);
        if let Err(message) = revalidate_target(target, target_kind, &target_identity) {
            return failed_target_inspection(target, target_kind, message);
        }

        let verification = assess_verification(verification_output, target);
        let metadata = assess_metadata(metadata_output, target);

        reconcile(target, target_kind, verification, metadata)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TargetIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    file_type: u32,
    #[cfg(unix)]
    length: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(not(unix))]
    is_file: bool,
    #[cfg(not(unix))]
    is_directory: bool,
    #[cfg(not(unix))]
    length: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
    #[cfg(not(unix))]
    read_only: bool,
}

impl TargetIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                file_type: metadata.mode() & 0o170000,
                length: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }

        #[cfg(not(unix))]
        {
            Self {
                is_file: metadata.is_file(),
                is_directory: metadata.is_dir(),
                length: metadata.len(),
                modified: metadata.modified().ok(),
                created: metadata.created().ok(),
                read_only: metadata.permissions().readonly(),
            }
        }
    }
}

#[derive(Default)]
struct ParsedMetadata {
    identifier: TextObservation,
    team_identifier: TextObservation,
    authorities: Vec<String>,
    ad_hoc: bool,
    certificate_backed: bool,
    runtime: RuntimeObservation,
}

#[derive(Default)]
enum TextObservation {
    #[default]
    Unseen,
    Consistent(String),
    Conflicting,
}

impl TextObservation {
    fn observe_nonempty(&mut self, value: &str) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }

        match self {
            Self::Unseen => *self = Self::Consistent(value.to_string()),
            Self::Consistent(existing) if existing == value => {}
            Self::Consistent(_) => *self = Self::Conflicting,
            Self::Conflicting => {}
        }
    }

    fn value(self) -> Option<String> {
        match self {
            Self::Consistent(value) => Some(value),
            Self::Unseen | Self::Conflicting => None,
        }
    }

    fn is_conflicting(&self) -> bool {
        matches!(self, Self::Conflicting)
    }
}

#[derive(Clone, Copy, Default)]
enum RuntimeObservation {
    #[default]
    Unseen,
    Consistent(bool),
    Conflicting,
}

impl RuntimeObservation {
    fn observe(&mut self, value: bool) {
        *self = match *self {
            Self::Unseen => Self::Consistent(value),
            Self::Consistent(existing) if existing == value => Self::Consistent(existing),
            Self::Consistent(_) | Self::Conflicting => Self::Conflicting,
        };
    }

    fn value(self) -> Option<bool> {
        match self {
            Self::Consistent(value) => Some(value),
            Self::Unseen | Self::Conflicting => None,
        }
    }

    fn is_conflicting(self) -> bool {
        matches!(self, Self::Conflicting)
    }
}

struct QueryAssessment {
    status: NativeCheckStatus,
    positive_signed: bool,
    explicit_unsigned: bool,
    detail: Option<String>,
    diagnostics: Vec<ScanDiagnostic>,
    metadata: ParsedMetadata,
}

fn validate_target(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
) -> Result<TargetIdentity, String> {
    let metadata = std::fs::symlink_metadata(target)
        .map_err(|error| format!("cannot inspect '{}': {error}", target.display()))?;

    if metadata.file_type().is_symlink() {
        return Err(format!("'{}' is a symbolic link", target.display()));
    }

    match target_kind {
        CodeSignatureTargetKind::MachOFile if !metadata.is_file() => {
            return Err(format!("'{}' is not a regular file", target.display()));
        }
        CodeSignatureTargetKind::ApplicationBundle
            if !metadata.is_dir() || !has_app_extension(target) =>
        {
            return Err(format!(
                "'{}' is not a real .app directory",
                target.display()
            ));
        }
        _ => {}
    }

    Ok(TargetIdentity::from_metadata(&metadata))
}

fn revalidate_target(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
    expected: &TargetIdentity,
) -> Result<(), String> {
    let current = validate_target(target, target_kind)
        .map_err(|message| format!("code-signature target changed during inspection: {message}"))?;

    if &current == expected {
        Ok(())
    } else {
        Err(format!(
            "code-signature target changed during inspection: identity no longer matches for '{}'",
            target.display()
        ))
    }
}

fn failed_target_inspection(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
    message: String,
) -> CodeSignatureInspection {
    let mut inspection = CodeSignatureInspection::unknown(target.to_path_buf(), target_kind);
    inspection
        .diagnostics
        .push(code_signature_diagnostic(target, message));
    inspection
}

fn has_app_extension(target: &Path) -> bool {
    target
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
}

fn assess_verification(
    result: Result<NativeCommandOutput, NativeCommandError>,
    target: &Path,
) -> QueryAssessment {
    match result {
        Ok(output) => {
            let explicit_unsigned = output_contains_unsigned(&output, target);
            if output.success {
                QueryAssessment {
                    status: NativeCheckStatus::Passed,
                    positive_signed: true,
                    explicit_unsigned,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: ParsedMetadata::default(),
                }
            } else if explicit_unsigned {
                QueryAssessment {
                    status: NativeCheckStatus::NotApplicable,
                    positive_signed: false,
                    explicit_unsigned: true,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: ParsedMetadata::default(),
                }
            } else {
                QueryAssessment {
                    status: NativeCheckStatus::Failed,
                    positive_signed: false,
                    explicit_unsigned: false,
                    detail: output_detail(&output),
                    diagnostics: Vec::new(),
                    metadata: ParsedMetadata::default(),
                }
            }
        }
        Err(error) => runner_failure(error, target, "verification"),
    }
}

fn assess_metadata(
    result: Result<NativeCommandOutput, NativeCommandError>,
    target: &Path,
) -> QueryAssessment {
    match result {
        Ok(output) => {
            let explicit_unsigned = output_contains_unsigned(&output, target);
            let parsed = parse_metadata(&output);
            if output.success {
                QueryAssessment {
                    status: NativeCheckStatus::Passed,
                    positive_signed: true,
                    explicit_unsigned,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: parsed,
                }
            } else if explicit_unsigned {
                QueryAssessment {
                    status: NativeCheckStatus::NotApplicable,
                    positive_signed: false,
                    explicit_unsigned: true,
                    detail: None,
                    diagnostics: Vec::new(),
                    metadata: parsed,
                }
            } else {
                let detail = output_detail(&output);
                let message = match detail.as_deref() {
                    Some(detail) => format!("codesign metadata query failed: {detail}"),
                    None => "codesign metadata query failed".to_string(),
                };
                QueryAssessment {
                    status: NativeCheckStatus::Failed,
                    positive_signed: false,
                    explicit_unsigned: false,
                    detail,
                    diagnostics: vec![code_signature_diagnostic(target, message)],
                    metadata: parsed,
                }
            }
        }
        Err(error) => runner_failure(error, target, "metadata"),
    }
}

fn runner_failure(error: NativeCommandError, target: &Path, query: &str) -> QueryAssessment {
    let (status, message) = match error {
        NativeCommandError::Unavailable(message) => (
            NativeCheckStatus::Unavailable,
            format!("codesign {query} query unavailable: {message}"),
        ),
        NativeCommandError::Io(message) => (
            NativeCheckStatus::Error,
            format!("codesign {query} query error: {message}"),
        ),
    };

    QueryAssessment {
        status,
        positive_signed: false,
        explicit_unsigned: false,
        detail: None,
        diagnostics: vec![code_signature_diagnostic(target, message)],
        metadata: ParsedMetadata::default(),
    }
}

fn reconcile(
    target: &Path,
    target_kind: CodeSignatureTargetKind,
    verification: QueryAssessment,
    metadata: QueryAssessment,
) -> CodeSignatureInspection {
    let positive_signed = verification.positive_signed || metadata.positive_signed;
    let explicit_unsigned = verification.explicit_unsigned || metadata.explicit_unsigned;
    let contradictory = positive_signed && explicit_unsigned;
    let presence = if contradictory {
        SignaturePresence::Unknown
    } else if positive_signed {
        SignaturePresence::Signed
    } else if explicit_unsigned {
        SignaturePresence::Unsigned
    } else {
        SignaturePresence::Unknown
    };

    let mut diagnostics = verification.diagnostics;
    diagnostics.extend(metadata.diagnostics);
    if contradictory {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign verification and metadata queries disagree about signature presence"
                .to_string(),
        ));
    }

    let mut parsed = metadata.metadata;
    let clear_metadata = contradictory || presence == SignaturePresence::Unsigned;
    if clear_metadata {
        parsed = ParsedMetadata::default();
    }

    let signature_kind = if presence == SignaturePresence::Signed {
        match (parsed.ad_hoc, parsed.certificate_backed) {
            (true, false) => SignatureKind::AdHoc,
            (false, true) => SignatureKind::CertificateBacked,
            (true, true) => {
                diagnostics.push(code_signature_diagnostic(
                    target,
                    "codesign metadata contains conflicting ad-hoc and certificate-backed markers"
                        .to_string(),
                ));
                SignatureKind::Unknown
            }
            (false, false) => SignatureKind::Unknown,
        }
    } else {
        SignatureKind::Unknown
    };

    if parsed.runtime.is_conflicting() {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign metadata contains ambiguous hardened-runtime observations".to_string(),
        ));
    }
    if parsed.identifier.is_conflicting() {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign metadata contains ambiguous Identifier observations".to_string(),
        ));
    }
    if parsed.team_identifier.is_conflicting() {
        diagnostics.push(code_signature_diagnostic(
            target,
            "codesign metadata contains ambiguous TeamIdentifier observations".to_string(),
        ));
    }
    let identifier = parsed.identifier.value();
    let team_identifier = parsed.team_identifier.value();
    let hardened_runtime = parsed.runtime.value();

    diagnostics.sort_by(|left, right| left.message.cmp(&right.message));

    CodeSignatureInspection {
        target: target.to_path_buf(),
        target_kind,
        native_fact_scope: NativeFactScope::Unknown,
        selected_architecture: None,
        available_architectures: Vec::new(),
        presence,
        verification_status: verification.status,
        metadata_status: metadata.status,
        der_entitlements_status: NativeCheckStatus::Error,
        entitlements_status: NativeCheckStatus::Error,
        entitlement_source: None,
        entitlements: Vec::new(),
        identifier,
        team_identifier,
        authorities: parsed.authorities,
        signature_kind,
        hardened_runtime,
        verification_detail: verification.detail,
        diagnostics,
    }
}

fn parse_metadata(output: &NativeCommandOutput) -> ParsedMetadata {
    let mut parsed = ParsedMetadata::default();
    for line in output_lines(output) {
        parse_metadata_line(line.trim(), &mut parsed);
    }
    parsed
}

fn parse_metadata_line(line: &str, parsed: &mut ParsedMetadata) {
    if let Some(value) = line.strip_prefix("Identifier=") {
        parsed.identifier.observe_nonempty(value);
    } else if let Some(value) = line.strip_prefix("TeamIdentifier=") {
        let value = value.trim();
        if value != "not set" {
            parsed.team_identifier.observe_nonempty(value);
        }
    } else if let Some(value) = line.strip_prefix("Authority=") {
        let value = value.trim();
        if !value.is_empty()
            && value != "(unavailable)"
            && !parsed
                .authorities
                .iter()
                .any(|authority| authority == value)
        {
            parsed.authorities.push(value.to_string());
            parsed.certificate_backed = true;
        }
    } else if let Some(value) = line.strip_prefix("Signature=") {
        if value.trim() == "adhoc" {
            parsed.ad_hoc = true;
        }
    } else if line.starts_with("Signature size=") {
        parsed.certificate_backed = true;
    } else if let Some(record) = line.strip_prefix("CodeDirectory ") {
        parse_code_directory_flags(record, parsed);
    }
}

fn parse_code_directory_flags(record: &str, parsed: &mut ParsedMetadata) {
    let Some(flags) = record
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("flags="))
    else {
        return;
    };

    let Some(opening) = flags.find('(') else {
        return;
    };
    let Some(through_tokens) = flags.strip_suffix(')') else {
        return;
    };
    let mut runtime = false;

    for token in through_tokens[opening + 1..].split(',').map(str::trim) {
        match token {
            "adhoc" => parsed.ad_hoc = true,
            "runtime" => runtime = true,
            _ => {}
        }
    }
    parsed.runtime.observe(runtime);
}

fn output_contains_unsigned(output: &NativeCommandOutput, target: &Path) -> bool {
    output_lines(output)
        .iter()
        .any(|line| is_unsigned_diagnostic_line(line.trim(), target))
}

fn is_unsigned_diagnostic_line(line: &str, target: &Path) -> bool {
    const UNSIGNED_DIAGNOSTIC: &str = "code object is not signed at all";

    line == UNSIGNED_DIAGNOSTIC || line == format!("{}: {UNSIGNED_DIAGNOSTIC}", target.display())
}

fn output_detail(output: &NativeCommandOutput) -> Option<String> {
    output_lines(output)
        .iter()
        .map(|line| line.trim())
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn output_lines(output: &NativeCommandOutput) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .chain(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .map(str::to_owned),
        )
        .collect()
}

fn code_signature_diagnostic(target: &Path, message: String) -> ScanDiagnostic {
    ScanDiagnostic::new(
        DiagnosticKind::CodeSignature,
        Some(target.to_path_buf()),
        message,
    )
}

#[cfg(target_os = "macos")]
pub type PlatformCodeSignatureInspector = CodesignInspector<SystemCommandRunner>;

#[cfg(target_os = "macos")]
pub fn platform_code_signature_inspector() -> PlatformCodeSignatureInspector {
    CodesignInspector::new(SystemCommandRunner)
}

#[cfg(not(target_os = "macos"))]
pub struct PlatformCodeSignatureInspector;

#[cfg(not(target_os = "macos"))]
impl CodeSignatureInspector for PlatformCodeSignatureInspector {
    fn inspect(
        &self,
        target: &Path,
        target_kind: CodeSignatureTargetKind,
    ) -> CodeSignatureInspection {
        let mut inspection = CodeSignatureInspection::unknown(target.to_path_buf(), target_kind);
        inspection.verification_status = NativeCheckStatus::Unavailable;
        inspection.metadata_status = NativeCheckStatus::Unavailable;
        inspection.diagnostics.push(code_signature_diagnostic(
            target,
            "native macOS code-signature inspection is unavailable on this platform".to_string(),
        ));
        inspection
    }
}

#[cfg(not(target_os = "macos"))]
pub fn platform_code_signature_inspector() -> PlatformCodeSignatureInspector {
    PlatformCodeSignatureInspector
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeSet, VecDeque};
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::macos::command::{NativeCommandError, NativeCommandOutput, NativeCommandRunner};
    use crate::scanner::result::DiagnosticKind;

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aegisforge-codesign-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory should be created");
            Self { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, b"fixture").expect("test file should be created");
            path
        }

        fn bundle(&self, name: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::create_dir(&path).expect("test bundle should be created");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    type RunResult = Result<NativeCommandOutput, NativeCommandError>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedCall {
        program: PathBuf,
        arguments: Vec<OsString>,
    }

    struct RecordingRunner {
        results: RefCell<VecDeque<RunResult>>,
        calls: RefCell<Vec<RecordedCall>>,
    }

    impl RecordingRunner {
        fn new(results: impl IntoIterator<Item = RunResult>) -> Self {
            Self {
                results: RefCell::new(results.into_iter().collect()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl NativeCommandRunner for RecordingRunner {
        fn run(&self, program: &Path, arguments: &[OsString]) -> RunResult {
            self.calls.borrow_mut().push(RecordedCall {
                program: program.to_path_buf(),
                arguments: arguments.to_vec(),
            });
            self.results
                .borrow_mut()
                .pop_front()
                .expect("fake runner should have a queued result")
        }
    }

    struct ReplacingRunner {
        target: PathBuf,
        backup: PathBuf,
        replace_after_call: usize,
        calls: Cell<usize>,
        results: RefCell<VecDeque<RunResult>>,
    }

    impl ReplacingRunner {
        fn new(
            target: PathBuf,
            replace_after_call: usize,
            results: impl IntoIterator<Item = RunResult>,
        ) -> Self {
            let backup = target.with_extension("original-before-codesign-test");
            Self {
                target,
                backup,
                replace_after_call,
                calls: Cell::new(0),
                results: RefCell::new(results.into_iter().collect()),
            }
        }
    }

    impl NativeCommandRunner for ReplacingRunner {
        fn run(&self, _program: &Path, _arguments: &[OsString]) -> RunResult {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.replace_after_call {
                fs::rename(&self.target, &self.backup)
                    .expect("validated test target should be moved aside");
                fs::write(&self.target, b"replacement target with different contents")
                    .expect("replacement test target should be created");
            }
            self.results
                .borrow_mut()
                .pop_front()
                .expect("replacing runner should have a queued result")
        }
    }

    fn command_output(success: bool, stdout: &str, stderr: &str) -> RunResult {
        Ok(NativeCommandOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    fn inspect_file(runner: RecordingRunner) -> (CodeSignatureInspection, RecordingRunner) {
        let directory = TestDirectory::new();
        let target = directory.file("sample");
        let inspector = CodesignInspector::new(runner);
        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);
        (inspection, inspector.runner)
    }

    fn messages(inspection: &CodeSignatureInspection) -> Vec<&str> {
        inspection
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    #[test]
    fn signature_presence_has_stable_labels() {
        assert_eq!(SignaturePresence::Signed.as_str(), "SIGNED");
        assert_eq!(SignaturePresence::Unsigned.as_str(), "UNSIGNED");
        assert_eq!(SignaturePresence::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn native_check_status_has_stable_labels() {
        assert_eq!(NativeCheckStatus::Passed.as_str(), "PASSED");
        assert_eq!(NativeCheckStatus::Failed.as_str(), "FAILED");
        assert_eq!(NativeCheckStatus::NotApplicable.as_str(), "NOT_APPLICABLE");
        assert_eq!(NativeCheckStatus::Unavailable.as_str(), "UNAVAILABLE");
        assert_eq!(NativeCheckStatus::Error.as_str(), "ERROR");
    }

    #[test]
    fn code_signature_target_kind_has_stable_labels() {
        assert_eq!(CodeSignatureTargetKind::MachOFile.as_str(), "MACH_O_FILE");
        assert_eq!(
            CodeSignatureTargetKind::ApplicationBundle.as_str(),
            "APPLICATION_BUNDLE"
        );
    }

    #[test]
    fn signature_kind_has_stable_labels() {
        assert_eq!(SignatureKind::AdHoc.as_str(), "AD_HOC");
        assert_eq!(
            SignatureKind::CertificateBacked.as_str(),
            "CERTIFICATE_BACKED"
        );
        assert_eq!(SignatureKind::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn native_fact_scope_has_stable_labels() {
        assert_eq!(
            NativeFactScope::AllArchitectures.as_str(),
            "ALL_ARCHITECTURES"
        );
        assert_eq!(
            NativeFactScope::SingleArchitecture.as_str(),
            "SINGLE_ARCHITECTURE"
        );
        assert_eq!(
            NativeFactScope::SelectedArchitecture.as_str(),
            "SELECTED_ARCHITECTURE"
        );
        assert_eq!(NativeFactScope::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn architecture_has_exact_selector_and_known_label() {
        let architecture = CodeSignatureArchitecture::new(16_777_228, 2);

        assert_eq!(architecture.cpu_type, 16_777_228);
        assert_eq!(architecture.cpu_subtype, 2);
        assert_eq!(architecture.display_label, "arm64e");
        assert_eq!(architecture.codesign_selector(), "16777228,2");
    }

    #[test]
    fn architecture_masks_capability_bits_only_for_label_lookup() {
        let subtype_with_capability = (0x8000_0000_u32 | 2) as i32;
        let architecture = CodeSignatureArchitecture::new(16_777_228, subtype_with_capability);

        assert_eq!(architecture.display_label, "arm64e");
        assert_eq!(architecture.cpu_subtype, subtype_with_capability);
        assert_eq!(
            architecture.codesign_selector(),
            format!("16777228,{subtype_with_capability}")
        );
    }

    #[test]
    fn architecture_fallback_label_is_deterministic_and_numeric() {
        let first = CodeSignatureArchitecture::new(123, -456);
        let second = CodeSignatureArchitecture::new(123, -456);

        assert_eq!(first, second);
        assert_eq!(first.display_label, "cpu_type=123,cpu_subtype=-456");
        assert_eq!(first.codesign_selector(), "123,-456");
    }

    #[test]
    fn architecture_order_uses_the_raw_signed_tuple() {
        let lower_subtype = CodeSignatureArchitecture::new(7, -1);
        let higher_subtype = CodeSignatureArchitecture::new(7, 0);
        let higher_type = CodeSignatureArchitecture::new(8, i32::MIN);

        assert!(lower_subtype < higher_subtype);
        assert!(higher_subtype < higher_type);
    }

    #[test]
    fn architecture_identity_ignores_display_label() {
        let first = CodeSignatureArchitecture {
            cpu_type: 16_777_228,
            cpu_subtype: 2,
            display_label: "arm64e".to_string(),
        };
        let relabeled = CodeSignatureArchitecture {
            display_label: "deliberately different".to_string(),
            ..first.clone()
        };

        assert_eq!(first, relabeled);
        assert_eq!(first.cmp(&relabeled), std::cmp::Ordering::Equal);
        assert_eq!(BTreeSet::from([first, relabeled]).len(), 1);
    }

    #[test]
    fn target_kinds_remain_distinct_in_constructed_inspections() {
        let file = CodeSignatureInspection::unknown(
            PathBuf::from("sample"),
            CodeSignatureTargetKind::MachOFile,
        );
        let bundle = CodeSignatureInspection::unknown(
            PathBuf::from("Sample.app"),
            CodeSignatureTargetKind::ApplicationBundle,
        );

        assert_eq!(file.target_kind, CodeSignatureTargetKind::MachOFile);
        assert_eq!(
            bundle.target_kind,
            CodeSignatureTargetKind::ApplicationBundle
        );
        assert_ne!(file.target_kind, bundle.target_kind);
    }

    #[test]
    fn unknown_inspection_uses_conservative_defaults() {
        let target = PathBuf::from("sample");

        let inspection =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.target, target);
        assert_eq!(inspection.target_kind, CodeSignatureTargetKind::MachOFile);
        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.native_fact_scope, NativeFactScope::Unknown);
        assert_eq!(inspection.selected_architecture, None);
        assert!(inspection.available_architectures.is_empty());
        assert_eq!(inspection.der_entitlements_status, NativeCheckStatus::Error);
        assert_eq!(inspection.entitlements_status, NativeCheckStatus::Error);
        assert_eq!(inspection.entitlement_source, None);
        assert!(inspection.entitlements.is_empty());
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert!(inspection.diagnostics.is_empty());
    }

    fn native_fact_scope_fields_are_valid(inspection: &CodeSignatureInspection) -> bool {
        let has_no_selected_facts = inspection.identifier.is_none()
            && inspection.team_identifier.is_none()
            && inspection.authorities.is_empty()
            && inspection.signature_kind == SignatureKind::Unknown
            && inspection.hardened_runtime.is_none()
            && inspection.entitlement_source.is_none()
            && inspection.entitlements.is_empty();

        match inspection.native_fact_scope {
            NativeFactScope::Unknown | NativeFactScope::AllArchitectures => {
                inspection.selected_architecture.is_none()
                    && inspection.available_architectures.is_empty()
                    && has_no_selected_facts
            }
            NativeFactScope::SingleArchitecture => inspection
                .selected_architecture
                .as_ref()
                .is_some_and(|selected| {
                    inspection.available_architectures.as_slice() == std::slice::from_ref(selected)
                }),
            NativeFactScope::SelectedArchitecture => {
                inspection.available_architectures.len() >= 2
                    && inspection
                        .selected_architecture
                        .as_ref()
                        .is_some_and(|selected| {
                            inspection.available_architectures.contains(selected)
                        })
            }
        }
    }

    #[test]
    fn native_fact_scope_examples_obey_field_invariants() {
        let target = PathBuf::from("sample");
        let first = CodeSignatureArchitecture::new(7, 3);
        let second = CodeSignatureArchitecture::new(16_777_228, 0);

        let unknown =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);

        let mut all =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);
        all.native_fact_scope = NativeFactScope::AllArchitectures;
        all.presence = SignaturePresence::Signed;
        all.verification_status = NativeCheckStatus::Passed;

        let mut single =
            CodeSignatureInspection::unknown(target.clone(), CodeSignatureTargetKind::MachOFile);
        single.native_fact_scope = NativeFactScope::SingleArchitecture;
        single.selected_architecture = Some(first.clone());
        single.available_architectures = vec![first.clone()];

        let mut selected =
            CodeSignatureInspection::unknown(target, CodeSignatureTargetKind::MachOFile);
        selected.native_fact_scope = NativeFactScope::SelectedArchitecture;
        selected.selected_architecture = Some(first.clone());
        selected.available_architectures = vec![first, second];

        assert!(native_fact_scope_fields_are_valid(&unknown));
        assert!(native_fact_scope_fields_are_valid(&all));
        assert!(native_fact_scope_fields_are_valid(&single));
        assert!(native_fact_scope_fields_are_valid(&selected));
    }

    #[test]
    fn code_signature_inspector_is_object_safe() {
        fn accepts_inspector(_inspector: &dyn CodeSignatureInspector) {}

        let runner = RecordingRunner::new([]);
        accepts_inspector(&CodesignInspector::new(runner));
    }

    #[test]
    fn successful_adhoc_signature_is_reconciled_as_signed() {
        let runner = RecordingRunner::new([
            command_output(true, "", "sample: valid on disk\n"),
            command_output(
                true,
                "",
                "Identifier=com.example.tool\nCodeDirectory v=20400 flags=0x20002(adhoc,linker-signed) hashes=1\nSignature=adhoc\nTeamIdentifier=not set\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.signature_kind, SignatureKind::AdHoc);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.tool"));
        assert_eq!(inspection.team_identifier, None);
        assert_eq!(inspection.hardened_runtime, Some(false));
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn certificate_metadata_handles_crlf_reordering_and_stable_deduplication() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\r\n"),
            command_output(
                true,
                "Authority=Leaf Certificate\r\nTeamIdentifier=TEAM12345\r\nAuthority=(unavailable)\r\nSignature size=9000\r\nAuthority=Root Certificate\r\nAuthority=Leaf Certificate\r\nCodeDirectory v=20500 flags=0x10000(runtime) hashes=2\r\nIdentifier=com.example.signed\r\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.signature_kind, SignatureKind::CertificateBacked);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.signed"));
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM12345"));
        assert_eq!(
            inspection.authorities,
            vec!["Leaf Certificate", "Root Certificate"]
        );
        assert_eq!(inspection.hardened_runtime, Some(true));
    }

    #[test]
    fn explicit_unsigned_from_both_queries_is_not_applicable() {
        let standalone = "code object is not signed at all\n";
        let runner = RecordingRunner::new([
            command_output(false, "", standalone),
            command_output(false, standalone, ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Unsigned);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::NotApplicable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::NotApplicable);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn unsigned_diagnostic_for_different_target_is_not_accepted() {
        let directory = TestDirectory::new();
        let target = directory.file("sample");
        let diagnostic = format!(
            "{}: code object is not signed at all\n",
            directory.path.join("different-sample").display()
        );
        let runner = RecordingRunner::new([
            command_output(false, "", &diagnostic),
            command_output(false, &diagnostic, ""),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Failed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Failed);
    }

    #[test]
    fn exact_unsigned_diagnostic_accepts_target_path_containing_equals() {
        let directory = TestDirectory::new();
        let target = directory.file("unsigned=sample");
        let diagnostic = format!("{}: code object is not signed at all\n", target.display());
        let runner = RecordingRunner::new([
            command_output(false, "", &diagnostic),
            command_output(false, &diagnostic, ""),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unsigned);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::NotApplicable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::NotApplicable);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn unsigned_phrase_inside_signed_key_value_metadata_is_not_a_diagnostic() {
        let directory = TestDirectory::new();
        let target = directory.file("signed code object is not signed at all");
        let authority = "Signer: code object is not signed at all";
        let display_output = format!(
            "Executable={}\nIdentifier=com.example.signed\nAuthority={authority}\nSignature size=9000\n",
            target.display()
        );
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "", &display_output),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.signature_kind, SignatureKind::CertificateBacked);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.signed"));
        assert_eq!(inspection.authorities, vec![authority]);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn invalid_verification_retains_successful_signed_metadata_and_detail() {
        let runner = RecordingRunner::new([
            command_output(
                false,
                "",
                "sample: invalid signature (code or signature modified)\n",
            ),
            command_output(
                true,
                "Identifier=com.example.invalid\nAuthority=Signer\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Failed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.invalid")
        );
        assert_eq!(inspection.authorities, vec!["Signer"]);
        assert!(
            inspection
                .verification_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("invalid signature"))
        );
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn failed_display_preserves_positive_verification_without_inventing_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                false,
                "unrecognized output\nIdentifier=com.example.partial\n",
                "display failed\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Failed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.partial")
        );
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("metadata"));
    }

    #[test]
    fn positive_signed_and_explicit_unsigned_are_reported_as_contradictory() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                false,
                "Identifier=must.be.cleared\nAuthority=Must Clear\nCodeDirectory flags=0x10000(runtime)\n",
                "code object is not signed at all\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::NotApplicable);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("disagree"));
    }

    #[test]
    fn conflicting_adhoc_and_certificate_markers_leave_signature_kind_unknown() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "Signature=adhoc\nAuthority=Signer\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.authorities, vec!["Signer"]);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("conflicting"));
    }

    #[test]
    fn independent_runner_failures_have_truthful_statuses_and_sorted_diagnostics() {
        let runner = RecordingRunner::new([
            Err(NativeCommandError::Unavailable(
                "codesign missing".to_string(),
            )),
            Err(NativeCommandError::Io(
                "display could not start".to_string(),
            )),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::Unavailable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.diagnostics.len(), 2);
        assert!(
            inspection
                .diagnostics
                .windows(2)
                .all(|pair| pair[0].message <= pair[1].message)
        );
        assert!(
            messages(&inspection)
                .iter()
                .any(|message| message.contains("codesign missing"))
        );
        assert!(
            messages(&inspection)
                .iter()
                .any(|message| message.contains("display could not start"))
        );
    }

    #[test]
    fn metadata_output_limit_preserves_successful_verification_without_inventing_metadata() {
        let directory = TestDirectory::new();
        let target = directory.file("output-limited");
        let limit_reason = "native command stderr exceeded 1048576-byte limit";
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            Err(NativeCommandError::Io(limit_reason.to_string())),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Passed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(inspection.diagnostics[0].message.contains(limit_reason));
        assert_eq!(
            inspector.runner.calls.borrow().as_slice(),
            [
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("--verify"),
                        OsString::from("--verbose=4"),
                        target.clone().into_os_string(),
                    ],
                },
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("-d"),
                        OsString::from("--verbose=4"),
                        target.into_os_string(),
                    ],
                },
            ]
        );
    }

    #[test]
    fn invokes_codesign_with_exact_arguments_and_keeps_hostile_bundle_path_atomic() {
        let directory = TestDirectory::new();
        let target = directory.bundle("name with spaces;$(touch nope).app");
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "Identifier=com.example.bundle\n", ""),
        ]);
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::ApplicationBundle);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(
            inspector.runner.calls.borrow().as_slice(),
            [
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("--verify"),
                        OsString::from("--verbose=4"),
                        target.clone().into_os_string(),
                    ],
                },
                RecordedCall {
                    program: PathBuf::from("/usr/bin/codesign"),
                    arguments: vec![
                        OsString::from("-d"),
                        OsString::from("--verbose=4"),
                        target.into_os_string(),
                    ],
                },
            ]
        );
        assert!(!directory.path.join("nope").exists());
    }

    #[test]
    fn useful_metadata_is_combined_from_stdout_and_stderr() {
        let runner = RecordingRunner::new([
            command_output(true, "unknown verify line\n", "valid\n"),
            command_output(
                true,
                "unknown first\nTeamIdentifier=TEAM-SPLIT\nAuthority=Leaf\n",
                "Identifier=com.example.split\nCodeDirectory v=1 flags=0x2(adhoc) extra\nAuthority=Root\nunknown last\n",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.identifier.as_deref(), Some("com.example.split"));
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM-SPLIT"));
        assert_eq!(inspection.authorities, vec!["Leaf", "Root"]);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, Some(false));
    }

    #[test]
    fn code_directory_prefix_without_record_boundary_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectoryBogus v=1 flags=0x10000(runtime)\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn flags_substring_inside_another_field_name_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectory v=1 notflags=0x10000(runtime)\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn flags_field_without_parenthesized_tokens_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectory v=1 flags=0x0\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn flags_field_with_unclosed_token_list_is_ignored() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(true, "CodeDirectory v=1 flags=0x10000(runtime\n", ""),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
    }

    #[test]
    fn conflicting_runtime_observations_are_ambiguous_without_losing_signed_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.runtime-conflict\nCodeDirectory v=1 flags=0x0(none)\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Passed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.runtime-conflict")
        );
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("ambiguous"));
    }

    #[test]
    fn duplicate_true_runtime_observations_remain_true_without_diagnostic() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "CodeDirectory v=1 flags=0x10000(runtime)\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, Some(true));
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn duplicate_false_runtime_observations_remain_false_without_diagnostic() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "CodeDirectory v=1 flags=0x0(none)\nCodeDirectory v=1 flags=0x2(linker-signed)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.hardened_runtime, Some(false));
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn conflicting_identifier_observations_clear_identifier_and_preserve_other_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.first\nTeamIdentifier=TEAM-STABLE\nIdentifier=com.example.second\nAuthority=Stable Signer\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM-STABLE"));
        assert_eq!(inspection.authorities, vec!["Stable Signer"]);
        assert_eq!(inspection.hardened_runtime, Some(true));
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("Identifier"));
        assert!(messages(&inspection)[0].contains("ambiguous"));
    }

    #[test]
    fn conflicting_team_identifier_observations_clear_team_and_preserve_other_metadata() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.stable\nTeamIdentifier=TEAM-FIRST\nTeamIdentifier=TEAM-SECOND\nAuthority=Stable Signer\nCodeDirectory v=1 flags=0x0(none)\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(inspection.identifier.as_deref(), Some("com.example.stable"));
        assert_eq!(inspection.team_identifier, None);
        assert_eq!(inspection.authorities, vec!["Stable Signer"]);
        assert_eq!(inspection.hardened_runtime, Some(false));
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("TeamIdentifier"));
        assert!(messages(&inspection)[0].contains("ambiguous"));
    }

    #[test]
    fn exact_duplicate_identity_observations_remain_present_without_diagnostic() {
        let runner = RecordingRunner::new([
            command_output(true, "", "valid\n"),
            command_output(
                true,
                "Identifier=com.example.duplicate\nTeamIdentifier=TEAM-SAME\nIdentifier=com.example.duplicate\nTeamIdentifier=TEAM-SAME\nAuthority=Signer\n",
                "",
            ),
        ]);

        let (inspection, _) = inspect_file(runner);

        assert_eq!(inspection.presence, SignaturePresence::Signed);
        assert_eq!(
            inspection.identifier.as_deref(),
            Some("com.example.duplicate")
        );
        assert_eq!(inspection.team_identifier.as_deref(), Some("TEAM-SAME"));
        assert_eq!(inspection.authorities, vec!["Signer"]);
        assert!(inspection.diagnostics.is_empty());
    }

    #[test]
    fn wrong_target_kind_is_rejected_before_commands_run() {
        let directory = TestDirectory::new();
        let target = directory.file("not-a-bundle.app");
        let inspector = CodesignInspector::new(RecordingRunner::new([]));

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::ApplicationBundle);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(inspector.runner.calls.borrow().is_empty());
    }

    #[test]
    fn target_replacement_after_verify_stops_display_and_discards_query_facts() {
        let directory = TestDirectory::new();
        let target = directory.file("replace-between-queries");
        let runner = ReplacingRunner::new(
            target.clone(),
            1,
            [
                command_output(true, "", "valid\n"),
                command_output(
                    true,
                    "Identifier=com.example.replacement\nAuthority=Replacement Signer\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                    "",
                ),
            ],
        );
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspector.runner.calls.get(), 1);
        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("changed"));
    }

    #[test]
    fn target_replacement_after_display_discards_all_query_facts() {
        let directory = TestDirectory::new();
        let target = directory.file("replace-after-display");
        let runner = ReplacingRunner::new(
            target.clone(),
            2,
            [
                command_output(true, "", "valid\n"),
                command_output(
                    true,
                    "Identifier=com.example.original\nAuthority=Original Signer\nCodeDirectory v=1 flags=0x10000(runtime)\n",
                    "",
                ),
            ],
        );
        let inspector = CodesignInspector::new(runner);

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspector.runner.calls.get(), 2);
        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.identifier, None);
        assert_eq!(inspection.team_identifier, None);
        assert!(inspection.authorities.is_empty());
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.hardened_runtime, None);
        assert_eq!(inspection.verification_detail, None);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(messages(&inspection)[0].contains("changed"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_is_rejected_before_commands_run() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let real_target = directory.file("real");
        let target = directory.path.join("link");
        symlink(real_target, &target).expect("test symlink should be created");
        let inspector = CodesignInspector::new(RecordingRunner::new([]));

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(inspection.verification_status, NativeCheckStatus::Error);
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Error);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert!(inspector.runner.calls.borrow().is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_platform_inspector_reports_unavailable_without_native_execution() {
        let directory = TestDirectory::new();
        let target = directory.file("sample");
        let inspector = platform_code_signature_inspector();

        let inspection = inspector.inspect(&target, CodeSignatureTargetKind::MachOFile);

        assert_eq!(inspection.presence, SignaturePresence::Unknown);
        assert_eq!(
            inspection.verification_status,
            NativeCheckStatus::Unavailable
        );
        assert_eq!(inspection.metadata_status, NativeCheckStatus::Unavailable);
        assert_eq!(inspection.signature_kind, SignatureKind::Unknown);
        assert_eq!(inspection.diagnostics.len(), 1);
        assert_eq!(
            inspection.diagnostics[0].kind,
            DiagnosticKind::CodeSignature
        );
        assert!(messages(&inspection)[0].contains("macOS"));
    }
}
