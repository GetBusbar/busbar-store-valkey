// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::persistence::{
    legacy_row::{self, Cell},
    lifecycle::{self as l, source::HistoricalFact},
};
use std::io::{Seek, SeekFrom};

struct Counted {
    archive: archive::VerifiedArchive<archive::spool::SpoolReader>,
    reads: usize,
}
impl SourceRows for Counted {
    fn header(&self) -> &archive::Header {
        self.archive.header()
    }
    fn row_count(&self) -> u64 {
        self.archive.summary().rows
    }
    fn row_frame_bytes(&self, ordinal: u64) -> Result<usize, l::Error> {
        self.archive.row_frame_bytes(ordinal).map_err(archive_error)
    }
    fn find_native(&self, table: u32, key: &[u8]) -> Result<Option<u64>, l::Error> {
        self.archive.find_native(table, key).map_err(archive_error)
    }
    fn read_row(&mut self, ordinal: u64) -> Result<archive::ArchiveRow<Own>, l::Error> {
        self.reads += 1;
        self.archive.read_row_owned(ordinal).map_err(archive_error)
    }
}
fn bounds() -> l::InterpretationBounds {
    l::InterpretationBounds {
        semantic_bytes: 16 * 1024 * 1024,
        index_bytes: 4 * 1024 * 1024,
        storage_bytes: 16 * 1024 * 1024,
    }
}
fn source(omit_membership: bool) -> (Counted, [u8; 32]) {
    let bytes = include_bytes!("fixtures/valkey-1.5.5-rows.json");
    let source_digest = archive::digest(bytes);
    let data: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let data = data.as_object().unwrap();
    let layout = legacy_row::encode::<Own>(
        &[
            Cell::Text(b"busbar.valkey.native-snapshot/1"),
            Cell::Integer(0),
            Cell::Integer(6),
            Cell::Blob(b"8.1.3"),
            Cell::Blob(&[1; 32]),
            Cell::Blob(&source_digest),
            Cell::Integer(1),
            Cell::Blob(&(data.len() as u64).to_le_bytes()),
        ],
        4096,
    )
    .unwrap();
    let header = archive::Header {
        owner: crate::source_interpretation::SOURCE_OWNER,
        physical: 6,
        catalogue_digest: source_digest,
        native_anchor_digest: [0; 32],
        capture: None,
        tables: vec![archive::Table {
            name: "valkey".into(),
            columns: decode::NATIVE_COLUMNS.iter().map(|s| (*s).into()).collect(),
            native_layout: layout.expose_own(&Own::here()).clone(),
        }],
    };
    let limits = archive::Limits {
        frame_bytes: 1024 * 1024,
        total_bytes: bounds().storage_bytes,
        rows: 10000,
        tables: 1,
        columns: 6,
        index_bytes: 1024 * 1024,
    };
    let mut writer = archive::Writer::new(
        archive::spool::SpoolWriter::bounded(bounds().storage_bytes).unwrap(),
        header,
        limits,
    )
    .unwrap();
    let mut emit = |key: &[u8], kind: i64, position: &[u8], value: &[u8]| {
        let identity = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Integer(kind),
                Cell::Blob(key),
                Cell::Blob(position),
            ],
            65536,
        )
        .unwrap();
        let row = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Integer(kind),
                Cell::Integer(-1),
                Cell::Blob(key),
                Cell::Blob(position),
                Cell::Blob(value),
            ],
            65536,
        )
        .unwrap();
        writer
            .write_row(
                0,
                identity.expose_own(&Own::here()),
                row.expose_own(&Own::here()),
            )
            .unwrap();
    };
    for (key, value) in data {
        assert_eq!(value["has_ttl"], false);
        let kind = value["type"].as_str().unwrap();
        emit(key.as_bytes(), 0, b"", kind.as_bytes());
        match kind {
            "string" => emit(
                key.as_bytes(),
                1,
                b"",
                value["value"].as_str().unwrap().as_bytes(),
            ),
            "hash" => {
                for (field, value) in value["value"].as_object().unwrap() {
                    emit(
                        key.as_bytes(),
                        2,
                        field.as_bytes(),
                        value.as_str().unwrap().as_bytes(),
                    );
                }
            }
            "set" => {
                for (i, member) in value["value"].as_array().unwrap().iter().enumerate() {
                    if !(omit_membership && key.starts_with("busbar:metering:") && i == 0) {
                        emit(key.as_bytes(), 3, member.as_str().unwrap().as_bytes(), b"");
                    }
                }
            }
            "zset" => {
                for item in value["value"].as_array().unwrap() {
                    emit(
                        key.as_bytes(),
                        4,
                        item[0].as_str().unwrap().as_bytes(),
                        item[1].as_str().unwrap().as_bytes(),
                    );
                }
            }
            _ => panic!("recorded native type"),
        }
    }
    let (output, _) = writer.finish().unwrap();
    let mut input = output.finish().unwrap();
    input.seek(SeekFrom::Start(0)).unwrap();
    (
        Counted {
            archive: archive::read(input, limits).unwrap(),
            reads: 0,
        },
        source_digest,
    )
}
#[test]
fn indexed_stream_preserves_every_original_once_without_per_page_rescans() {
    let (mut source, digest) = source(false);
    let mut prepared = Prepared::build(&mut source, [1; 32], digest, bounds()).unwrap();
    let before = source.reads;
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut facts = 0;
    let mut usage = 0;
    let mut sequence = 0;
    let mut active = None;
    loop {
        let page: l::SourcePage<Own> = prepared
            .page(
                &mut source,
                [2; 16],
                cursor
                    .as_ref()
                    .map(|s: &busbar_contract::Secret<Vec<u8>, Own>| {
                        s.expose_own(&Own::here()).as_slice()
                    }),
                l::Bounds {
                    items: 1,
                    bytes: 65536,
                },
            )
            .unwrap();
        for row in page.rows {
            let chunk = l::codec::decode_source_chunk_owned::<Own>(
                row.value.expose_own(&Own::here()),
                l::Bounds {
                    items: u32::MAX,
                    bytes: bounds().semantic_bytes,
                },
            )
            .unwrap();
            if active.is_none() {
                active = Some(chunk.group.clone());
                sequence = 0;
            }
            assert_eq!(active.as_ref(), Some(&chunk.group));
            assert_eq!(sequence, chunk.sequence);
            sequence += 1;
            for fact in chunk.facts {
                facts += 1;
                if let HistoricalFact::Usage { ledger, .. } = fact {
                    usage += 1;
                    assert!(ledger.total_input() > 0);
                }
            }
            for evidence in chunk.evidence {
                let ordinal = source
                    .find_native(evidence.table, evidence.native_key.expose_own(&Own::here()))
                    .unwrap()
                    .unwrap();
                assert!(seen.insert(ordinal));
                let original = source.archive.read_row_owned::<Own>(ordinal).unwrap();
                assert_eq!(
                    evidence.value_digest,
                    archive::digest(original.value.expose_own(&Own::here()))
                );
            }
            if chunk.complete {
                active = None;
            }
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert!(active.is_none());
    assert_eq!(seen.len() as u64, source.row_count());
    assert!(facts > 10);
    assert_eq!(usage, 3);
    assert_eq!(
        source.reads - before,
        source.row_count() as usize,
        "normal paging visits every original group once"
    );
}
#[test]
fn missing_native_membership_refuses_the_interpreted_stream() {
    let (mut source, digest) = source(true);
    let mut prepared = Prepared::build(&mut source, [1; 32], digest, bounds()).unwrap();
    let mut cursor = None;
    loop {
        let page: Result<l::SourcePage<Own>, _> = prepared.page(
            &mut source,
            [2; 16],
            cursor
                .as_ref()
                .map(|s: &busbar_contract::Secret<Vec<u8>, Own>| {
                    s.expose_own(&Own::here()).as_slice()
                }),
            l::Bounds {
                items: 1,
                bytes: 65536,
            },
        );
        match page {
            Err(_) => break,
            Ok(page) => {
                cursor = page.next;
                assert!(cursor.is_some(), "incomplete source must not finish");
            }
        }
    }
}
#[test]
fn retained_origin_digest_and_index_limits_are_mandatory() {
    let (mut source, digest) = source(false);
    assert!(Prepared::build(&mut source, [9; 32], digest, bounds()).is_err());
    assert!(Prepared::build(&mut source, [1; 32], [9; 32], bounds()).is_err());
    let mut tiny = bounds();
    tiny.index_bytes = 128;
    assert!(Prepared::build(&mut source, [1; 32], digest, tiny).is_err());
}
