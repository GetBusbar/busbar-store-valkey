// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Bounded one-pass group index and retained per-group output; no native rescans.
use super::{archive, decode, facts, group, Own, SourceRows};
use busbar_contract::{
    persistence::{
        legacy_row::Row,
        lifecycle::{
            self as l,
            source::{HistoricalFamily, SourceChunk, SourceEvidence},
        },
    },
    Secret,
};

struct Entry {
    family: HistoricalFamily,
    group: [u8; 32],
    ordinal: u64,
}
struct Pending {
    start: usize,
    end: usize,
    group: [u8; 32],
    chunks: Vec<Secret<Vec<u8>, Own>>,
}
pub(crate) struct Prepared {
    entries: Vec<Entry>,
    layout: decode::NativeLayout,
    pending: Option<Pending>,
    semantic_bytes: usize,
    reader: l::SourceReader,
    source_digest: [u8; 32],
}
fn tag(family: HistoricalFamily) -> u8 {
    match family {
        HistoricalFamily::Identity => 0,
        HistoricalFamily::Accounting => 1,
        HistoricalFamily::Archival => 2,
        HistoricalFamily::Audit => 3,
        HistoricalFamily::Evidence => 4,
    }
}
fn classify_error(error: super::Error) -> l::Error {
    match error {
        super::Error::Range => l::Error::Bounds,
        super::Error::Unsupported => l::Error::UnsupportedFormat,
        _ => l::Error::Corrupt,
    }
}
impl Prepared {
    pub(crate) fn build(
        source: &mut dyn SourceRows,
        anchor: [u8; 32],
        digest: [u8; 32],
        bounds: l::InterpretationBounds,
    ) -> Result<Self, l::Error> {
        let row_count = usize::try_from(source.row_count()).map_err(|_| l::Error::Bounds)?;
        let index_limit = bounds.index_bytes as usize / 3;
        if row_count
            .checked_mul(std::mem::size_of::<Entry>())
            .and_then(|v| v.checked_add(16384))
            .is_none_or(|v| v > index_limit)
        {
            return Err(l::Error::Bounds);
        }
        let table = source.header().tables.first().ok_or(l::Error::Corrupt)?;
        let layout = decode::NativeLayout::decode(&table.native_layout).map_err(classify_error)?;
        if layout.source_rdb != digest {
            return Err(l::Error::SourceChanged);
        }
        let reader = super::descriptor(source.header().physical)?;
        decode::verify_inventory(&layout, source, index_limit, anchor)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(row_count)
            .map_err(|_| l::Error::Bounds)?;
        for ordinal in 0..source.row_count() {
            let original = source.read_row(ordinal)?;
            let table = source
                .header()
                .tables
                .get(original.table as usize)
                .ok_or(l::Error::Corrupt)?;
            let columns = table.columns.iter().map(String::as_str).collect::<Vec<_>>();
            let classified = group::classify(
                layout.profile,
                layout.source_db,
                &table.name,
                &columns,
                original.native_key.expose_own(&Own::here()),
                Row::decode(original.value.expose_own(&Own::here()))
                    .map_err(|_| l::Error::Corrupt)?,
            )
            .map_err(classify_error)?;
            entries.push(Entry {
                family: classified.family,
                group: archive::digest(classified.key.expose_own(&Own::here())),
                ordinal,
            });
        }
        entries.sort_unstable_by_key(|entry| (tag(entry.family), entry.group, entry.ordinal));
        Ok(Self {
            entries,
            layout,
            pending: None,
            semantic_bytes: bounds.semantic_bytes as usize,
            reader,
            source_digest: digest,
        })
    }
    fn materialize(&mut self, source: &mut dyn SourceRows, start: usize) -> Result<(), l::Error> {
        let first = self.entries.get(start).ok_or(l::Error::Refused)?;
        if start > 0
            && (
                self.entries[start - 1].family,
                self.entries[start - 1].group,
            ) == (first.family, first.group)
        {
            return Err(l::Error::Refused);
        }
        let mut end = start + 1;
        while end < self.entries.len()
            && (self.entries[end].family, self.entries[end].group) == (first.family, first.group)
        {
            end += 1;
        }
        let mut charge = (end - start).checked_mul(1024).ok_or(l::Error::Bounds)?;
        if charge > self.semantic_bytes {
            return Err(l::Error::Bounds);
        }
        for entry in &self.entries[start..end] {
            charge = charge
                .checked_add(
                    source
                        .row_frame_bytes(entry.ordinal)?
                        .checked_mul(64)
                        .ok_or(l::Error::Bounds)?,
                )
                .ok_or(l::Error::Bounds)?;
            if charge > self.semantic_bytes {
                return Err(l::Error::Bounds);
            }
        }
        let mut originals = Vec::new();
        originals
            .try_reserve_exact(end - start)
            .map_err(|_| l::Error::Bounds)?;
        for entry in &self.entries[start..end] {
            let original = source.read_row(entry.ordinal)?;
            originals.push(original);
        }
        let cells = originals
            .iter()
            .map(|row| {
                decode::physical(
                    Row::decode(row.value.expose_own(&Own::here()))
                        .map_err(|_| l::Error::Corrupt)?,
                )
                .map_err(classify_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let facts = facts::interpret(
            &self.layout,
            first.family,
            &cells,
            l::Bounds {
                items: u32::MAX,
                bytes: u32::try_from(self.semantic_bytes).map_err(|_| l::Error::Bounds)?,
            },
        )?;
        let family = facts.first().ok_or(l::Error::Corrupt)?.family();
        if facts.iter().any(|fact| fact.family() != family) {
            return Err(l::Error::Corrupt);
        }
        let total = facts
            .len()
            .checked_add(originals.len())
            .ok_or(l::Error::Bounds)?;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(total)
            .map_err(|_| l::Error::Bounds)?;
        // An atomic fact or evidence record has stable framing independent of page size.
        // Cached output means the normal sequence parses a complete native group once.
        for fact in facts {
            let chunk = SourceChunk {
                reader: self.reader,
                family,
                group: Secret::held(first.group.to_vec()),
                sequence: chunks.len() as u64,
                complete: false,
                evidence: vec![],
                facts: vec![fact],
            };
            chunks.push(l::codec::encode_source_chunk_owned(
                &chunk,
                l::Bounds {
                    items: u32::MAX,
                    bytes: self.semantic_bytes as u32,
                },
            )?);
        }
        for original in originals {
            let evidence = SourceEvidence {
                table: original.table,
                native_key: original.native_key,
                value_digest: archive::digest(original.value.expose_own(&Own::here())),
            };
            let chunk = SourceChunk::<Own> {
                reader: self.reader,
                family,
                group: Secret::held(first.group.to_vec()),
                sequence: chunks.len() as u64,
                complete: chunks.len() + 1 == total,
                evidence: vec![evidence],
                facts: vec![],
            };
            chunks.push(l::codec::encode_source_chunk_owned(
                &chunk,
                l::Bounds {
                    items: u32::MAX,
                    bytes: self.semantic_bytes as u32,
                },
            )?);
        }
        self.pending = Some(Pending {
            start,
            end,
            group: first.group,
            chunks,
        });
        Ok(())
    }
    pub(crate) fn page<O: busbar_contract::redacted::OwnerSeal>(
        &mut self,
        source: &mut dyn SourceRows,
        snapshot: l::Id,
        cursor: Option<&[u8]>,
        bounds: l::Bounds,
    ) -> Result<l::SourcePage<O>, l::Error> {
        if bounds.items == 0 || bounds.bytes < 256 {
            return Err(l::Error::Bounds);
        }
        let (start, sequence) = match cursor {
            None => (0, 0),
            Some(bytes) if bytes.len() == 48 && bytes[..32] == self.reader.decoder_digest() => (
                usize::try_from(u64::from_le_bytes(
                    bytes[32..40].try_into().map_err(|_| l::Error::Corrupt)?,
                ))
                .map_err(|_| l::Error::Bounds)?,
                usize::try_from(u64::from_le_bytes(
                    bytes[40..48].try_into().map_err(|_| l::Error::Corrupt)?,
                ))
                .map_err(|_| l::Error::Bounds)?,
            ),
            _ => return Err(l::Error::Refused),
        };
        if start == self.entries.len() && sequence == 0 {
            return Ok(l::SourcePage {
                snapshot,
                family: l::INTERPRETED_SOURCE,
                rows: vec![],
                next: None,
                source_digest: self.source_digest,
                coverage_digest: archive::digest(&self.source_digest),
            });
        }
        if self
            .pending
            .as_ref()
            .is_none_or(|pending| pending.start != start)
        {
            self.materialize(source, start)?;
        }
        let pending = self.pending.as_ref().ok_or(l::Error::Corrupt)?;
        let encoded = pending.chunks.get(sequence).ok_or(l::Error::Refused)?;
        if encoded.expose_own(&Own::here()).len() > bounds.bytes as usize - 256 {
            return Err(l::Error::Bounds);
        }
        let next = if sequence + 1 < pending.chunks.len() {
            Some((start, sequence + 1))
        } else if pending.end < self.entries.len() {
            Some((pending.end, 0))
        } else {
            None
        };
        let next = next.map(|(start, sequence)| {
            let mut value = Vec::with_capacity(48);
            value.extend_from_slice(&self.reader.decoder_digest());
            value.extend_from_slice(&(start as u64).to_le_bytes());
            value.extend_from_slice(&(sequence as u64).to_le_bytes());
            Secret::held(value)
        });
        let mut coverage = archive::Hasher::new();
        coverage.update(&self.source_digest);
        coverage.update(&self.reader.decoder_digest());
        coverage.update(&(start as u64).to_le_bytes());
        coverage.update(&(sequence as u64).to_le_bytes());
        coverage.update(encoded.expose_own(&Own::here()));
        Ok(l::SourcePage {
            snapshot,
            family: l::INTERPRETED_SOURCE,
            rows: vec![l::SourceRow {
                table: 0,
                native_key: Secret::held(pending.group.to_vec()),
                value: Secret::held(encoded.expose_own(&Own::here()).clone()),
            }],
            next,
            source_digest: self.source_digest,
            coverage_digest: coverage.finish(),
        })
    }
}
