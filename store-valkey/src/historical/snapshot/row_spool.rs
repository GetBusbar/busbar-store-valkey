// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One verified RDB pass creates owner-private encrypted random-access rows.
//! The original native RDB stays retained and remains the evidence authority.
use super::*;
use archive::{
    spool::{SpoolReader, SpoolWriter},
    VerifiedArchive,
};
use std::io::{Seek, SeekFrom};

pub(super) struct RowSpool {
    archive: VerifiedArchive<SpoolReader>,
    prepared: crate::source_interpretation::Prepared,
    storage_bytes: u64,
    bounds: l::InterpretationBounds,
}
fn archive_error(error: archive::Error) -> l::Error {
    match error {
        archive::Error::Budget | archive::Error::Allocation => l::Error::Bounds,
        archive::Error::Io => l::Error::Unavailable,
        _ => l::Error::Corrupt,
    }
}
impl Snapshot {
    pub(crate) async fn ensure_row_spool(
        &self,
        c: &mut Conn,
        bounds: l::InterpretationBounds,
    ) -> Result<(), l::Error> {
        bounds.validate()?;
        {
            let retained = self.row_spool.lock().map_err(|_| l::Error::Corrupt)?;
            if let Some(spool) = retained.as_ref() {
                if spool.storage_bytes > bounds.storage_bytes
                    || spool.bounds.index_bytes > bounds.index_bytes
                    || spool.bounds.semantic_bytes > bounds.semantic_bytes
                {
                    return Err(l::Error::Bounds);
                }
                return Ok(());
            }
        }
        // Fixed encrypted writer/reader working blocks plus one encoded row.
        let fixed = 4 * CHUNK_BYTES;
        let frame = (bounds.semantic_bytes as usize)
            .checked_sub(fixed)
            .ok_or(l::Error::Bounds)?
            .checked_div(4)
            .ok_or(l::Error::Bounds)?
            .min(self.budget / 4);
        if frame == 0 {
            return Err(l::Error::Bounds);
        }
        let limits = archive::Limits {
            frame_bytes: frame,
            total_bytes: bounds.storage_bytes,
            rows: u64::try_from(bounds.index_bytes as usize / 3 / archive::index_entry_bytes())
                .map_err(|_| l::Error::Bounds)?,
            tables: 1,
            columns: 6,
            index_bytes: bounds.index_bytes as usize / 3,
        };
        let header = archive::Header {
            owner: crate::source_interpretation::SOURCE_OWNER,
            physical: self.capture.physical,
            catalogue_digest: self.digest,
            native_anchor_digest: [0; 32],
            capture: None,
            tables: vec![self.catalogue()?],
        };
        // Writer charges every frame and the footer before issuing any write.
        // Dropping it on any refusal closes the already-anonymous encrypted file.
        let mut writer = archive::Writer::new(
            SpoolWriter::bounded(bounds.storage_bytes).map_err(|_| l::Error::Unavailable)?,
            header,
            limits,
        )
        .map_err(archive_error)?;
        let mut worker = self.start(true)?;
        loop {
            match worker.event(c.wire()).await? {
                Event::Need(index) => self.supply(c, &mut worker, index).await?,
                Event::Failed(error) => return Err(error),
                Event::Row(row) => {
                    writer
                        .write_row(
                            row.table,
                            row.native_key.expose_own(&Own::here()),
                            row.value.expose_own(&Own::here()),
                        )
                        .map_err(archive_error)?;
                    worker.send(Command::Advance)?;
                }
                Event::Complete(summary) => {
                    if summary.digest != self.digest || summary.counts != self.counts {
                        return Err(l::Error::SourceChanged);
                    }
                    break;
                }
            }
        }
        drop(worker);
        let (output, summary) = writer.finish().map_err(archive_error)?;
        let mut input = output.finish().map_err(|_| l::Error::Unavailable)?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|_| l::Error::Unavailable)?;
        let storage_bytes = input.storage_bytes().map_err(|_| l::Error::Unavailable)?;
        let mut verified = archive::read(input, limits).map_err(archive_error)?;
        if verified.summary() != summary {
            return Err(l::Error::Corrupt);
        }
        let prepared = crate::source_interpretation::Prepared::build(
            &mut verified,
            self.capture.anchor,
            self.digest,
            bounds,
        )?;
        let mut retained = self.row_spool.lock().map_err(|_| l::Error::Corrupt)?;
        if retained.is_none() {
            *retained = Some(RowSpool {
                archive: verified,
                prepared,
                storage_bytes,
                bounds,
            });
        }
        Ok(())
    }
    pub(crate) async fn interpreted_page<O: OwnerSeal>(
        &self,
        c: &mut Conn,
        reader: l::SourceReader,
        bounds: l::InterpretationBounds,
        cursor: Option<&[u8]>,
        page_bounds: l::Bounds,
    ) -> Result<l::SourcePage<O>, l::Error> {
        if crate::source_interpretation::descriptor(self.capture.physical)? != reader {
            return Err(l::Error::SourceChanged);
        }
        self.ensure_row_spool(c, bounds).await?;
        let mut held = self.row_spool.lock().map_err(|_| l::Error::Corrupt)?;
        let spool = held.as_mut().ok_or(l::Error::Refused)?;
        spool
            .prepared
            .page(&mut spool.archive, self.id, cursor, page_bounds)
    }
}
