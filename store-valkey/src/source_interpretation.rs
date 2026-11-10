// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owning native source reader declaration and historical interpretation.
pub(crate) const SOURCE_OWNER: [u8; 16] = *b"legacy.valkey.v1";
use busbar_contract::persistence::{
    archive,
    lifecycle::{DocumentSemantics, Error as LifecycleError, SourceCodec, SourceReader},
};

pub(crate) fn descriptor(physical: u32) -> Result<SourceReader, LifecycleError> {
    let documents = match physical {
        6 => DocumentSemantics::Historical,
        7..=9 => DocumentSemantics::Current,
        _ => return Err(LifecycleError::UnsupportedFormat),
    };
    SourceReader::new(SourceCodec::HistoricalV1, documents, {
        let mut hash = archive::Hasher::new();
        for bytes in [
            include_bytes!("source_interpretation.rs").as_slice(),
            include_bytes!("source_interpretation/decode.rs").as_slice(),
            include_bytes!("source_interpretation/facts.rs").as_slice(),
            include_bytes!("source_interpretation/group.rs").as_slice(),
            include_bytes!("source_interpretation/stream.rs").as_slice(),
            include_bytes!("historical/snapshot.rs").as_slice(),
            include_bytes!("historical/snapshot/row_spool.rs").as_slice(),
            include_bytes!("historical.rs").as_slice(),
            include_bytes!("v4/bootstrap.rs").as_slice(),
            include_bytes!("../../Cargo.lock").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/compact.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/stream.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/types.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/opcodes.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/intset.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/lib.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/limits.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/lzf.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/listpack.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/crc64.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/ziplist.rs").as_slice(),
            include_bytes!("../../vendor/rdb-parser/src/reader.rs").as_slice(),
        ] {
            hash.update(bytes);
        }
        hash.finish()
    })
}

mod decode;
mod facts;
mod group;
mod stream;
pub(crate) use stream::Prepared;
busbar_contract::own_seal!(Own);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Columns,
    Type,
    Range,
    Invalid,
    Unsupported,
}
pub(crate) trait SourceRows {
    fn header(&self) -> &archive::Header;
    fn row_count(&self) -> u64;
    fn row_frame_bytes(
        &self,
        ordinal: u64,
    ) -> Result<usize, busbar_contract::persistence::lifecycle::Error>;
    fn find_native(
        &self,
        table: u32,
        key: &[u8],
    ) -> Result<Option<u64>, busbar_contract::persistence::lifecycle::Error>;
    fn read_row(
        &mut self,
        ordinal: u64,
    ) -> Result<archive::ArchiveRow<Own>, busbar_contract::persistence::lifecycle::Error>;
}
impl<R: std::io::Read + std::io::Seek> SourceRows for archive::VerifiedArchive<R> {
    fn header(&self) -> &archive::Header {
        self.header()
    }
    fn row_count(&self) -> u64 {
        self.summary().rows
    }
    fn row_frame_bytes(
        &self,
        ordinal: u64,
    ) -> Result<usize, busbar_contract::persistence::lifecycle::Error> {
        self.row_frame_bytes(ordinal).map_err(archive_error)
    }
    fn find_native(
        &self,
        table: u32,
        key: &[u8],
    ) -> Result<Option<u64>, busbar_contract::persistence::lifecycle::Error> {
        self.find_native(table, key).map_err(archive_error)
    }
    fn read_row(
        &mut self,
        ordinal: u64,
    ) -> Result<archive::ArchiveRow<Own>, busbar_contract::persistence::lifecycle::Error> {
        self.read_row_owned(ordinal).map_err(archive_error)
    }
}
fn archive_error(error: archive::Error) -> busbar_contract::persistence::lifecycle::Error {
    use busbar_contract::persistence::lifecycle::Error;
    match error {
        archive::Error::Allocation | archive::Error::Budget => Error::Bounds,
        archive::Error::Io => Error::Unavailable,
        _ => Error::Corrupt,
    }
}
mod hex {
    pub(super) fn encode(bytes: impl AsRef<[u8]>) -> String {
        crate::hex(bytes.as_ref())
    }
    pub(super) fn decode(bytes: impl AsRef<[u8]>) -> Result<Vec<u8>, ()> {
        let bytes = bytes.as_ref();
        if bytes.len() % 2 != 0 {
            return Err(());
        }
        let nibble = |value: u8| match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err(()),
        };
        let mut out = Vec::new();
        out.try_reserve_exact(bytes.len() / 2).map_err(|_| ())?;
        for pair in bytes.as_chunks::<2>().0 {
            out.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
