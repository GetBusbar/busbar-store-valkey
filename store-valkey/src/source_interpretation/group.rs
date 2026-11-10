// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Physical ownership groups, including their native secondary memberships.
use super::{decode as valkey, hex, Error, Own};
use busbar_contract::{
    persistence::{
        legacy_row::{self, Cell, Row},
        lifecycle::source::HistoricalFamily,
    },
    Secret,
};
const IDENTITY: HistoricalFamily = HistoricalFamily::Identity;
const ACCOUNTING: HistoricalFamily = HistoricalFamily::Accounting;
const ARCHIVAL: HistoricalFamily = HistoricalFamily::Archival;
const AUDIT: HistoricalFamily = HistoricalFamily::Audit;
pub(super) struct LogicalGroup {
    pub family: HistoricalFamily,
    pub key: Secret<Vec<u8>, Own>,
}
fn framed(parts: &[&[u8]]) -> Result<Secret<Vec<u8>, Own>, Error> {
    let size = parts
        .iter()
        .try_fold(64usize, |n, p| n.checked_add(p.len() + 16))
        .ok_or(Error::Range)?;
    let value = legacy_row::encode::<Own>(
        &parts.iter().map(|p| Cell::Blob(p)).collect::<Vec<_>>(),
        size,
    )
    .map_err(|_| Error::Range)?;
    Ok(value)
}
pub(super) fn classify(
    profile: valkey::Profile,
    source_db: u32,
    table: &str,
    columns: &[&str],
    native_key: &[u8],
    row: Row<'_>,
) -> Result<LogicalGroup, Error> {
    use valkey::PhysicalKind as Kind;
    if table != "valkey" || columns != valkey::NATIVE_COLUMNS {
        return Err(Error::Columns);
    }
    let cell = valkey::physical(row)?;
    if !valkey::native_identity_matches(cell, native_key) {
        return Err(Error::Invalid);
    }
    let archive = || {
        Ok(LogicalGroup {
            family: ARCHIVAL,
            key: framed(&[b"X", &cell.database.to_be_bytes(), native_key])?,
        })
    };
    if cell.database != source_db || !cell.key.starts_with(b"busbar:") {
        return archive();
    }
    let key = std::str::from_utf8(cell.key).map_err(|_| Error::Type)?;
    let family;
    let group = if let Some(id) = key.strip_prefix("busbar:key:") {
        family = IDENTITY;
        framed(&[b"O", id.as_bytes()])?
    } else if key == "busbar:revision" {
        family = IDENTITY;
        framed(&[b"V"])?
    } else if key == "busbar:keys" || key == "busbar:keys:byrev" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if !matches!(
            (key, cell.kind),
            ("busbar:keys", Kind::Set) | ("busbar:keys:byrev", Kind::SortedSet)
        ) {
            return Err(Error::Type);
        }
        family = IDENTITY;
        framed(&[b"O", cell.position])?
    } else if key == "busbar:creds:byrev" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::SortedSet {
            return Err(Error::Type);
        }
        let (owner, _, _) = valkey::pointer(cell.position)?;
        family = IDENTITY;
        framed(&[b"O", owner.as_bytes()])?
    } else if let Some(id) = key.strip_prefix("busbar:cred:ids:") {
        family = IDENTITY;
        framed(&[b"O", id.as_bytes()])?
    } else if key.starts_with("busbar:cred:id:") || key.starts_with("busbar:cred:pub:") {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::String {
            return Err(Error::Type);
        }
        let (owner, _, _) = valkey::pointer(cell.value)?;
        family = IDENTITY;
        framed(&[b"O", owner.as_bytes()])?
    } else if let Some(rest) = key.strip_prefix("busbar:cred:") {
        let (owner, _, _) = valkey::pointer(rest.as_bytes())?;
        family = IDENTITY;
        framed(&[b"O", owner.as_bytes()])?
    } else if key == "busbar:denylist" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::Set {
            return Err(Error::Type);
        }
        family = IDENTITY;
        framed(&[b"D", cell.position])?
    } else if let Some(subject) = key.strip_prefix("busbar:denylist:") {
        family = IDENTITY;
        framed(&[b"D", subject.as_bytes()])?
    } else if key.starts_with("busbar:usage:") {
        family = ACCOUNTING;
        framed(&[b"U", cell.key])?
    } else if let Some(rest) = key.strip_prefix("busbar:metering:") {
        if rest.contains(':') {
            family = ACCOUNTING;
            framed(&[b"M", cell.key])?
        } else if cell.kind == Kind::Header {
            return archive();
        } else if cell.kind == Kind::Set {
            family = ACCOUNTING;
            framed(&[b"M", cell.position])?
        } else {
            return Err(Error::Type);
        }
    } else if key == "busbar:audit" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::SortedSet {
            return Err(Error::Type);
        }
        let record = valkey::audit(cell.position)?;
        family = AUDIT;
        framed(&[b"A", &record.seq.to_be_bytes()])?
    } else if key.starts_with("busbar:op:") && profile != valkey::Profile::Released6 {
        family = ARCHIVAL;
        framed(&[b"T", cell.key])?
    } else if let Some(rest) = key.strip_prefix("busbar:records:") {
        if profile == valkey::Profile::Released6 {
            return Err(Error::Unsupported);
        }
        if cell.kind == Kind::Header {
            return archive();
        }
        let (schema, suffix) = rest.rsplit_once(':').ok_or(Error::Invalid)?;
        if !matches!(
            (suffix, cell.kind),
            ("v", Kind::Hash) | ("k", Kind::SortedSet)
        ) {
            return Err(Error::Type);
        }
        let schema = hex::decode(schema).map_err(|_| Error::Invalid)?;
        family = ARCHIVAL;
        framed(&[b"R", &schema, cell.position])?
    } else {
        // Development plane record sidecar and body fields share one position.
        if profile != valkey::Profile::Released6
            && key.starts_with("busbar:plane:")
            && cell.kind == Kind::Hash
        {
            let rest = key.strip_prefix("busbar:plane:").ok_or(Error::Invalid)?;
            let (kind, suffix) = rest.split_once(':').ok_or(Error::Invalid)?;
            if matches!(suffix, "rec" | "body") {
                return Ok(LogicalGroup {
                    family: ARCHIVAL,
                    key: framed(&[b"P", kind.as_bytes(), cell.position])?,
                });
            }
        }
        return archive();
    };
    Ok(LogicalGroup { family, key: group })
}
