// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Complete native-group validation before publishing neutral historical facts.
use super::{decode as valkey, hex, Error, Own};
use busbar_contract::{
    persistence::lifecycle::{
        self as l,
        source::{AccountingRole, HistoricalFact, HistoricalFamily, RequestAggregation},
        Bounds,
    },
    records::CredentialSecret,
    Secret,
};
use std::collections::{BTreeMap, BTreeSet};
use valkey::{PhysicalCell, PhysicalKind as Kind};
type Fact = HistoricalFact<Own>;
fn fail(error: Error) -> l::Error {
    match error {
        Error::Range => l::Error::Bounds,
        Error::Unsupported => l::Error::UnsupportedFormat,
        _ => l::Error::Corrupt,
    }
}
fn text(bytes: &[u8]) -> Result<&str, l::Error> {
    std::str::from_utf8(bytes).map_err(|_| l::Error::Corrupt)
}
fn integer(bytes: &[u8]) -> Result<u64, l::Error> {
    text(bytes)?.parse().map_err(|_| l::Error::Corrupt)
}
fn physical_groups<'a>(cells: &[PhysicalCell<'a>]) -> BTreeMap<&'a [u8], Vec<PhysicalCell<'a>>> {
    let mut out = BTreeMap::<&[u8], Vec<PhysicalCell<'a>>>::new();
    for cell in cells {
        out.entry(cell.key).or_default().push(*cell);
    }
    out
}
fn complete<'a>(
    cells: &[PhysicalCell<'a>],
    bounds: Bounds,
) -> Result<valkey::CompleteGroup<'a>, l::Error> {
    valkey::complete_group(cells, bounds.items as usize, bounds.bytes as usize).map_err(fail)
}

fn identity(
    layout: &valkey::NativeLayout,
    cells: &[PhysicalCell<'_>],
    bounds: Bounds,
) -> Result<Vec<Fact>, l::Error> {
    if cells
        .iter()
        .any(|c| c.database != layout.source_db || c.expires_at_ms.is_some())
    {
        return Err(l::Error::Corrupt);
    }
    let by_key = physical_groups(cells);
    if let Some(raw) = by_key.get(b"busbar:revision".as_slice()) {
        if by_key.len() != 1 {
            return Err(l::Error::Corrupt);
        }
        let group = complete(raw, bounds)?;
        if group.header.value != b"string" {
            return Err(l::Error::Corrupt);
        }
        return Ok(vec![HistoricalFact::Revision(integer(group.values[0].1)?)]);
    }
    let mut denied = None;
    let mut denied_member = None;
    for (key, raw) in &by_key {
        if let Some(subject) = text(key)?.strip_prefix("busbar:denylist:") {
            let group = complete(raw, bounds)?;
            if group.header.value != b"string"
                || denied
                    .replace((subject, text(group.values[0].1)?))
                    .is_some()
            {
                return Err(l::Error::Corrupt);
            }
        } else if *key == b"busbar:denylist" {
            for cell in raw {
                if cell.kind != Kind::Set || denied_member.replace(text(cell.position)?).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
        }
    }
    if denied.is_some() || denied_member.is_some() {
        let (subject, reason) = denied.ok_or(l::Error::Corrupt)?;
        if denied_member != Some(subject) || by_key.len() != 2 {
            return Err(l::Error::Corrupt);
        }
        // Valkey stored no creation instant for a denial. Canonical zero is
        // the explicit unstamped legacy discriminator, not an invented time.
        return Ok(vec![HistoricalFact::Denial {
            subject: subject.to_owned(),
            reason: reason.to_owned(),
            created_at: 0,
        }]);
    }
    let mut owner = None;
    let mut credentials = Vec::<CredentialSecret>::new();
    let mut key_member = None;
    let mut key_revision = None;
    let mut slots = BTreeSet::new();
    let mut ids = BTreeMap::new();
    let mut publics = BTreeMap::new();
    let mut revisions = BTreeSet::new();
    for (raw_key, raw) in &by_key {
        let key = text(raw_key)?;
        if let Some(id) = key.strip_prefix("busbar:key:") {
            let group = complete(raw, bounds)?;
            if group.header.value != b"string" || owner.is_some() {
                return Err(l::Error::Corrupt);
            }
            owner = Some(valkey::key(layout.profile, id, group.values[0].1).map_err(fail)?);
        } else if key == "busbar:keys" {
            for cell in raw {
                if cell.kind != Kind::Set || key_member.replace(text(cell.position)?).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
        } else if key == "busbar:keys:byrev" {
            for cell in raw {
                if cell.kind != Kind::SortedSet
                    || key_revision.replace(text(cell.position)?).is_some()
                {
                    return Err(l::Error::Corrupt);
                }
            }
        } else if key == "busbar:creds:byrev" {
            for cell in raw {
                if cell.kind != Kind::SortedSet || !revisions.insert(text(cell.position)?) {
                    return Err(l::Error::Corrupt);
                }
            }
        } else if key.starts_with("busbar:cred:ids:") {
            let group = complete(raw, bounds)?;
            if group.header.value != b"set" {
                return Err(l::Error::Corrupt);
            }
            for (slot, _) in group.values {
                if !slots.insert(text(slot)?) {
                    return Err(l::Error::Corrupt);
                }
            }
        } else if let Some(id) = key.strip_prefix("busbar:cred:id:") {
            for cell in raw {
                if cell.kind != Kind::String || ids.insert(id, cell.value).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
        } else if key.starts_with("busbar:cred:pub:") {
            for cell in raw {
                if cell.kind != Kind::String || publics.insert(key, cell.value).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
        } else if let Some(pointer) = key.strip_prefix("busbar:cred:") {
            let (id, kind, slot) = valkey::pointer(pointer.as_bytes()).map_err(fail)?;
            let group = complete(raw, bounds)?;
            if group.header.value != b"string" {
                return Err(l::Error::Corrupt);
            }
            credentials.push(
                valkey::credential(layout.profile, id, kind, slot, group.values[0].1)
                    .map_err(fail)?,
            );
        } else {
            return Err(l::Error::UnsupportedFormat);
        }
    }
    let owner = owner.ok_or(l::Error::Corrupt)?;
    if key_member != Some(owner.id.as_str())
        || key_revision.is_some_and(|id| id != owner.id)
        || owner.revision != 0 && key_revision.is_none()
    {
        return Err(l::Error::Corrupt);
    }
    let mut facts = Vec::with_capacity(credentials.len() + 1);
    for credential in &credentials {
        let meta = &credential.meta;
        if meta.key_id != owner.id {
            return Err(l::Error::Corrupt);
        }
        let slot = format!("{}:{}", meta.kind, meta.slot);
        let pointer = format!("{}:{}:{}", meta.key_id, meta.kind, meta.slot);
        let public = format!("busbar:cred:pub:{}:{}", meta.kind, meta.public_id);
        if !slots.remove(slot.as_str())
            || ids.remove(meta.id.as_str()) != Some(pointer.as_bytes())
            || publics.remove(public.as_str()) != Some(pointer.as_bytes())
            || meta.revision != 0 && !revisions.remove(pointer.as_str())
        {
            return Err(l::Error::Corrupt);
        }
        revisions.remove(pointer.as_str());
        facts.push(HistoricalFact::Credential {
            meta: meta.clone(),
            envelope: Secret::held(credential.secret.as_bytes().to_vec()),
        });
    }
    if !slots.is_empty() || !ids.is_empty() || !publics.is_empty() || !revisions.is_empty() {
        return Err(l::Error::Corrupt);
    }
    facts.push(HistoricalFact::Key {
        value: owner,
        updated_at: None,
    });
    Ok(facts)
}
fn accounting(
    layout: &valkey::NativeLayout,
    cells: &[PhysicalCell<'_>],
    bounds: Bounds,
) -> Result<Vec<Fact>, l::Error> {
    if cells
        .iter()
        .any(|c| c.database != layout.source_db || c.expires_at_ms.is_some())
    {
        return Err(l::Error::Corrupt);
    }
    let by_key = physical_groups(cells);
    if let Some((key, raw)) = by_key
        .iter()
        .find(|(key, _)| key.starts_with(b"busbar:usage:"))
    {
        if by_key.len() != 1 {
            return Err(l::Error::Corrupt);
        }
        let group = complete(raw, bounds)?;
        if group.header.value != b"hash" {
            return Err(l::Error::Corrupt);
        }
        let rest = text(key)?
            .strip_prefix("busbar:usage:")
            .ok_or(l::Error::Corrupt)?;
        let (bucket, window) = rest.rsplit_once(':').ok_or(l::Error::Corrupt)?;
        let window = window.parse::<u64>().map_err(|_| l::Error::Corrupt)?;
        let ledger = valkey::usage(layout.profile, &group.values).map_err(fail)?;
        return Ok(vec![HistoricalFact::Usage {
            bucket: bucket.to_owned(),
            window,
            model: String::new(),
            requests: RequestAggregation::Dedicated,
            ledger,
            role: AccountingRole::Exact,
        }]);
    }
    let mut primary = None;
    let mut membership = None;
    for (key, raw) in &by_key {
        let rest = text(key)?
            .strip_prefix("busbar:metering:")
            .ok_or(l::Error::UnsupportedFormat)?;
        if let Some((bucket, _)) = rest.split_once(':') {
            if primary.is_some() {
                return Err(l::Error::Corrupt);
            }
            let group = complete(raw, bounds)?;
            if group.header.value != b"hash" {
                return Err(l::Error::Corrupt);
            }
            let row = valkey::metering(layout.profile, &group.values).map_err(fail)?;
            let bucket = integer(bucket.as_bytes())?;
            check_meter_identity(key, bucket, &row, layout.profile)?;
            primary = Some((*key, bucket, row));
        } else {
            for cell in raw {
                if cell.kind != Kind::Set
                    || membership
                        .replace((integer(rest.as_bytes())?, cell.position))
                        .is_some()
                {
                    return Err(l::Error::Corrupt);
                }
            }
        }
    }
    let (key, bucket, row) = primary.ok_or(l::Error::Corrupt)?;
    if membership != Some((bucket, key)) {
        return Err(l::Error::Corrupt);
    }
    Ok(vec![HistoricalFact::Metering {
        bucket,
        row,
        role: AccountingRole::Exact,
    }])
}
fn check_meter_identity(
    key: &[u8],
    bucket: u64,
    row: &busbar_contract::records::MeteringRow,
    profile: valkey::Profile,
) -> Result<(), l::Error> {
    let prefix = format!("busbar:metering:{bucket}:");
    let rest = text(key)?.strip_prefix(&prefix).ok_or(l::Error::Corrupt)?;
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            if !matches!(ch, '\\' | '|') {
                return Err(l::Error::Corrupt);
            }
            fields.last_mut().ok_or(l::Error::Corrupt)?.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            fields.push(String::new());
        } else {
            fields.last_mut().ok_or(l::Error::Corrupt)?.push(ch);
        }
    }
    if escaped
        || !matches!(fields.len(), 3 | 4 | 6)
        || fields[0] != row.key_id
        || fields[1] != row.model
        || fields[2] != row.provider
        || profile == valkey::Profile::Released6 && fields.len() != 3
    {
        return Err(l::Error::Corrupt);
    }
    if fields.len() >= 4 && integer(fields[3].as_bytes())? != row.priced_from_ms
        || fields.len() == 3 && row.priced_from_ms != 0
    {
        return Err(l::Error::Corrupt);
    }
    if fields.len() == 6 && (fields[4] != row.key_group_at_use || fields[5] != row.pricing_version)
    {
        return Err(l::Error::Corrupt);
    }
    Ok(())
}

pub(super) struct ReceiptGroup<'a> {
    operation: [u8; 16],
    body: &'a [u8],
    expires_at_ms: Option<i64>,
    digest: Option<[u8; 32]>,
}
pub(super) fn receipt_group<'a>(
    cells: &[PhysicalCell<'a>],
    bounds: Bounds,
) -> Result<ReceiptGroup<'a>, l::Error> {
    let group = complete(cells, bounds)?;
    if group.header.value != b"hash" || group.values.len() != 1 || group.values[0].0 != b"b" {
        return Err(l::Error::Refused);
    }
    let operation = text(group.header.key)?
        .strip_prefix("busbar:op:")
        .ok_or(l::Error::Corrupt)?;
    if operation.len() != 32
        || !operation
            .bytes()
            .all(|b| matches!(b,b'0'..=b'9'|b'a'..=b'f'))
    {
        return Err(l::Error::Corrupt);
    }
    let operation = hex::decode(operation)
        .map_err(|_| l::Error::Corrupt)?
        .try_into()
        .map_err(|_| l::Error::Corrupt)?;
    let body = group.values[0].1;
    let digest = if body.len() == 32 {
        Some(body.try_into().map_err(|_| l::Error::Corrupt)?)
    } else if body.len() == 64 && body.iter().all(|b| matches!(*b,b'0'..=b'9'|b'a'..=b'f')) {
        Some(
            hex::decode(body)
                .map_err(|_| l::Error::Corrupt)?
                .try_into()
                .map_err(|_| l::Error::Corrupt)?,
        )
    } else {
        None
    };
    Ok(ReceiptGroup {
        operation,
        body,
        expires_at_ms: group.header.expires_at_ms,
        digest,
    })
}
fn plane_group<'a>(
    cells: &[PhysicalCell<'a>],
) -> Result<(String, valkey::Sidecar, &'a str, &'a [u8]), l::Error> {
    if cells.len() != 2 {
        return Err(l::Error::Corrupt);
    }
    let mut metadata = None;
    let mut body = None;
    let mut kind = None;
    let mut position = None;
    for cell in cells {
        if cell.kind != Kind::Hash || cell.expires_at_ms.is_some() {
            return Err(l::Error::Corrupt);
        }
        let (actual_kind, suffix) = valkey::plane_key(cell.key).map_err(fail)?;
        if kind.as_ref().is_some_and(|k| k != &actual_kind)
            || position.is_some_and(|p| p != cell.position)
        {
            return Err(l::Error::Corrupt);
        }
        kind = Some(actual_kind);
        position = Some(cell.position);
        match suffix {
            "rec" => {
                if metadata
                    .replace(valkey::sidecar(cell.value).map_err(fail)?)
                    .is_some()
                {
                    return Err(l::Error::Corrupt);
                }
            }
            "body" => {
                if body.replace(cell.value).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
            _ => return Err(l::Error::UnsupportedFormat),
        }
    }
    let sidecar = metadata.ok_or(l::Error::Corrupt)?;
    let (seq, identity) =
        valkey::plane_position(position.ok_or(l::Error::Corrupt)?).map_err(fail)?;
    if seq != sidecar.seq || identity != sidecar.id && sidecar.parent.as_deref() != Some(identity) {
        return Err(l::Error::Corrupt);
    }
    Ok((
        kind.ok_or(l::Error::Corrupt)?,
        sidecar,
        identity,
        body.ok_or(l::Error::Corrupt)?,
    ))
}

pub(super) fn interpret(
    layout: &valkey::NativeLayout,
    family: HistoricalFamily,
    cells: &[PhysicalCell<'_>],
    bounds: Bounds,
) -> Result<Vec<Fact>, l::Error> {
    if cells.is_empty() {
        return Err(l::Error::Corrupt);
    }
    match family {
        HistoricalFamily::Identity => identity(layout, cells, bounds),
        HistoricalFamily::Accounting => accounting(layout, cells, bounds),
        HistoricalFamily::Audit => cells
            .iter()
            .map(|cell| {
                if cell.database != layout.source_db
                    || cell.kind != Kind::SortedSet
                    || cell.key != b"busbar:audit"
                    || cell.expires_at_ms.is_some()
                {
                    return Err(l::Error::Corrupt);
                }
                valkey::audit(cell.position)
                    .map(HistoricalFact::Audit)
                    .map_err(fail)
            })
            .collect(),
        HistoricalFamily::Archival => archival(layout, cells, bounds),
        HistoricalFamily::Evidence => Err(l::Error::Corrupt),
    }
}
fn archival(
    layout: &valkey::NativeLayout,
    cells: &[PhysicalCell<'_>],
    bounds: Bounds,
) -> Result<Vec<Fact>, l::Error> {
    if cells
        .iter()
        .all(|c| c.database != layout.source_db || !c.key.starts_with(b"busbar:"))
    {
        return Ok(vec![HistoricalFact::EvidenceOnly]);
    }
    if cells.iter().any(|c| c.database != layout.source_db) {
        return Err(l::Error::Corrupt);
    }
    if cells.iter().any(|c| c.key.starts_with(b"busbar:op:")) {
        if layout.profile == valkey::Profile::Released6 {
            return Err(l::Error::UnsupportedFormat);
        }
        let receipt = receipt_group(cells, bounds)?;
        return Ok(vec![HistoricalFact::Receipt {
            operation: receipt.operation,
            body: Secret::held(receipt.body.to_vec()),
            answer: Secret::held(Vec::new()),
            recorded_at: None,
            expires_at_ms: receipt.expires_at_ms,
            historical_digest: receipt.digest,
            completed_shape: receipt.digest.is_some(),
        }]);
    }
    if cells
        .iter()
        .any(|c| c.key.starts_with(b"busbar:records:") && c.kind != Kind::Header)
    {
        if layout.profile == valkey::Profile::Released6 || cells.len() != 2 {
            return Err(l::Error::Corrupt);
        }
        let mut record = None;
        let mut index = None;
        for cell in cells {
            if cell.expires_at_ms.is_some() {
                return Err(l::Error::Corrupt);
            }
            let rest = text(cell.key)?
                .strip_prefix("busbar:records:")
                .ok_or(l::Error::Corrupt)?;
            let (encoded, suffix) = rest.rsplit_once(':').ok_or(l::Error::Corrupt)?;
            let schema = String::from_utf8(hex::decode(encoded).map_err(|_| l::Error::Corrupt)?)
                .map_err(|_| l::Error::Corrupt)?;
            if hex::encode(schema.as_bytes()) != encoded {
                return Err(l::Error::Corrupt);
            }
            match (suffix, cell.kind) {
                ("v", Kind::Hash) if record.is_none() => {
                    record = Some((schema, cell.position, cell.value))
                }
                ("k", Kind::SortedSet) if cell.value == b"0" && index.is_none() => {
                    index = Some((schema, cell.position))
                }
                _ => return Err(l::Error::Corrupt),
            }
        }
        let (schema, key, value) = record.ok_or(l::Error::Corrupt)?;
        if index.as_ref().map(|(s, k)| (s.as_str(), *k)) != Some((schema.as_str(), key)) {
            return Err(l::Error::Corrupt);
        }
        return Ok(vec![HistoricalFact::Record {
            schema,
            key: Secret::held(key.to_vec()),
            value: Secret::held(value.to_vec()),
        }]);
    }
    if cells.iter().any(|c| {
        c.key.starts_with(b"busbar:plane:")
            && c.kind == Kind::Hash
            && valkey::plane_key(c.key).is_ok_and(|(_, suffix)| matches!(suffix, "rec" | "body"))
    }) {
        let (kind, sidecar, identity, body) = plane_group(cells)?;
        let append = match (
            sidecar.parent.as_deref() == Some(identity),
            sidecar.id == identity && sidecar.seq == 0,
        ) {
            (true, true) => None,
            (true, false) => Some(true),
            (false, true) => Some(false),
            (false, false) => return Err(l::Error::Corrupt),
        };
        return Ok(vec![HistoricalFact::History {
            kind,
            id: sidecar.id,
            parent: sidecar.parent,
            sequence: sidecar.seq,
            timestamp: sidecar.ts,
            disposition: sidecar.disposition,
            body: Secret::held(body.to_vec()),
            append,
        }]);
    }
    let mut facts = Vec::new();
    for cell in cells {
        let key = text(cell.key)?;
        if key == "busbar:schema" {
            if cell.expires_at_ms.is_some() {
                return Err(l::Error::Corrupt);
            }
            match cell.kind {
                Kind::Header if cell.value == b"string" => {}
                Kind::String
                    if integer(cell.value)? == u64::from(layout.importer_format().physical) => {}
                _ => return Err(l::Error::Corrupt),
            }
            continue;
        }
        if cell.kind == Kind::Header {
            if cell.expires_at_ms.is_some() && !key.starts_with("busbar:plane:") {
                return Err(l::Error::UnsupportedFormat);
            }
            let known = matches!(
                key,
                "busbar:keys"
                    | "busbar:keys:byrev"
                    | "busbar:creds:byrev"
                    | "busbar:denylist"
                    | "busbar:audit"
            ) || key.starts_with("busbar:cred:id:")
                || key.starts_with("busbar:cred:pub:")
                || key.starts_with("busbar:metering:")
                || layout.profile != valkey::Profile::Released6
                    && (key.starts_with("busbar:records:") || key.starts_with("busbar:plane:"));
            if !known {
                return Err(l::Error::UnsupportedFormat);
            }
            let expected = if matches!(key, "busbar:keys" | "busbar:denylist")
                || key.starts_with("busbar:metering:")
            {
                b"set".as_slice()
            } else if matches!(
                key,
                "busbar:keys:byrev" | "busbar:creds:byrev" | "busbar:audit"
            ) {
                b"zset".as_slice()
            } else if key.starts_with("busbar:cred:") {
                b"string".as_slice()
            } else if key.starts_with("busbar:records:") {
                if key.ends_with(":k") {
                    b"zset".as_slice()
                } else if key.ends_with(":v") {
                    b"hash".as_slice()
                } else {
                    return Err(l::Error::UnsupportedFormat);
                }
            } else {
                let (_, suffix) = valkey::plane_key(cell.key).map_err(fail)?;
                if suffix.starts_with("tok:") {
                    b"string".as_slice()
                } else if matches!(suffix, "rec" | "body" | "pcount") {
                    b"hash".as_slice()
                } else if suffix == "byts" || suffix.starts_with("idx:") {
                    b"zset".as_slice()
                } else {
                    return Err(l::Error::UnsupportedFormat);
                }
            };
            if cell.value != expected {
                return Err(l::Error::Corrupt);
            }
            continue;
        }
        if layout.profile != valkey::Profile::Released6 && key.starts_with("busbar:plane:") {
            let (kind, suffix) = valkey::plane_key(cell.key).map_err(fail)?;
            if let Some(token) = suffix.strip_prefix("tok:") {
                if cell.kind != Kind::String {
                    return Err(l::Error::Corrupt);
                }
                let token =
                    zeroize::Zeroizing::new(hex::decode(token).map_err(|_| l::Error::Corrupt)?);
                text(&token)?;
                let expires = integer(cell.value)?;
                if let Some(physical) = cell.expires_at_ms {
                    let expected = expires
                        .checked_add(1)
                        .and_then(|v| v.checked_mul(1000))
                        .and_then(|v| i64::try_from(v).ok())
                        .ok_or(l::Error::Bounds)?;
                    if physical != expected {
                        return Err(l::Error::Corrupt);
                    }
                }
                facts.push(HistoricalFact::Token {
                    kind,
                    token: Secret::held(token.to_vec()),
                    expires_at: expires,
                });
                continue;
            }
            if matches!(
                (suffix, cell.kind),
                ("byts", Kind::SortedSet) | ("pcount", Kind::Hash)
            ) || suffix.starts_with("idx:") && cell.kind == Kind::SortedSet
            {
                continue;
            }
        }
        return Err(l::Error::UnsupportedFormat);
    }
    if facts.is_empty() {
        facts.push(HistoricalFact::EvidenceOnly);
    }
    Ok(facts)
}
