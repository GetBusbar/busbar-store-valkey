// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable native chunk storage with a bounded synchronous-codec bridge.
//! Only the host-owned native operation performs I/O. The one retained codec
//! worker has one input chunk and one event slot; it has no network or runtime.

use crate::{
    historical::Bytes as NativeBytes,
    resp::{cmd, Conn},
};
use busbar_contract::persistence::{
    archive::{self, digest, Hasher},
    legacy_row::{self, Cell},
    lifecycle as l,
};
use busbar_contract::redacted::{OwnerSeal, Secret};
use rdb_parser::{Limits, RdbEntry, RdbReader, RdbValue};
use std::{
    collections::VecDeque,
    io::{self, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread,
};
use zeroize::Zeroizing;

busbar_contract::own_seal!(Own);
mod row_spool;

pub(crate) const CHUNK_BYTES: usize = 65536;
#[derive(Clone)]
pub(crate) struct Capture {
    pub anchor: [u8; 32],
    pub source_db: u32,
    pub databases: u32,
    pub physical: u32,
    pub engine: Vec<u8>,
    pub replication_id: Vec<u8>,
    pub replication_offset: i64,
}
/// Retained native descriptor, never an in-memory copy of the complete RDB.
pub(crate) struct Snapshot {
    pub digest: [u8; 32],
    pub id: l::Id,
    pub capture: Capture,
    pub counts: Vec<u64>,
    upgrade: l::Id,
    length: u64,
    chunks: u64,
    budget: usize,
    worker: Mutex<Option<Worker>>,
    row_spool: Mutex<Option<row_spool::RowSpool>>,
}
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeSnapshot([REDACTED])")
    }
}

fn parser_error(error: rdb_parser::RdbError) -> l::Error {
    match error {
        rdb_parser::RdbError::UnsupportedProfile(_)
        | rdb_parser::RdbError::UnsupportedVersion(_)
        | rdb_parser::RdbError::UnknownType(_) => l::Error::UnsupportedFormat,
        rdb_parser::RdbError::ResourceLimit => l::Error::Bounds,
        rdb_parser::RdbError::Io(error) if error.kind() == io::ErrorKind::OutOfMemory => {
            l::Error::Bounds
        }
        _ => l::Error::Corrupt,
    }
}
pub(crate) fn chunk_key(id: l::Id, index: u64) -> String {
    format!("busbar:v4:bootstrap:rdb:{}:{index}", crate::hex(&id))
}

impl Snapshot {
    /// Full EOF/CRC/raw metadata/count validation before publishing a source.
    /// The descriptor is supplied only by the native fenced capture owner.
    pub(crate) async fn admit(
        c: &mut Conn,
        upgrade: l::Id,
        length: u64,
        sha: [u8; 32],
        capture: Capture,
        budget: usize,
    ) -> Result<Self, l::Error> {
        if capture.anchor == [0; 32]
            || capture.databases == 0
            || capture.databases > 1024
            || capture.source_db >= capture.databases
            || !(6..=9).contains(&capture.physical)
            || sha == [0; 32]
            || length == 0
            || budget < CHUNK_BYTES * 8
        {
            return Err(l::Error::Bounds);
        };
        let chunks = length.div_ceil(CHUNK_BYTES as u64);
        let mut snapshot = Self {
            digest: sha,
            id: sha[..16].try_into().map_err(|_| l::Error::Corrupt)?,
            capture,
            counts: Vec::new(),
            upgrade,
            length,
            chunks,
            budget,
            worker: Mutex::new(None),
            row_spool: Mutex::new(None),
        };
        let mut worker = snapshot.start(false)?;
        loop {
            match worker.event(c.wire()).await? {
                Event::Need(index) => snapshot.supply(c, &mut worker, index).await?,
                Event::Complete(summary) => {
                    if summary.digest != sha {
                        return Err(l::Error::SourceChanged);
                    };
                    snapshot.counts = summary.counts;
                    break;
                }
                Event::Failed(error) => return Err(error),
                Event::Row(_) => return Err(l::Error::Corrupt),
            }
        }
        drop(worker);
        Ok(snapshot)
    }
    fn start(&self, rows: bool) -> Result<Worker, l::Error> {
        // A very long shared key may be repeated across every yielded collection
        // chunk. This finite conservative bound covers that quadratic output
        // work as well as upstream's bounded LZF/compact expansion.
        let work = self
            .length
            .saturating_mul(self.length)
            .saturating_mul(4096)
            .saturating_add(1 << 20);
        let limits = Limits {
            input_bytes: self.length,
            allocated_bytes: (self.budget / 8) as u64,
            metadata_bytes: (self.budget / 32) as u64,
            string_bytes: (self.budget / 16) as u64,
            elements: (self.budget / 1024) as u64,
            work,
        };
        Worker::start(
            self.length,
            self.capture.clone(),
            limits,
            self.budget / 4,
            rows,
            self.digest,
        )
    }
    async fn supply(&self, c: &mut Conn, worker: &mut Worker, index: u64) -> Result<(), l::Error> {
        if index >= self.chunks {
            return Err(l::Error::Corrupt);
        };
        let bytes: NativeBytes = cmd("GET")
            .arg(chunk_key(self.upgrade, index))
            .query(c)
            .await
            .map_err(|_| {
                #[cfg(test)]
                eprintln!("native snapshot chunk fetch failed");
                l::Error::Unavailable
            })?;
        let expected = (self.length - index * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64) as usize;
        if bytes.as_bytes().len() != expected {
            return Err(l::Error::Corrupt);
        };
        worker.send(Command::Chunk(index, bytes.into_guarded()))
    }
    pub(crate) fn retire_worker(&self) -> Result<(), l::Error> {
        let worker = { self.worker.lock().map_err(|_| l::Error::Corrupt)?.take() };
        drop(worker);
        self.row_spool.lock().map_err(|_| l::Error::Corrupt)?.take();
        Ok(())
    }
    pub(crate) fn catalogue(&self) -> Result<archive::Table, l::Error> {
        let mut counts = Zeroizing::new(Vec::new());
        counts
            .try_reserve_exact(self.counts.len() * 8)
            .map_err(|_| l::Error::Bounds)?;
        for count in &self.counts {
            counts.extend_from_slice(&count.to_le_bytes());
        }
        let layout = legacy_row::encode::<Own>(
            &[
                Cell::Text(b"busbar.valkey.native-snapshot/1"),
                Cell::Integer(i64::from(self.capture.source_db)),
                Cell::Integer(i64::from(self.capture.physical)),
                Cell::Blob(&self.capture.engine),
                Cell::Blob(&self.capture.anchor),
                Cell::Blob(&self.digest),
                Cell::Integer(i64::from(self.capture.databases)),
                Cell::Blob(&counts),
            ],
            4096 + counts.len(),
        )
        .map_err(|_| l::Error::Bounds)?;
        Ok(archive::Table {
            name: "valkey".into(),
            columns: ["db", "kind", "absolute_expiry", "key", "position", "value"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            native_layout: layout.expose_own(&Own::here()).clone(),
        })
    }
    pub(crate) async fn page<O: OwnerSeal>(
        &self,
        c: &mut Conn,
        family: l::Id,
        selector: &l::SourceSelector<O>,
        cursor: Option<&[u8]>,
        bounds: l::Bounds,
        owner: &O,
    ) -> Result<l::SourcePage<O>, l::Error> {
        if let l::SourceSelector::Interpret {
            reader,
            bounds: interpretation,
        } = selector
        {
            if family != l::INTERPRETED_SOURCE {
                return Err(l::Error::Refused);
            }
            return self
                .interpreted_page(c, *reader, *interpretation, cursor, bounds)
                .await;
        }
        if bounds.items == 0
            || bounds.bytes == 0
            || bounds.bytes as usize > self.budget / 4
            || bounds.items as usize > bounds.bytes as usize / 32
        {
            return Err(l::Error::Bounds);
        };
        let after = match cursor {
            None => 0,
            Some(v) => u64::from_le_bytes(v.try_into().map_err(|_| l::Error::Corrupt)?),
        };
        let exact = match selector {
            l::SourceSelector::Scan { table: 0 } => None,
            l::SourceSelector::Exact { table: 0, key } => Some(key.expose_own(owner).as_slice()),
            _ => return Err(l::Error::UnsupportedFormat),
        };
        let selection = exact.map(digest);
        let previous = { self.worker.lock().map_err(|_| l::Error::Corrupt)?.take() };
        let mut worker = match previous {
            Some(worker)
                if !worker.finished && worker.selection == selection && worker.cursor == after =>
            {
                worker
            }
            _ => self.start(true)?,
        };
        worker.selection = selection;
        let answer = self
            .page_inner(c, &mut worker, family, exact, after, bounds)
            .await;
        if answer.is_ok() {
            *self.worker.lock().map_err(|_| l::Error::Corrupt)? = Some(worker)
        };
        answer
    }
    async fn page_inner<O: OwnerSeal>(
        &self,
        c: &mut Conn,
        worker: &mut Worker,
        family: l::Id,
        exact: Option<&[u8]>,
        after: u64,
        bounds: l::Bounds,
    ) -> Result<l::SourcePage<O>, l::Error> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(bounds.items as usize)
            .map_err(|_| l::Error::Bounds)?;
        let mut size = 0usize;
        let mut complete = false;
        loop {
            let event = if let Some(row) = worker.pending.take() {
                Event::Row(row)
            } else {
                worker.event(c.wire()).await?
            };
            match event {
                Event::Need(index) => self.supply(c, worker, index).await?,
                Event::Failed(error) => return Err(error),
                Event::Complete(summary) => {
                    if summary.digest != self.digest || summary.counts != self.counts {
                        return Err(l::Error::SourceChanged);
                    };
                    worker.finished = true;
                    complete = true;
                    break;
                }
                Event::Row(row) => {
                    let key = row.native_key.expose_own(&Own::here());
                    if exact.is_some_and(|v| v != key) {
                        worker.send(Command::Advance)?;
                        continue;
                    };
                    let rowbytes = key
                        .len()
                        .checked_add(row.value.expose_own(&Own::here()).len())
                        .ok_or(l::Error::Bounds)?;
                    if rowbytes > bounds.bytes as usize {
                        return Err(l::Error::Bounds);
                    };
                    if worker.cursor >= after
                        && (rows.len() >= bounds.items as usize
                            || size.checked_add(rowbytes).ok_or(l::Error::Bounds)?
                                > bounds.bytes as usize)
                    {
                        worker.pending = Some(row);
                        break;
                    };
                    worker.cursor = worker.cursor.checked_add(1).ok_or(l::Error::Bounds)?;
                    let mut chain = [0u8; 96];
                    chain[..32].copy_from_slice(&worker.coverage);
                    chain[32..64].copy_from_slice(&digest(key));
                    chain[64..].copy_from_slice(&digest(row.value.expose_own(&Own::here())));
                    worker.coverage = digest(&chain);
                    if worker.cursor > after {
                        size += rowbytes;
                        rows.push(l::SourceRow {
                            table: 0,
                            native_key: Secret::held(key.clone()),
                            value: Secret::held(row.value.expose_own(&Own::here()).clone()),
                        })
                    };
                    worker.send(Command::Advance)?;
                }
            }
        }
        if worker.cursor < after {
            return Err(l::Error::SourceChanged);
        };
        let next = if complete {
            None
        } else {
            Some(Secret::held(worker.cursor.to_le_bytes().to_vec()))
        };
        Ok(l::SourcePage {
            snapshot: self.id,
            family,
            rows,
            next,
            source_digest: self.digest,
            coverage_digest: worker.coverage,
        })
    }
}

struct Summary {
    digest: [u8; 32],
    counts: Vec<u64>,
}
enum Event {
    Need(u64),
    Row(l::SourceRow<Own>),
    Complete(Summary),
    Failed(l::Error),
}
enum Command {
    Chunk(u64, Zeroizing<Vec<u8>>),
    Advance,
}
struct Slot {
    event: Option<Event>,
}
struct Bridge {
    slot: Mutex<Slot>,
    changed: Condvar,
    cancelled: AtomicBool,
}
impl Bridge {
    fn emit(&self, event: Event) -> Result<(), l::Error> {
        let mut slot = self.slot.lock().map_err(|_| l::Error::Corrupt)?;
        while slot.event.is_some() && !self.cancelled.load(Ordering::Acquire) {
            slot = self.changed.wait(slot).map_err(|_| l::Error::Corrupt)?;
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(l::Error::Refused);
        };
        slot.event = Some(event);
        self.changed.notify_all();
        Ok(())
    }
}
struct Worker {
    bridge: Arc<Bridge>,
    commands: Option<mpsc::SyncSender<Command>>,
    thread: Option<thread::JoinHandle<()>>,
    pending: Option<l::SourceRow<Own>>,
    cursor: u64,
    selection: Option<[u8; 32]>,
    finished: bool,
    coverage: [u8; 32],
}
impl Worker {
    fn start(
        length: u64,
        capture: Capture,
        limits: Limits,
        frame: usize,
        rows: bool,
        sha: [u8; 32],
    ) -> Result<Self, l::Error> {
        let bridge = Arc::new(Bridge {
            slot: Mutex::new(Slot { event: None }),
            changed: Condvar::new(),
            cancelled: AtomicBool::new(false),
        });
        let (tx, rx) = mpsc::sync_channel(1);
        let shared = bridge.clone();
        let thread = thread::Builder::new()
            .name("valkey-rdb-codec".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decode(shared.clone(), rx, length, capture, limits, frame, rows)
                }));
                match result {
                    Ok(Ok(summary)) => {
                        let _ = shared.emit(Event::Complete(summary));
                    }
                    Ok(Err(error)) => {
                        let _ = shared.emit(Event::Failed(error));
                    }
                    Err(_) => {
                        let _ = shared.emit(Event::Failed(l::Error::Corrupt));
                    }
                }
            })
            .map_err(|_| l::Error::Unavailable)?;
        Ok(Self {
            bridge,
            commands: Some(tx),
            thread: Some(thread),
            pending: None,
            cursor: 0,
            selection: None,
            finished: false,
            coverage: sha,
        })
    }
    fn send(&self, command: Command) -> Result<(), l::Error> {
        self.commands
            .as_ref()
            .ok_or(l::Error::Refused)?
            .try_send(command)
            .map_err(|_| l::Error::Corrupt)
    }
    async fn event(&self, wire: &crate::Wire) -> Result<Event, l::Error> {
        loop {
            let event = {
                let mut slot = self.bridge.slot.lock().map_err(|_| l::Error::Corrupt)?;
                let event = slot.event.take();
                if event.is_some() {
                    self.bridge.changed.notify_all()
                };
                event
            };
            if let Some(event) = event {
                return Ok(event);
            };
            if self.bridge.cancelled.load(Ordering::Acquire) {
                return Err(l::Error::Refused);
            };
            wire.wait_codec().await.map_err(|error| {
                #[cfg(test)]
                eprintln!("native codec wait failed: {error:?}");
                let _ = error;
                l::Error::Unavailable
            })?;
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.bridge.cancelled.store(true, Ordering::Release);
        self.commands.take();
        self.bridge.changed.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct NativeInput {
    bridge: Arc<Bridge>,
    commands: std::rc::Rc<std::cell::RefCell<mpsc::Receiver<Command>>>,
    length: u64,
    position: u64,
    cache: Zeroizing<Vec<u8>>,
    offset: usize,
    next: u64,
    hash: Hasher,
}
impl Read for NativeInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.position == self.length {
            return Ok(0);
        };
        if self.bridge.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "native snapshot cancelled",
            ));
        };
        if self.offset == self.cache.len() {
            self.bridge
                .emit(Event::Need(self.next))
                .map_err(|_| io::Error::other("native input closed"))?;
            let command = self
                .commands
                .borrow_mut()
                .recv()
                .map_err(|_| io::Error::other("native input closed"))?;
            let Command::Chunk(index, bytes) = command else {
                return Err(io::Error::other("native input order"));
            };
            if index != self.next
                || bytes.len() != (self.length - self.position).min(CHUNK_BYTES as u64) as usize
            {
                return Err(io::Error::other("native input length"));
            };
            self.cache = bytes;
            self.offset = 0;
            self.next = self
                .next
                .checked_add(1)
                .ok_or_else(|| io::Error::other("native input overflow"))?;
        }
        let count = out.len().min(self.cache.len() - self.offset);
        out[..count].copy_from_slice(&self.cache[self.offset..self.offset + count]);
        self.offset += count;
        self.position += count as u64;
        self.hash.update(&out[..count]);
        Ok(count)
    }
}
fn decode(
    bridge: Arc<Bridge>,
    rx: mpsc::Receiver<Command>,
    length: u64,
    capture: Capture,
    limits: Limits,
    frame: usize,
    rows: bool,
) -> Result<Summary, l::Error> {
    let commands = std::rc::Rc::new(std::cell::RefCell::new(rx));
    let input = NativeInput {
        bridge: bridge.clone(),
        commands: commands.clone(),
        length,
        position: 0,
        cache: Zeroizing::new(Vec::new()),
        offset: 0,
        next: 0,
        hash: Hasher::new(),
    };
    let mut reader = RdbReader::new_limited(input, limits)
        .map_err(parser_error)?
        .with_max_key_elements(if rows { 1 } else { 1024 });
    match (
        capture.engine.as_slice(),
        &reader.header().magic,
        reader.header().version,
    ) {
        (engine, rdb_parser::RdbMagic::Redis, 11) if engine.starts_with(b"8.1.") => {}
        (b"9.1.3", rdb_parser::RdbMagic::Valkey, 80) => {}
        _ => return Err(l::Error::UnsupportedFormat),
    }
    metadata(&reader, &capture)?;
    let mut counts = vec![0u64; capture.databases as usize];
    let mut marker = None;
    while let Some(entry) = reader.next_protected() {
        let mut entry = entry.map_err(parser_error)?;
        if entry.db >= capture.databases || entry.expiry_ms.is_some_and(|v| v < 0) {
            return Err(l::Error::Corrupt);
        };
        if entry.element_offset.unwrap_or(0) == 0 {
            let count = &mut counts[entry.db as usize];
            *count = count.checked_add(1).ok_or(l::Error::Bounds)?;
        }
        if entry.db == capture.source_db && entry.key == b"busbar:schema" {
            let RdbValue::String(value) = &entry.value else {
                return Err(l::Error::Corrupt);
            };
            let physical = std::str::from_utf8(value)
                .ok()
                .and_then(|v| v.parse::<u32>().ok());
            if marker.replace(physical).is_some() {
                return Err(l::Error::Corrupt);
            };
        }
        if rows {
            for (kind, position, value) in physical(&mut entry)? {
                let native_key = legacy_row::encode::<Own>(
                    &[
                        Cell::Integer(i64::from(entry.db)),
                        Cell::Integer(kind),
                        Cell::Blob(&entry.key),
                        Cell::Blob(&position),
                    ],
                    frame,
                )
                .map_err(|_| l::Error::Bounds)?;
                let value = legacy_row::encode::<Own>(
                    &[
                        Cell::Integer(i64::from(entry.db)),
                        Cell::Integer(kind),
                        Cell::Integer(entry.expiry_ms.unwrap_or(-1)),
                        Cell::Blob(&entry.key),
                        Cell::Blob(&position),
                        Cell::Blob(&value),
                    ],
                    frame,
                )
                .map_err(|_| l::Error::Bounds)?;
                bridge.emit(Event::Row(l::SourceRow {
                    table: 0,
                    native_key,
                    value,
                }))?;
                if !matches!(commands.borrow_mut().recv(), Ok(Command::Advance)) {
                    return Err(l::Error::Refused);
                };
            }
        }
    }
    metadata(&reader, &capture)?;
    if marker != Some(Some(capture.physical)) {
        return Err(l::Error::SourceChanged);
    };
    let input = reader.into_inner();
    if input.position != length {
        return Err(l::Error::Corrupt);
    };
    Ok(Summary {
        digest: input.hash.finish(),
        counts,
    })
}
fn metadata(reader: &RdbReader<NativeInput>, capture: &Capture) -> Result<(), l::Error> {
    let mut version = None;
    let mut redis_version = None;
    let mut replid = None;
    let mut offset = None;
    for (key, value) in &reader.metadata().raw_aux {
        match key.as_slice() {
            b"valkey-ver" => {
                if version.replace(value.as_slice()).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
            b"redis-ver" => {
                if redis_version.replace(value.as_slice()).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
            b"repl-id" => {
                if replid.replace(value.as_slice()).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
            b"repl-offset" => {
                if offset.replace(value.as_slice()).is_some() {
                    return Err(l::Error::Corrupt);
                }
            }
            b"redis-bits" | b"ctime" | b"used-mem" | b"repl-stream-db" | b"aof-base"
            | b"aof-preamble" => {}
            _ => return Err(l::Error::UnsupportedFormat),
        }
    }
    if version.or(redis_version) != Some(capture.engine.as_slice())
        || replid != Some(capture.replication_id.as_slice())
        || offset
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|v| v.parse::<i64>().ok())
            != Some(capture.replication_offset)
    {
        return Err(l::Error::SourceChanged);
    };
    Ok(())
}
type Bytes = Zeroizing<Vec<u8>>;
type Cells = VecDeque<(i64, Bytes, Bytes)>;
fn physical(entry: &mut RdbEntry) -> Result<Cells, l::Error> {
    let mut cells = Cells::new();
    let type_name = match &entry.value {
        RdbValue::String(_) => b"string".as_slice(),
        RdbValue::List(_) => b"list",
        RdbValue::Set(_) => b"set",
        RdbValue::Hash(_) => b"hash",
        RdbValue::SortedSetBytes(_) => b"zset",
        _ => return Err(l::Error::UnsupportedFormat),
    };
    if entry.element_offset.unwrap_or(0) == 0 {
        cells.push_back((0, Bytes::new(Vec::new()), Bytes::new(type_name.to_vec())));
    }
    let mut push = |kind, position, value| {
        cells.push_back((kind, Bytes::new(position), Bytes::new(value)));
    };
    match &mut entry.value {
        RdbValue::String(v) => push(1, Vec::new(), std::mem::take(v)),
        RdbValue::List(v) => {
            for (index, value) in std::mem::take(v).into_iter().enumerate() {
                let index = entry
                    .element_offset
                    .unwrap_or(0)
                    .checked_add(index as u64)
                    .ok_or(l::Error::Bounds)?;
                push(5, index.to_string().into_bytes(), value);
            }
        }
        RdbValue::Set(v) => {
            for member in std::mem::take(v) {
                push(3, member, Vec::new());
            }
        }
        RdbValue::Hash(v) => {
            for mut field in std::mem::take(v) {
                if field.expiry_ms.is_some() {
                    return Err(l::Error::UnsupportedFormat);
                }
                push(
                    2,
                    std::mem::take(&mut field.field),
                    std::mem::take(&mut field.value),
                );
            }
        }
        RdbValue::SortedSetBytes(v) => {
            for (member, score) in std::mem::take(v) {
                push(4, member, score);
            }
        }
        _ => return Err(l::Error::UnsupportedFormat),
    }
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocked_native_codec_cancellation_joins_without_input_or_network() {
        let capture = Capture {
            anchor: [1; 32],
            source_db: 0,
            databases: 1,
            physical: 9,
            engine: b"9.1.3".to_vec(),
            replication_id: vec![b'a'; 40],
            replication_offset: 0,
        };
        let limits = Limits {
            input_bytes: 100,
            allocated_bytes: 4096,
            metadata_bytes: 1024,
            string_bytes: 1024,
            elements: 16,
            work: 4096,
        };
        let worker = Worker::start(100, capture, limits, 4096, false, [2; 32]).unwrap();
        let bridge = worker.bridge.clone();
        let slot = bridge.slot.lock().unwrap();
        let (slot, timeout) = bridge
            .changed
            .wait_timeout_while(slot, std::time::Duration::from_secs(1), |v| {
                v.event.is_none()
            })
            .unwrap();
        assert!(!timeout.timed_out());
        assert!(matches!(slot.event, Some(Event::Need(0))));
        drop(slot);
        let before = std::time::Instant::now();
        drop(worker);
        assert!(before.elapsed() < std::time::Duration::from_secs(1));
    }
}
