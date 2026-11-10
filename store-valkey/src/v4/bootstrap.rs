// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native pre-open lifecycle. Inspection never calls ordinary initialization.
//! Account ownership is established from existing scoped native grants, never
//! inferred from an empty client list or the names of currently stored keys.

use super::*;
use crate::historical::snapshot;
use crate::historical::{Bytes, Raw};
use crate::Wire;
use busbar_contract::persistence::{
    archive,
    legacy_row::{self, Cell},
    lifecycle as l,
};
use zeroize::Zeroizing;

const SOURCE: &[u8] = b"busbar:schema";
const OWNER: [u8; 16] = crate::source_interpretation::SOURCE_OWNER;
const JOURNAL: &str = "busbar:v4:bootstrap";

#[derive(Default)]
pub(super) struct Session {
    inspected: Option<Facts>,
    snapshot: Option<Arc<snapshot::Snapshot>>,
    control: Option<Control>,
    token: Zeroizing<Vec<u8>>,
}
#[derive(Clone)]
pub(super) struct Facts {
    pub source: l::SourceIdentity,
    pub engine: Vec<u8>,
    pub run_id: Vec<u8>,
    pub db: u32,
    pub databases: u32,
    pub physical: u32,
    pub bounds: l::Bounds,
}

fn fail(error: crate::resp::RedisError, line: u32) -> l::Error {
    #[cfg(test)]
    eprintln!("native bootstrap command unavailable at line {line}: {error:?}");
    let _ = (error, line);
    l::Error::Unavailable
}
fn uncertain(error: crate::resp::RedisError) -> l::Error {
    #[cfg(test)]
    eprintln!("native bootstrap publication uncertain: {error:?}");
    let _ = error;
    l::Error::Unknown
}
fn info<'a>(bytes: &'a [u8], key: &[u8]) -> Result<&'a [u8], l::Error> {
    let mut found = None;
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(key)
            && line.get(key.len()) == Some(&b':')
            && found.replace(&line[key.len() + 1..]).is_some()
        {
            return Err(l::Error::Corrupt);
        }
    }
    found.ok_or(l::Error::MissingCapability)
}
fn number(bytes: &[u8]) -> Result<u32, l::Error> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(l::Error::Corrupt)
}
fn value_bytes(v: &Value) -> Result<&[u8], l::Error> {
    match v {
        Value::Data(v) => Ok(v),
        Value::Status(v) => Ok(v.as_bytes()),
        _ => Err(l::Error::Corrupt),
    }
}
fn field<'a>(value: &'a Value, name: &[u8]) -> Result<&'a Value, l::Error> {
    let Value::Array(rows) = value else {
        return Err(l::Error::Corrupt);
    };
    if rows.len() % 2 != 0 {
        return Err(l::Error::Corrupt);
    };
    let mut result = None;
    for row in rows.as_chunks::<2>().0 {
        if value_bytes(&row[0])? == name && result.replace(&row[1]).is_some() {
            return Err(l::Error::Corrupt);
        }
    }
    result.ok_or(l::Error::Corrupt)
}
fn array(v: &Value) -> Result<&[Value], l::Error> {
    match v {
        Value::Array(v) => Ok(v),
        _ => Err(l::Error::Corrupt),
    }
}

impl OwnBackend {
    pub(super) fn bootstrap_native(
        &self,
        op: &mut Op<'_>,
        request: &l::Request<Own>,
    ) -> Step<Result<l::Response<Own>, l::Error>> {
        let request = copy_request(request);
        let me = self.clone();
        busbar_contract::abi::sdk::store::wire::drive_channels(
            op,
            &self.0.bootstrap_channels,
            move |mut wires| {
                Box::pin(async move {
                    let capture = wires.pop().ok_or(l::Error::Corrupt)?;
                    let wire = wires.pop().ok_or(l::Error::Corrupt)?;
                    let mut c =
                        me.0.transport
                            .conn(wire, Some("bootstrap"))
                            .await
                            .map_err(|_| l::Error::Unavailable)?;
                    c.reply_budget(me.0.budget);
                    let result = me.bootstrap_request(&mut c, capture, request).await;
                    c.settle();
                    result
                })
            },
        )
    }
    pub(super) fn connect_native_prepared(
        &self,
        op: &mut Op<'_>,
        binding: &l::OpenBinding,
    ) -> Step<Result<(), String>> {
        let me = self.clone();
        let binding = binding.clone();
        let pool = me.0.transport.pool().clone();
        drive_kept(op, &pool, move |wire| {
            Box::pin(async move {
                let mut c =
                    me.0.transport
                        .conn(wire, Some("prepared-open"))
                        .await
                        .map_err(|e| e.0)?;
                c.reply_budget(me.0.budget);
                let bounds = l::Bounds {
                    items: 1024,
                    bytes: u32::try_from(me.0.budget).unwrap_or(u32::MAX),
                };
                if let l::OpenBinding::Recovery(recovery) = &binding {
                    c.wire()
                        .reconnect()
                        .await
                        .map_err(|_| "fresh native recovery connection unavailable")?;
                    me.0.transport
                        .handshake(&mut c)
                        .await
                        .map_err(|_| "fresh native recovery authentication refused")?;

                    let facts = me
                        .facts(&mut c, bounds)
                        .await
                        .map_err(|_| "native recovery source unavailable")?;
                    let control = me
                        .control(&mut c)
                        .await
                        .map_err(|_| "native recovery selector unavailable")?
                        .ok_or("missing native upgrade")?;
                    let info = control
                        .info(me.0.local)
                        .map_err(|_| "invalid native recovery target")?;
                    if control.stage < 5
                        || control.id != recovery.upgrade
                        || info.dataset != recovery.target
                        || control.recovery != recovery.activation_receipt_digest
                        || archive::digest(&control.target) != recovery.selector_digest
                        || control.run_id != facts.run_id
                    {
                        return Err("native recovery binding changed".into());
                    };
                    let selected: Bytes = cmd("GET")
                        .arg(META)
                        .query(&mut c)
                        .await
                        .map_err(|_| "native recovery selector unavailable")?;
                    if selected.as_bytes() != control.target {
                        return Err("native recovery selector mismatch".into());
                    };
                    if *me.0.info.get_or_init(|| info) != info {
                        return Err("native recovery dataset changed".into());
                    };
                    me.0.bootstrap
                        .lock()
                        .map_err(|_| "native recovery session poisoned")?
                        .control = Some(control);
                    return Ok(());
                }
                let actual = me
                    .inspect(&mut c, bounds)
                    .await
                    .map_err(|_| "native prepared open inspection refused")?;
                match binding {
                    l::OpenBinding::Empty if actual.state == l::InspectionState::Empty => {}
                    l::OpenBinding::Current {
                        source,
                        admission_marker_digest,
                    } if actual.state == l::InspectionState::Current => {
                        if actual.source.as_ref() != Some(&source)
                            || actual
                                .admission_marker
                                .as_ref()
                                .map(|v| archive::digest(v.expose_own(&Own::here())))
                                != Some(admission_marker_digest)
                        {
                            return Err("native prepared open identity changed".into());
                        }
                    }
                    _ => return Err("native prepared recovery binding unavailable".into()),
                }
                let result = me.connected(&mut c).await;
                c.settle();
                result
            })
        })
    }
    async fn bootstrap_request(
        &self,
        c: &mut Conn,
        capture: Wire,
        request: l::Request<Own>,
    ) -> Result<l::Response<Own>, l::Error> {
        match request {
            l::Request::Inspect { bounds } => {
                self.inspect(c, bounds).await.map(l::Response::Inspected)
            }
            l::Request::BeginOrResume {
                expected_source,
                route_digest,
                target_format,
                operation_id,
            } => self
                .begin(
                    c,
                    capture,
                    expected_source,
                    route_digest,
                    target_format,
                    operation_id,
                )
                .await
                .map(l::Response::Begun),
            l::Request::SourcePage {
                upgrade,
                snapshot,
                family,
                selector,
                cursor,
                bounds,
            } => {
                self.verify(c, &upgrade).await?;
                let native = {
                    self.0
                        .bootstrap
                        .lock()
                        .map_err(|_| l::Error::Corrupt)?
                        .snapshot
                        .clone()
                        .ok_or(l::Error::Refused)?
                };
                if native.id != snapshot {
                    return Err(l::Error::SourceChanged);
                };
                native
                    .page(
                        c,
                        family,
                        &selector,
                        cursor
                            .as_ref()
                            .map(|v| v.expose_own(&Own::here()).as_slice()),
                        bounds,
                        &Own::here(),
                    )
                    .await
                    .map(l::Response::SourcePage)
            }
            l::Request::CheckFence { upgrade } => {
                self.verify(c, &upgrade).await.map(l::Response::Fence)
            }
            l::Request::Target { upgrade } => {
                self.verify(c, &upgrade).await?;
                let state = self.0.bootstrap.lock().map_err(|_| l::Error::Corrupt)?;
                let control = state.control.as_ref().ok_or(l::Error::Refused)?;
                let info = control.info(self.0.local)?;
                if *self.0.info.get_or_init(|| info) != info {
                    return Err(l::Error::Refused);
                };
                Ok(l::Response::Target(l::TargetBinding {
                    upgrade: control.id,
                    info,
                    binding: Secret::held(state.token.to_vec()),
                }))
            }
            l::Request::Finish {
                upgrade,
                activation_receipt,
            } => self.finish_native(c, &upgrade, activation_receipt).await,
        }
    }
    async fn facts(&self, c: &mut Conn, bounds: l::Bounds) -> Result<Facts, l::Error> {
        if bounds.bytes == 0 || bounds.items == 0 || bounds.bytes as usize > self.0.budget {
            return Err(l::Error::Bounds);
        };
        let server: Bytes = cmd("INFO")
            .arg("server")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let server = server.as_bytes();
        let engine = info(server, b"valkey_version")?.to_vec();
        if !engine.starts_with(b"8.1.") && engine != b"9.1.3" {
            return Err(l::Error::UnsupportedFormat);
        };
        let run_id = info(server, b"run_id")?.to_vec();
        if run_id.len() != 40 || !run_id.iter().all(u8::is_ascii_hexdigit) {
            return Err(l::Error::Corrupt);
        };
        let topology: Bytes = cmd("INFO")
            .arg("replication")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if info(topology.as_bytes(), b"role")? != b"master"
            || info(topology.as_bytes(), b"connected_slaves")? != b"0"
        {
            return Err(l::Error::MissingCapability);
        }
        let cluster: Bytes = cmd("INFO")
            .arg("cluster")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if info(cluster.as_bytes(), b"cluster_enabled")? != b"0" {
            return Err(l::Error::MissingCapability);
        };
        self.0
            .transport
            .assert_noeviction(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?;
        let status: Bytes = cmd("INFO")
            .arg("persistence")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if info(status.as_bytes(), b"loading")? != b"0"
            || info(status.as_bytes(), b"rdb_bgsave_in_progress")? != b"0"
        {
            return Err(l::Error::Busy);
        };
        let modules = Raw(cmd("MODULE")
            .arg("LIST")
            .query::<Value>(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?);
        let modules = array(&modules.0)?;
        if modules.len() > 1 {
            return Err(l::Error::UnsupportedFormat);
        };
        for module in modules {
            if engine != b"9.1.3"
                || array(module)?.len() != 8
                || value_bytes(field(module, b"name")?)? != b"lua"
                || value_bytes(field(module, b"path")?)? != b"lua"
                || !matches!(field(module, b"ver")?, Value::Int(1))
                || !array(field(module, b"args")?)?.is_empty()
            {
                return Err(l::Error::UnsupportedFormat);
            };
        }

        if self.0.local {
            let config: Vec<(String, String)> = cmd("CONFIG")
                .arg("GET")
                .arg("appendonly")
                .arg("appendfsync")
                .arg("no-appendfsync-on-rewrite")
                .query(c)
                .await
                .map_err(|_| l::Error::MissingCapability)?;
            let status: Bytes = cmd("INFO")
                .arg("persistence")
                .query(c)
                .await
                .map_err(|error| fail(error, line!()))?;
            if ![
                ("appendonly", "yes"),
                ("appendfsync", "always"),
                ("no-appendfsync-on-rewrite", "no"),
            ]
            .iter()
            .all(|(k, v)| config.iter().any(|(a, b)| a == k && b == v))
                || info(status.as_bytes(), b"aof_enabled")? != b"1"
                || info(status.as_bytes(), b"aof_last_write_status")? != b"ok"
            {
                return Err(l::Error::MissingCapability);
            };
        }
        let config = Raw(cmd("CONFIG")
            .arg("GET")
            .arg("databases")
            .query::<Value>(c)
            .await
            .map_err(|error| fail(error, line!()))?);
        let databases = number(value_bytes(field(&config.0, b"databases")?)?)?;
        let db = u32::try_from(self.0.transport.inner.target.db).map_err(|_| l::Error::Corrupt)?;
        if databases == 0 || databases > 1024 || db >= databases {
            return Err(l::Error::Bounds);
        };
        let keyspace: Bytes = cmd("INFO")
            .arg("keyspace")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        volatile_fields(keyspace.as_bytes(), databases, &engine)?;
        let marker: Option<Bytes> = cmd("GET")
            .arg(SOURCE)
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let physical = match marker {
            None => 0,
            Some(v) => number(v.as_bytes())?,
        };
        let mut anchor = Zeroizing::new(Vec::new());
        anchor
            .try_reserve_exact(run_id.len() + 4)
            .map_err(|_| l::Error::Bounds)?;
        anchor.extend_from_slice(&run_id);
        anchor.extend_from_slice(&db.to_le_bytes());
        let anchor = archive::digest(&anchor);
        let catalogue = layout(db, physical, databases, &engine)?;
        let catalogue_digest = archive::digest(&catalogue.native_layout);
        let source = l::SourceIdentity {
            native_anchor: anchor,
            dataset: DatasetId(anchor[..16].try_into().map_err(|_| l::Error::Corrupt)?),
            format: if (6..=9).contains(&physical) {
                Some(l::Format {
                    owner: OWNER,
                    physical,
                    logical: 1,
                    codec: 1,
                })
            } else {
                None
            },
            catalogue_digest,
            layout_digest: catalogue_digest,
        };
        Ok(Facts {
            source,
            engine,
            run_id,
            db,
            databases,
            physical,
            bounds,
        })
    }
    async fn check_instance(&self, c: &mut Conn, expected: &Facts) -> Result<(), l::Error> {
        let current = self.facts(c, expected.bounds).await?;
        if current.run_id != expected.run_id
            || current.db != expected.db
            || current.databases != expected.databases
            || current.physical != expected.physical
            || current.engine != expected.engine
        {
            return Err(l::Error::SourceChanged);
        };
        Ok(())
    }
    async fn inspect(
        &self,
        c: &mut Conn,
        bounds: l::Bounds,
    ) -> Result<l::Inspection<Own>, l::Error> {
        let mut facts = self.facts(c, bounds).await?;
        let metadata: Option<Bytes> = cmd("GET")
            .arg(META)
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let pending: Option<Bytes> = cmd("GET")
            .arg(JOURNAL)
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let count: u64 = cmd("DBSIZE")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let mut admission = None;
        let state = if pending
            .as_ref()
            .is_some_and(|v| Control::decode(v.as_bytes()).map_or(true, |v| v.stage < 6))
        {
            let retained = Control::decode(pending.as_ref().ok_or(l::Error::Corrupt)?.as_bytes())?;
            l::InspectionState::InProgress(crate::source_interpretation::descriptor(
                retained.physical,
            )?)
        } else if let Some(bytes) = metadata {
            let native = metadata::decode(bytes.as_bytes()).map_err(|_| l::Error::Corrupt)?;
            if native.physical_version != 1 {
                return Err(l::Error::UnsupportedFormat);
            };
            facts.source.dataset = native.dataset;
            facts.source.format = Some(l::CORE_FORMAT);
            admission = Some(Secret::held(bytes.as_bytes().to_vec()));
            l::InspectionState::Current
        } else if count == 0 {
            l::InspectionState::Empty
        } else if (6..=9).contains(&facts.physical) {
            l::InspectionState::Legacy(crate::source_interpretation::descriptor(facts.physical)?)
        } else {
            l::InspectionState::Unsupported
        };
        let catalogue = inspection_catalogue(
            state,
            facts.db,
            facts.physical,
            facts.databases,
            &facts.engine,
        )?;
        if matches!(state, l::InspectionState::InProgress(_)) {
            let retained = Control::decode(pending.as_ref().ok_or(l::Error::Corrupt)?.as_bytes())?;
            facts.source = retained.source();
        }
        let source = if state == l::InspectionState::Empty {
            None
        } else {
            Some(facts.source.clone())
        };
        let capabilities = if matches!(
            state,
            l::InspectionState::Empty | l::InspectionState::Current
        ) {
            vec![l::NativeCapability::CurrentOpen]
        } else if matches!(
            state,
            l::InspectionState::Legacy(_) | l::InspectionState::InProgress(_)
        ) && self.preflight_authority(c, &facts, false).await.is_ok()
        {
            vec![
                l::NativeCapability::Snapshot,
                l::NativeCapability::PersistentFence,
                l::NativeCapability::Resume,
                l::NativeCapability::InactiveTarget,
            ]
        } else {
            Vec::new()
        };
        self.0
            .bootstrap
            .lock()
            .map_err(|_| l::Error::Corrupt)?
            .inspected = Some(facts);
        Ok(l::Inspection {
            state,
            source,
            admission_marker: admission,
            catalogue,
            capabilities,
        })
    }
    async fn preflight_authority(
        &self,
        c: &mut Conn,
        facts: &Facts,
        persist: bool,
    ) -> Result<Authority, l::Error> {
        if !(6..=9).contains(&facts.physical) {
            return Err(l::Error::UnsupportedFormat);
        };
        if self.0.budget < snapshot::CHUNK_BYTES * 8 {
            return Err(l::Error::Bounds);
        };
        let who: Bytes = cmd("ACL")
            .arg("WHOAMI")
            .query(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?;
        let users = Raw(cmd("ACL")
            .arg("USERS")
            .query::<Value>(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?);
        if array(&users.0)?.len() > 1024 {
            return Err(l::Error::Bounds);
        };
        let mut fence = None;
        for user in array(&users.0)? {
            let user = value_bytes(user)?;
            let grants = Raw(cmd("ACL")
                .arg("GETUSER")
                .arg(user)
                .query::<Value>(c)
                .await
                .map_err(|_| l::Error::MissingCapability)?);
            let enabled = array(field(&grants.0, b"flags")?)?
                .iter()
                .any(|v| value_bytes(v) == Ok(b"on"));
            if !enabled {
                continue;
            };
            if !array(field(&grants.0, b"selectors")?)?.is_empty() {
                return Err(l::Error::MissingCapability);
            };
            let keys = value_bytes(field(&grants.0, b"keys")?)?;
            if user == who.as_bytes() {
                // Admit only the two supported native scopes; never infer
                // authority from the current key inventory or account name.
                fence = Some(FenceKind::admit(keys).ok_or(l::Error::MissingCapability)?);
            } else {
                // Preserve other accounts untouched. Only simple disjoint key
                // scopes can currently be proved not to grant source writes.
                for pattern in keys.split(|v| *v == b' ').filter(|v| !v.is_empty()) {
                    let pattern = pattern.strip_prefix(b"%R~");
                    if pattern.is_some() {
                        continue;
                    };
                    return Err(l::Error::MissingCapability);
                }
            }
        }
        let fence = fence.ok_or(l::Error::MissingCapability)?;
        let configuration = Raw(cmd("CONFIG")
            .arg("GET")
            .arg("aclfile")
            .query::<Value>(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?);
        let aclfile = !value_bytes(field(&configuration.0, b"aclfile")?)?.is_empty();
        let server: Bytes = cmd("INFO")
            .arg("server")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if !aclfile && info(server.as_bytes(), b"config_file")?.is_empty() {
            return Err(l::Error::MissingCapability);
        };
        let mut dry = cmd("ACL");
        dry.arg("DRYRUN")
            .arg(who.as_bytes())
            .arg("ACL")
            .arg("SETUSER")
            .arg(who.as_bytes())
            .arg("resetkeys")
            .arg(fence.rules());
        let allowed: Bytes = dry
            .query(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?;
        if allowed.as_bytes() != b"OK" {
            return Err(l::Error::MissingCapability);
        };
        let authority = Authority {
            user: who.as_bytes().to_vec(),
            aclfile,
            fence,
        };
        // Persist the unchanged native policy first. A failed persistence check
        // cannot leave a partially installed fence or converted target behind.
        if persist {
            authority.persist(c).await?;
        }
        Ok(authority)
    }
}
fn inspection_catalogue(
    state: l::InspectionState,
    db: u32,
    physical: u32,
    databases: u32,
    engine: &[u8],
) -> Result<Vec<archive::Table>, l::Error> {
    // Empty inspection has no source catalogue; the lifecycle codec enforces this.
    if state == l::InspectionState::Empty {
        Ok(Vec::new())
    } else {
        Ok(vec![layout(db, physical, databases, engine)?])
    }
}

fn layout(
    db: u32,
    physical: u32,
    databases: u32,
    engine: &[u8],
) -> Result<archive::Table, l::Error> {
    let bytes = legacy_row::encode::<Own>(
        &[
            Cell::Text(b"busbar.valkey.native-session/1"),
            Cell::Integer(i64::from(db)),
            Cell::Integer(i64::from(physical)),
            Cell::Blob(engine),
            Cell::Integer(i64::from(databases)),
        ],
        4096,
    )
    .map_err(|_| l::Error::Bounds)?;
    Ok(archive::Table {
        name: "valkey".into(),
        columns: ["db", "kind", "absolute_expiry", "key", "position", "value"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        native_layout: bytes.expose_own(&Own::here()).clone(),
    })
}
fn copy_request(r: &l::Request<Own>) -> l::Request<Own> {
    r.clone()
}

#[derive(Clone, Copy)]
enum FenceKind {
    Scoped,
    Broad,
}
impl FenceKind {
    fn admit(keys: &[u8]) -> Option<Self> {
        match keys {
            b"~busbar:*" | b"%R~busbar:* %W~busbar:*" => Some(Self::Scoped),
            b"~*" | b"%R~* %W~*" | b"%W~* %R~*" => Some(Self::Broad),
            _ => Self::fenced(keys),
        }
    }
    fn fenced(keys: &[u8]) -> Option<Self> {
        if keys == Self::Scoped.canonical() {
            Some(Self::Scoped)
        } else if keys == Self::Broad.canonical() {
            Some(Self::Broad)
        } else {
            None
        }
    }
    fn rules(self) -> &'static [&'static str] {
        match self {
            Self::Scoped => &["%R~busbar:*", "~busbar:v4:*"],
            // Exact byte-glob complement of busbar:, plus the new target.
            // Short keys end before the prefix; each remaining pattern names
            // the first mismatching byte. Reads retain the original full scope.
            // Read/write commands require both rights in one native pattern,
            // so these grants include reads already covered by %R~*.
            Self::Broad => &[
                "%R~*",
                "~",
                "~b",
                "~bu",
                "~bus",
                "~busb",
                "~busba",
                "~busbar",
                "~[^b]*",
                "~b[^u]*",
                "~bu[^s]*",
                "~bus[^b]*",
                "~busb[^a]*",
                "~busba[^r]*",
                "~busbar[^:]*",
                "~busbar:v4:*",
            ],
        }
    }
    fn canonical(self) -> &'static [u8] {
        match self {
            Self::Scoped => b"%R~busbar:* ~busbar:v4:*",
            Self::Broad => b"%R~* ~ ~b ~bu ~bus ~busb ~busba ~busbar ~[^b]* ~b[^u]* ~bu[^s]* ~bus[^b]* ~busb[^a]* ~busba[^r]* ~busbar[^:]* ~busbar:v4:*",
        }
    }
}
struct Authority {
    user: Vec<u8>,
    aclfile: bool,
    fence: FenceKind,
}
impl Authority {
    async fn persist(&self, c: &mut Conn) -> Result<(), l::Error> {
        let command = if self.aclfile {
            let mut v = cmd("ACL");
            v.arg("SAVE");
            v
        } else {
            let mut v = cmd("CONFIG");
            v.arg("REWRITE");
            v
        };
        let answer: Bytes = command
            .query(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?;
        if answer.as_bytes() != b"OK" {
            return Err(l::Error::MissingCapability);
        };
        Ok(())
    }
    async fn install(&self, c: &mut Conn) -> Result<(), l::Error> {
        let answer: Bytes = cmd("ACL")
            .arg("SETUSER")
            .arg(&self.user)
            .arg("resetkeys")
            .arg(self.fence.rules())
            .query(c)
            .await
            .map_err(uncertain)?;
        if answer.as_bytes() != b"OK" {
            return Err(l::Error::Unknown);
        };
        self.persist(c).await.map_err(|_| l::Error::Unknown)
    }
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    version: u32,
    id: [u8; 16],
    route: [u8; 32],
    format_owner: [u8; 16],
    format_axes: [u32; 3],
    source_anchor: [u8; 32],
    source_dataset: [u8; 16],
    catalogue: [u8; 32],
    layout: [u8; 32],
    physical: u32,
    db: u32,
    databases: u32,
    engine: Vec<u8>,
    run_id: Vec<u8>,
    target: Vec<u8>,
    acl_digest: [u8; 32],
    client: u64,
    clients: Vec<u64>,
    token: [u8; 32],
    stage: u32,
    snapshot: [u8; 32],
    length: u64,
    chunks: u64,
    replid: Vec<u8>,
    offset: i64,
    user: Vec<u8>,
    aclfile: bool,
    recovery: [u8; 32],
    completed: [u8; 32],
}
impl Control {
    fn source(&self) -> l::SourceIdentity {
        l::SourceIdentity {
            native_anchor: self.source_anchor,
            dataset: DatasetId(self.source_dataset),
            format: Some(l::Format {
                owner: OWNER,
                physical: self.physical,
                logical: 1,
                codec: 1,
            }),
            catalogue_digest: self.catalogue,
            layout_digest: self.layout,
        }
    }
    fn info(&self, local: bool) -> Result<BackendInfo, l::Error> {
        let mut info = metadata::decode(&self.target).map_err(|_| l::Error::Corrupt)?;
        info.durability = if local {
            Durability::Local
        } else {
            Durability::Ephemeral
        };
        Ok(info)
    }
    fn encoded(&self) -> Result<Zeroizing<Vec<u8>>, l::Error> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| l::Error::Corrupt)
    }
    fn decode(bytes: &[u8]) -> Result<Self, l::Error> {
        if bytes.len() > 65536 {
            return Err(l::Error::Bounds);
        };
        let value: Self = serde_json::from_slice(bytes).map_err(|_| l::Error::Corrupt)?;
        if value.version != 1
            || value.id == [0; 16]
            || value.route == [0; 32]
            || value.token == [0; 32]
            || value.stage > 6
            || !(6..=9).contains(&value.physical)
            || value.databases == 0
            || value.databases > 1024
            || value.db >= value.databases
            || value.clients.len() > 1024
            || value.target.len() != 64
            || value.engine.len() > 32
            || value.run_id.len() != 40
            || value.user.len() > 256
            || (value.chunks > 0
                && value.chunks
                    != value.length.div_ceil(snapshot::CHUNK_BYTES as u64))
        {
            return Err(l::Error::Corrupt);
        }
        Ok(value)
    }
}
const CAS: &str = "if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end redis.call('SET',KEYS[1],ARGV[2]) return 1";
const CLAIM: &str = "if redis.call('EXISTS',KEYS[1])~=0 then return 0 end redis.call('SET',KEYS[1],ARGV[1]) return 1";
const CHUNK: &str = "if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end redis.call('MSET',KEYS[1],ARGV[2],KEYS[2],ARGV[3]) return 1";
impl OwnBackend {
    async fn control(&self, c: &mut Conn) -> Result<Option<Control>, l::Error> {
        let bytes: Option<Bytes> = cmd("GET")
            .arg(JOURNAL)
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        bytes.map(|v| Control::decode(v.as_bytes())).transpose()
    }
    async fn cas(&self, c: &mut Conn, old: &Control, new: &Control) -> Result<(), l::Error> {
        let before = old.encoded()?;
        let after = new.encoded()?;
        let ok: u64 = cmd("EVAL")
            .arg(CAS)
            .arg(1)
            .arg(JOURNAL)
            .arg(&*before)
            .arg(&*after)
            .query(c)
            .await
            .map_err(uncertain)?;
        if ok != 1 {
            return Err(l::Error::Busy);
        };
        Ok(())
    }
    async fn acl_inventory(&self, c: &mut Conn) -> Result<[u8; 32], l::Error> {
        let users = Raw(cmd("ACL")
            .arg("USERS")
            .query::<Value>(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?);
        let users = array(&users.0)?;
        if users.len() > 1024 {
            return Err(l::Error::Bounds);
        };
        let mut names = Vec::new();
        names
            .try_reserve_exact(users.len())
            .map_err(|_| l::Error::Bounds)?;
        for user in users {
            let name = value_bytes(user)?;
            if name.len() > 256 {
                return Err(l::Error::Bounds);
            };
            names.push(name)
        }
        names.sort_unstable();
        if names.windows(2).any(|v| v[0] == v[1]) {
            return Err(l::Error::Corrupt);
        };
        let mut hash = archive::Hasher::new();
        for name in names {
            hash.update(&(name.len() as u64).to_le_bytes());
            hash.update(name);
            let grants = Raw(cmd("ACL")
                .arg("GETUSER")
                .arg(name)
                .query::<Value>(c)
                .await
                .map_err(|_| l::Error::MissingCapability)?);
            hash_value(&mut hash, &grants.0, 0)?;
        }
        Ok(hash.finish())
    }
    async fn client_list(&self, c: &mut Conn) -> Result<Bytes, l::Error> {
        cmd("CLIENT")
            .arg("LIST")
            .query(c)
            .await
            .map_err(|_| l::Error::MissingCapability)
    }
    async fn begin(
        &self,
        c: &mut Conn,
        capture: Wire,
        expected: l::SourceIdentity,
        route: [u8; 32],
        format: l::Format,
        operation: [u8; 16],
    ) -> Result<l::Upgrade<Own>, l::Error> {
        let facts = self
            .0
            .bootstrap
            .lock()
            .map_err(|_| l::Error::Corrupt)?
            .inspected
            .clone()
            .ok_or(l::Error::Refused)?;
        if facts.source != expected
            || route == [0; 32]
            || operation == [0; 16]
            || format.physical != 1
        {
            return Err(l::Error::SourceChanged);
        };
        self.check_instance(c, &facts).await?;
        let previous = self.control(c).await?;
        // A recorded exact restricted policy is admitted on resume. The control
        // route, physical identity and target must still match below.
        let authority = self.preflight_authority(c, &facts, true).await?;
        let client: u64 = cmd("CLIENT")
            .arg("ID")
            .query(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?;
        let clients = self.client_list(c).await?;
        let mut token = Zeroizing::new(vec![0u8; 32]);
        getrandom::fill(&mut token).map_err(|_| l::Error::Unavailable)?;
        let hash = archive::digest(&token);
        let mut control = if let Some(old) = previous {
            if old.route != route
                || old.format_owner != format.owner
                || old.format_axes != [format.physical, format.logical, format.codec]
                || old.db != facts.db
                || old.databases != facts.databases
                || old.physical != facts.physical
                || old.engine != facts.engine
            {
                return Err(l::Error::SourceChanged);
            };
            let own_token = {
                let state = self.0.bootstrap.lock().map_err(|_| l::Error::Corrupt)?;
                if state.control.as_ref().is_some_and(|v| v.id == old.id)
                    && archive::digest(&state.token) == old.token
                {
                    Some(state.token.to_vec())
                } else {
                    None
                }
            };
            // Native client IDs are scoped to one server run and can be
            // reused by a different connection after a configuration restart.
            let same_instance = old.run_id == facts.run_id;
            if same_instance && old.client == client {
                if let Some(owned) = own_token {
                    token.clear();
                    token.extend_from_slice(&owned);
                } else {
                    return Err(l::Error::Busy);
                };
                old
            } else {
                if same_instance
                    && native_clients(clients.as_bytes())?
                        .iter()
                        .any(|v| v.id == old.client)
                {
                    return Err(l::Error::Busy);
                };
                let mut next = old.clone();
                next.client = client;
                next.clients.clear();
                next.token = hash;
                next.run_id = facts.run_id.clone();
                self.cas(c, &old, &next).await?;
                next
            }
        } else {
            // Refuse active legacy sessions before creating durable ownership.
            // A preceding EXEC/script has completed before these native commands;
            // queued or reconnected writes are denied by the installed key ACL.
            if native_clients(clients.as_bytes())?
                .iter()
                .any(|v| v.id != client)
            {
                return Err(l::Error::Busy);
            };
            let mut id = [0u8; 16];
            getrandom::fill(&mut id).map_err(|_| l::Error::Unavailable)?;
            if id == [0; 16] {
                return Err(l::Error::Unavailable);
            };
            let value = Control {
                version: 1,
                id,
                route,
                format_owner: format.owner,
                format_axes: [format.physical, format.logical, format.codec],
                source_anchor: facts.source.native_anchor,
                source_dataset: facts.source.dataset.0,
                catalogue: facts.source.catalogue_digest,
                layout: facts.source.layout_digest,
                physical: facts.physical,
                db: facts.db,
                databases: facts.databases,
                engine: facts.engine.clone(),
                run_id: facts.run_id.clone(),
                target: persistent(self.0.proposed),
                acl_digest: [0; 32],
                client,
                clients: Vec::new(),
                token: hash,
                stage: 0,
                snapshot: [0; 32],
                length: 0,
                chunks: 0,
                replid: Vec::new(),
                offset: 0,
                user: authority.user.clone(),
                aclfile: authority.aclfile,
                recovery: [0; 32],
                completed: [0; 32],
            };
            let encoded = value.encoded()?;
            let ok: u64 = cmd("EVAL")
                .arg(CLAIM)
                .arg(1)
                .arg(JOURNAL)
                .arg(&*encoded)
                .query(c)
                .await
                .map_err(uncertain)?;
            if ok != 1 {
                return Err(l::Error::Busy);
            };
            value
        };
        {
            let mut state = self.0.bootstrap.lock().map_err(|_| l::Error::Corrupt)?;
            state.token = token;
            state.control = Some(control.clone());
        }
        if control.stage < 1 {
            authority.install(c).await?;
            let mut next = control.clone();
            next.stage = 1;
            next.acl_digest = self.acl_inventory(c).await?;
            self.cas(c, &control, &next).await?;
            control = next;
        }
        self.policy(c, &control).await?;
        if control.stage < 2 {
            for index in 0..control.chunks {
                let _: u64 = cmd("DEL")
                    .arg(snapshot::chunk_key(control.id, index))
                    .query(c)
                    .await
                    .map_err(uncertain)?;
            }
            if control.chunks != 0 {
                let mut next = control.clone();
                next.chunks = 0;
                self.cas(c, &control, &next).await?;
                control = next;
            }
            self.capture_native(c, capture, &facts, &mut control)
                .await?;
        }
        let snapshot = Arc::new(
            snapshot::Snapshot::admit(
                c,
                control.id,
                control.length,
                control.snapshot,
                snapshot::Capture {
                    anchor: control.source_anchor,
                    source_db: control.db,
                    databases: control.databases,
                    physical: control.physical,
                    engine: control.engine.clone(),
                    replication_id: control.replid.clone(),
                    replication_offset: control.offset,
                },
                self.0.budget,
            )
            .await?,
        );
        if control.stage < 3 {
            let mut next = control.clone();
            next.stage = 3;
            self.cas(c, &control, &next).await?;
            control = next;
        }
        if control.stage < 4 {
            let target = target_meta(control.id);
            let old: Option<Bytes> = cmd("GET")
                .arg(&target)
                .query(c)
                .await
                .map_err(|error| fail(error, line!()))?;
            match old {
                None => {
                    let _: Bytes = cmd("SET")
                        .arg(&target)
                        .arg(&control.target)
                        .query(c)
                        .await
                        .map_err(uncertain)?;
                }
                Some(bytes) if bytes.as_bytes() == control.target => {}
                _ => return Err(l::Error::Corrupt),
            }
            let mut next = control.clone();
            next.stage = 4;
            self.cas(c, &control, &next).await?;
            control = next;
        }
        self.policy(c, &control).await?;
        let snapshot_id = snapshot.id;
        let catalogue = vec![snapshot.catalogue()?];
        let response = l::Upgrade {
            reference: l::UpgradeRef {
                id: control.id,
                authority: Secret::held(
                    self.0
                        .bootstrap
                        .lock()
                        .map_err(|_| l::Error::Corrupt)?
                        .token
                        .to_vec(),
                ),
            },
            source: control.source(),
            snapshot: snapshot_id,
            target: control.info(self.0.local)?,
            native_step: u64::from(control.stage),
            catalogue,
        };
        let mut state = self.0.bootstrap.lock().map_err(|_| l::Error::Corrupt)?;
        state.snapshot = Some(snapshot);
        state.control = Some(control);
        Ok(response)
    }
    async fn policy(&self, c: &mut Conn, control: &Control) -> Result<FenceKind, l::Error> {
        let topology: Bytes = cmd("INFO")
            .arg("replication")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if info(topology.as_bytes(), b"role")? != b"master"
            || info(topology.as_bytes(), b"connected_slaves")? != b"0"
        {
            return Err(l::Error::SourceChanged);
        };
        if control.acl_digest == [0; 32] || self.acl_inventory(c).await? != control.acl_digest {
            return Err(l::Error::SourceChanged);
        };
        let grants = Raw(cmd("ACL")
            .arg("GETUSER")
            .arg(&control.user)
            .query::<Value>(c)
            .await
            .map_err(|_| l::Error::MissingCapability)?);
        let fence = FenceKind::fenced(value_bytes(field(&grants.0, b"keys")?)?)
            .ok_or(l::Error::SourceChanged)?;
        if !array(field(&grants.0, b"selectors")?)?.is_empty() {
            return Err(l::Error::SourceChanged);
        };
        let server: Bytes = cmd("INFO")
            .arg("server")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if info(server.as_bytes(), b"run_id")? != control.run_id {
            return Err(l::Error::SourceChanged);
        };
        let current = self.control(c).await?.ok_or(l::Error::SourceChanged)?;
        if current.id != control.id
            || current.token != control.token
            || current.client != control.client
        {
            return Err(l::Error::Busy);
        };
        let client: u64 = cmd("CLIENT")
            .arg("ID")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if client != control.client {
            return Err(l::Error::Busy);
        };
        Ok(fence)
    }
    async fn verify(
        &self,
        c: &mut Conn,
        reference: &l::UpgradeRef<Own>,
    ) -> Result<l::Fence, l::Error> {
        let (control, id) = {
            let state = self.0.bootstrap.lock().map_err(|_| l::Error::Corrupt)?;
            let control = state.control.clone().ok_or(l::Error::Refused)?;
            if reference.id != control.id
                || archive::digest(reference.authority.expose_own(&Own::here())) != control.token
            {
                return Err(l::Error::Refused);
            };
            (
                control,
                state.snapshot.as_ref().ok_or(l::Error::Refused)?.id,
            )
        };
        let fence = self.policy(c, &control).await?;
        let current = self.control(c).await?.ok_or(l::Error::SourceChanged)?;
        let clients = self.client_list(c).await?;
        if native_clients(clients.as_bytes())?
            .iter()
            .any(|v| v.id != control.client && !current.clients.contains(&v.id))
        {
            return Err(l::Error::Busy);
        };
        self.0
            .bootstrap
            .lock()
            .map_err(|_| l::Error::Corrupt)?
            .control = Some(current);
        Ok(l::Fence {
            upgrade: control.id,
            source: control.source(),
            enforcement_digest: archive::digest(fence.canonical()),
            observation_digest: archive::digest(clients.as_bytes()),
            snapshot: id,
        })
    }
    async fn capture_native(
        &self,
        control_conn: &mut Conn,
        wire: Wire,
        facts: &Facts,
        control: &mut Control,
    ) -> Result<(), l::Error> {
        let mut c = self
            .0
            .transport
            .conn(wire, Some("native-capture"))
            .await
            .map_err(|_| l::Error::Unavailable)?;
        struct Discard(Wire);
        impl Drop for Discard {
            fn drop(&mut self) {
                self.0.discard();
            }
        }
        let _discard = Discard(c.wire().clone());
        c.reply_budget(self.0.budget.min(65536));
        self.check_instance(&mut c, facts).await?;
        let reply: Bytes = cmd("PSYNC")
            .arg("?")
            .arg(-1)
            .query(&mut c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let mut pieces = reply.as_bytes().split(|v| *v == b' ');
        if pieces.next() != Some(b"FULLRESYNC".as_slice()) {
            return Err(l::Error::Corrupt);
        };
        let replid = pieces.next().ok_or(l::Error::Corrupt)?.to_vec();
        let offset = pieces
            .next()
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or(l::Error::Corrupt)?;
        if replid.len() != 40
            || !replid.iter().all(u8::is_ascii_hexdigit)
            || offset < 0
            || pieces.next().is_some()
        {
            return Err(l::Error::Corrupt);
        };
        let length = c
            .native_rdb_length()
            .await
            .map_err(|error| fail(error, line!()))?;
        let mut remaining = length;
        let mut hash = archive::Hasher::new();
        let mut index = 0u64;
        while remaining != 0 {
            let count = remaining.min(snapshot::CHUNK_BYTES as u64) as usize;
            let bytes = c
                .native_rdb_chunk(count)
                .await
                .map_err(|error| fail(error, line!()))?;
            let mut next = control.clone();
            next.chunks = index.checked_add(1).ok_or(l::Error::Bounds)?;
            let before = control.encoded()?;
            let after = next.encoded()?;
            let ok: u64 = cmd("EVAL")
                .arg(CHUNK)
                .arg(2)
                .arg(JOURNAL)
                .arg(snapshot::chunk_key(control.id, index))
                .arg(&*before)
                .arg(&*after)
                .arg(&*bytes)
                .query(control_conn)
                .await
                .map_err(|error| {
                    #[cfg(test)]
                    eprintln!("native snapshot chunk publication index {index}");
                    uncertain(error)
                })?;
            if ok != 1 {
                return Err(l::Error::Busy);
            };
            hash.update(&bytes);
            *control = next;
            remaining -= count as u64;
            index += 1;
        }
        c.wire().close().await;
        let mut next = control.clone();
        next.length = length;
        next.snapshot = hash.finish();
        next.replid = replid;
        next.offset = offset;
        next.stage = 2;
        self.cas(control_conn, control, &next).await?;
        *control = next;
        Ok(())
    }
}

fn target_meta(id: [u8; 16]) -> String {
    format!("busbar:v4:bootstrap:target:{}", hex(&id))
}
struct NativeClient {
    id: u64,
}
fn native_clients(bytes: &[u8]) -> Result<Vec<NativeClient>, l::Error> {
    let mut clients = Vec::new();
    for line in bytes.split(|v| *v == b'\n').filter(|v| !v.is_empty()) {
        let mut id = None;
        for field in line.split(|v| *v == b' ') {
            if let Some(value) = field.strip_prefix(b"id=") {
                if id
                    .replace(
                        std::str::from_utf8(value)
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .ok_or(l::Error::Corrupt)?,
                    )
                    .is_some()
                {
                    return Err(l::Error::Corrupt);
                };
            }
        }
        clients.try_reserve_exact(1).map_err(|_| l::Error::Bounds)?;
        clients.push(NativeClient {
            id: id.ok_or(l::Error::Corrupt)?,
        });
    }
    Ok(clients)
}

impl OwnBackend {
    /// Target requests retain the native owner token and use their inactive
    /// metadata address. The existing primitive publication remains one MSET.
    pub(super) async fn native_eval(
        &self,
        c: &mut Conn,
        source: &str,
        args: &[Vec<u8>],
    ) -> Result<Zeroizing<Vec<Vec<u8>>>, crate::resp::RedisError> {
        let binding = {
            let state = self
                .0
                .bootstrap
                .lock()
                .map_err(|_| crate::resp::RedisError::refused("native lifecycle poisoned"))?;
            state
                .control
                .as_ref()
                .filter(|control| control.stage < 6)
                .map(|control| (control.id, control.token))
        };
        let Some((id, token)) = binding else {
            return super::eval(c, source, args).await;
        };
        self.authorize_target(c, id, token)
            .await
            .map_err(|_| crate::resp::RedisError::refused("V4_SOURCE_CHANGED"))?;
        const GUARD: &str = "local raw=redis.call('GET',KEYS[2]); if not raw then return redis.error_reply('V4_SOURCE_CHANGED') end local c=cjson.decode(raw); local token=ARGV[#ARGV]; table.remove(ARGV); if c.stage<4 or #c.token~=32 or string.char(unpack(c.token))~=token then return redis.error_reply('V4_SOURCE_CHANGED') end\n";
        cmd("EVAL")
            .arg(format!("{GUARD}{COMMON}\n{source}"))
            .arg(2)
            .arg(target_meta(id))
            .arg(JOURNAL)
            .arg(args)
            .arg(token.as_slice())
            .query(c)
            .await
            .map(Zeroizing::new)
    }
    async fn authorize_target(
        &self,
        c: &mut Conn,
        id: [u8; 16],
        token: [u8; 32],
    ) -> Result<(), l::Error> {
        let server: Bytes = cmd("INFO")
            .arg("server")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let current = self.control(c).await?.ok_or(l::Error::SourceChanged)?;
        if current.id != id || current.token != token {
            return Err(l::Error::SourceChanged);
        };
        if current.stage == 6 {
            let selected: Bytes = cmd("GET")
                .arg(META)
                .query(c)
                .await
                .map_err(|error| fail(error, line!()))?;
            if selected.as_bytes() != current.target {
                return Err(l::Error::SourceChanged);
            };
            self.0
                .bootstrap
                .lock()
                .map_err(|_| l::Error::Corrupt)?
                .control = Some(current);
            return Ok(());
        }
        if info(server.as_bytes(), b"run_id")? != current.run_id {
            return Err(l::Error::SourceChanged);
        };
        let client: u64 = cmd("CLIENT")
            .arg("ID")
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        if client == current.client || current.clients.contains(&client) {
            return Ok(());
        };
        if current.clients.len() >= 1024 {
            return Err(l::Error::Bounds);
        };
        let mut next = current.clone();
        next.clients
            .try_reserve_exact(1)
            .map_err(|_| l::Error::Bounds)?;
        next.clients.push(client);
        self.cas(c, &current, &next).await?;
        self.0
            .bootstrap
            .lock()
            .map_err(|_| l::Error::Corrupt)?
            .control = Some(next);
        Ok(())
    }
    async fn finish_native(
        &self,
        c: &mut Conn,
        reference: &l::UpgradeRef<Own>,
        receipt: l::ActivationReceipt<Own>,
    ) -> Result<l::Response<Own>, l::Error> {
        self.verify(c, reference).await?;
        let control = self
            .0
            .bootstrap
            .lock()
            .map_err(|_| l::Error::Corrupt)?
            .control
            .clone()
            .ok_or(l::Error::Refused)?;
        let info = control.info(self.0.local)?;
        if receipt.attempt.dataset != info.dataset
            || receipt.candidate_fingerprint == [0; 32]
            || receipt.checkpoint_value_digest == [0; 32]
            || receipt.checkpoint_address.namespace == control::GENERATION_NAMESPACE.0
        {
            return Err(l::Error::Refused);
        }
        let base = prefix(info);
        let attempt = receipt.attempt;
        let receipt_key = format!(
            "{base}o:{}:{}",
            hex(&attempt.writer),
            hex(&attempt.operation)
        );
        let checkpoint_key = record(
            &base,
            receipt.checkpoint_address.namespace,
            &receipt.checkpoint_address.key,
        );
        let observed: Vec<Bytes> = cmd("MGET")
            .arg(&receipt_key)
            .arg(&checkpoint_key)
            .query(c)
            .await
            .map_err(|error| fail(error, line!()))?;
        let [native_receipt, checkpoint] = observed.as_slice() else {
            return Err(l::Error::Corrupt);
        };
        let original = native_receipt.as_bytes();
        let checkpoint = checkpoint.as_bytes();
        if original.len() < 52
            || &original[..4] != b"BVR1"
            || original[4..36] != receipt.candidate_fingerprint
            || original[36..44] != attempt.execution_epoch.to_le_bytes()
            || &original[52..] != receipt.original_result.expose_own(&Own::here())
            || checkpoint.first() != Some(&1)
            || archive::digest(&checkpoint[1..]) != receipt.checkpoint_value_digest
        {
            return Err(l::Error::Refused);
        }
        let activation = archive::digest(original);
        let mut next = control.clone();
        match receipt.phase {
            l::CompletionPhase::Activation => {
                if control.stage != 4 && control.stage != 5 {
                    return Err(l::Error::Refused);
                };
                if control.stage == 5 && control.recovery != activation {
                    return Err(l::Error::SourceChanged);
                };
                next.stage = 5;
                next.recovery = activation;
            }
            l::CompletionPhase::Complete => {
                if control.stage != 5 && control.stage != 6 {
                    return Err(l::Error::Refused);
                };
                if control.stage == 6 && control.completed != activation {
                    return Err(l::Error::SourceChanged);
                };
                next.stage = 6;
                next.completed = activation;
            }
        }
        let old = control.encoded()?;
        let new = next.encoded()?;
        const FINISH: &str = "if redis.call('GET',KEYS[1])~=ARGV[1] or redis.call('GET',KEYS[2])~=ARGV[3] or redis.call('GET',KEYS[3])~=ARGV[4] then return 0 end redis.call('MSET',KEYS[1],ARGV[2],KEYS[4],ARGV[5]) return 1";
        let ok: u64 = cmd("EVAL")
            .arg(FINISH)
            .arg(4)
            .arg(JOURNAL)
            .arg(receipt_key)
            .arg(checkpoint_key)
            .arg(META)
            .arg(&*old)
            .arg(&*new)
            .arg(original)
            .arg(checkpoint)
            .arg(&control.target)
            .query(c)
            .await
            .map_err(uncertain)?;
        if ok != 1 {
            return Err(l::Error::SourceChanged);
        };
        let snapshot = {
            let mut state = self.0.bootstrap.lock().map_err(|_| l::Error::Corrupt)?;
            state.control = Some(next.clone());
            state.snapshot.clone()
        };
        if receipt.phase == l::CompletionPhase::Complete {
            if let Some(snapshot) = snapshot {
                snapshot.retire_worker()?;
            }
        }
        let recovery = l::RecoveryReady {
            upgrade: next.id,
            target: info.dataset,
            activation_receipt_digest: next.recovery,
            selector_digest: archive::digest(&next.target),
        };
        Ok(match receipt.phase {
            l::CompletionPhase::Activation => l::Response::RecoveryReady(recovery),
            l::CompletionPhase::Complete => l::Response::ServingReady(l::ServingReady {
                recovery,
                completed_checkpoint_digest: receipt.checkpoint_value_digest,
            }),
        })
    }
}

fn volatile_fields(bytes: &[u8], databases: u32, engine: &[u8]) -> Result<(), l::Error> {
    for line in bytes.split(|v| *v == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        };
        let (db, values) = line.split_at(
            line.iter()
                .position(|v| *v == b':')
                .ok_or(l::Error::Corrupt)?,
        );
        let db = number(db.strip_prefix(b"db").ok_or(l::Error::Corrupt)?)?;
        if db >= databases {
            return Err(l::Error::SourceChanged);
        };
        let mut found = false;
        for value in values[1..].split(|v| *v == b',') {
            if let Some(count) = value.strip_prefix(b"keys_with_volatile_items=") {
                if found {
                    return Err(l::Error::Corrupt);
                };
                found = true;
                if number(count)? != 0 {
                    return Err(l::Error::UnsupportedFormat);
                };
            }
        }
        if !found && !engine.starts_with(b"8.1.") {
            return Err(l::Error::MissingCapability);
        };
    }
    Ok(())
}

fn hash_value(hash: &mut archive::Hasher, value: &Value, depth: u32) -> Result<(), l::Error> {
    if depth > 32 {
        return Err(l::Error::Bounds);
    };
    match value {
        Value::Nil => hash.update(&[0]),
        Value::Int(v) => {
            hash.update(&[1]);
            hash.update(&v.to_le_bytes())
        }
        Value::Data(v) => {
            hash.update(&[2]);
            hash.update(&(v.len() as u64).to_le_bytes());
            hash.update(v)
        }
        Value::Status(v) => {
            hash.update(&[3]);
            hash.update(&(v.len() as u64).to_le_bytes());
            hash.update(v.as_bytes())
        }
        Value::Array(v) => {
            hash.update(&[4]);
            hash.update(&(v.len() as u64).to_le_bytes());
            for item in v {
                hash_value(hash, item, depth + 1)?;
            }
        }
        Value::Error(_) => return Err(l::Error::Corrupt),
    }
    Ok(())
}

#[cfg(test)]
mod inspection_tests {
    use super::*;

    #[test]
    fn empty_native_inspection_encodes_without_a_source_catalogue() {
        let bounds = l::Bounds {
            items: 16,
            bytes: 4096,
        };
        let response = l::Response::<Own>::Inspected(l::Inspection {
            state: l::InspectionState::Empty,
            source: None,
            admission_marker: None,
            catalogue: inspection_catalogue(l::InspectionState::Empty, 15, 0, 16, b"8.1.6")
                .unwrap(),
            capabilities: Vec::new(),
        });
        l::codec::encode_response(&Ok(response), bounds)
            .expect("empty inspection crosses the lifecycle ABI");

        let expected = layout(15, 9, 16, b"8.1.6").unwrap();
        for state in [
            l::InspectionState::Legacy(crate::source_interpretation::descriptor(9).unwrap()),
            l::InspectionState::InProgress(crate::source_interpretation::descriptor(9).unwrap()),
            l::InspectionState::Current,
            l::InspectionState::Unsupported,
            l::InspectionState::Busy,
        ] {
            let catalogue = inspection_catalogue(state, 15, 9, 16, b"8.1.6").unwrap();
            assert_eq!(catalogue.len(), 1);
            assert_eq!(catalogue[0].name, expected.name);
            assert_eq!(catalogue[0].columns, expected.columns);
            assert_eq!(catalogue[0].native_layout, expected.native_layout);
        }
    }
}
