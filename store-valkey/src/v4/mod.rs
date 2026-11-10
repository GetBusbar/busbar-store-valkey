// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Normal primitive backend. Legacy decoding and migration are independent.
//! Every candidate publishes exactly one native MSET after read-only preparation.

use crate::resp::{cmd, Conn, Value};
use crate::{hex, ValkeyStore};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::v4::retirement::Horizon;
use busbar_contract::abi::sdk::store::v4::{
    backend::{Backend, Committed},
    metadata,
};
use busbar_contract::abi::sdk::store::wire::drive_kept;
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::persistence::{self as p, control, *};
use busbar_contract::redacted::Secret;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

mod bootstrap;

busbar_contract::own_seal!(Own);
const META: &str = "busbar:v4:metadata";
const COMMON: &str = include_str!("common.lua");
const CONNECT: &str = include_str!("connect.lua");
const READ: &str = include_str!("read.lua");
const SCAN: &str = include_str!("scan.lua");
const COMMIT: &str = include_str!("commit.lua");
const GC: &str = include_str!("gc.lua");

/// This type and its owner seal stay private to the primitive door.
#[derive(Clone)]
struct OwnBackend(Arc<State>);
struct State {
    transport: ValkeyStore,
    owner: Own,
    info: OnceLock<BackendInfo>,
    proposed: BackendInfo,
    budget: usize,
    local: bool,
    horizons: Mutex<HashMap<[u8; 16], Horizon>>,
    bootstrap: Mutex<bootstrap::Session>,
    bootstrap_channels: busbar_contract::abi::sdk::store::wire::Channels,
}

busbar_contract::statement_extensions!(V4_EXTENSIONS:[
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS,br#"["url"]"#),
]);
busbar_contract::store_v4_door!(OwnBackend, "busbar-store-valkey", env!("CARGO_PKG_VERSION"), 64, needs: crate::NEEDS,
    extensions: V4_EXTENSIONS,
    settings_schema: busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json")));

// Drive through the same kept connections, host connector, TLS and authentication
// as the transport. Never retry a sent commit or migrate a legacy namespace.
macro_rules! operation {
    ($this:expr,$op:expr,$me:ident,$conn:ident,$body:expr) => {{
        let $me = $this.clone();
        let pool = $me.0.transport.pool().clone();
        drive_kept($op, &pool, move |wire| {
            Box::pin(async move {
                let mut $conn = match $me.0.transport.conn(wire, Some("v4")).await {
                    Ok(conn) => conn,
                    Err(_) => return Err(Failure::Unavailable),
                };
                $conn.reply_budget($me.0.budget);
                let answer = $body;
                $conn.settle();
                answer
            })
        })
    }};
}

struct SettingsJson(serde_json::Value);
impl Drop for SettingsJson {
    fn drop(&mut self) {
        fn wipe(v: &mut serde_json::Value) {
            use zeroize::Zeroize;
            match v {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(a) => a.iter_mut().for_each(wipe),
                serde_json::Value::Object(o) => o.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
fn settings(bytes: &[u8]) -> Result<(zeroize::Zeroizing<Vec<u8>>, usize, bool), String> {
    let mut value =
        SettingsJson(serde_json::from_slice(bytes).map_err(|_| "invalid valkey v4 settings")?);
    let object = value
        .0
        .as_object_mut()
        .ok_or("valkey v4 settings must be an object")?;
    let budget = object
        .remove("input_budget")
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0 && *v <= isize::MAX as usize)
        .ok_or("input_budget must be a positive allocation budget")?;
    let local = match object
        .remove("durability")
        .and_then(|v| v.as_str().map(str::to_owned))
        .as_deref()
    {
        Some("local") => true,
        Some("ephemeral") => false,
        _ => return Err("durability must be local or ephemeral".into()),
    };
    let transport = serde_json::to_vec(&value.0).map_err(|_| "invalid valkey v4 settings")?;
    Ok((zeroize::Zeroizing::new(transport), budget, local))
}

fn prefix(info: BackendInfo) -> String {
    format!("busbar:v4:{{{}}}:", hex(&info.dataset.0))
}
fn record(prefix: &str, namespace: [u8; 16], key: &[u8]) -> String {
    format!("{prefix}r:{}:{}", hex(&namespace), hex(key))
}
fn record_prefix(prefix: &str, namespace: [u8; 16]) -> String {
    format!("{prefix}r:{}:", hex(&namespace))
}
fn persistent(info: BackendInfo) -> Vec<u8> {
    metadata::encode(BackendInfo {
        durability: Durability::Ephemeral,
        ..info
    })
    .expect("valid connected metadata")
    .to_vec()
}
fn guard(time: Option<TimeGuard>) -> [Vec<u8>; 2] {
    [
        time.and_then(|v| v.not_before)
            .map(|v| v.to_le_bytes().to_vec())
            .unwrap_or_default(),
        time.and_then(|v| v.before)
            .map(|v| v.to_le_bytes().to_vec())
            .unwrap_or_default(),
    ]
}
async fn eval(
    c: &mut Conn,
    source: &str,
    args: &[Vec<u8>],
) -> Result<zeroize::Zeroizing<Vec<Vec<u8>>>, crate::resp::RedisError> {
    cmd("EVAL")
        .arg(format!("{COMMON}\n{source}"))
        .arg(1)
        .arg(META)
        .arg(args)
        .query(c)
        .await
        .map(zeroize::Zeroizing::new)
}
fn fault(error: crate::resp::RedisError, commit: bool) -> Failure {
    // Only these deliberate script errors precede the publication instruction.
    let text = error.to_string();
    if text.contains("V4_CORRUPT") {
        Failure::Corrupt
    } else if text.contains("V4_RESOURCE") {
        Failure::Refused
    } else if commit {
        Failure::Unknown
    } else {
        Failure::Unavailable
    }
}
fn owned(bytes: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Failure::Overloaded)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
fn u64bytes(bytes: &[u8]) -> Result<u64, Failure> {
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| Failure::Corrupt)?,
    ))
}
fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], Failure> {
    let value = input.get(..count).ok_or(Failure::Corrupt)?;
    *input = &input[count..];
    Ok(value)
}
fn framed<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Failure> {
    let count =
        u32::from_le_bytes(take(input, 4)?.try_into().map_err(|_| Failure::Corrupt)?) as usize;
    take(input, count)
}
impl OwnBackend {
    fn observation(&self, bytes: &[u8]) -> Result<ClockObservation, Failure> {
        Ok(ClockObservation {
            authority: self.info().clock_authority,
            unix_seconds: u64bytes(bytes)?,
        })
    }
    fn checked_info(&self, dataset: DatasetId) -> Result<BackendInfo, Failure> {
        let info = *self.0.info.get().ok_or(Failure::Unavailable)?;
        if info.dataset != dataset {
            return Err(Failure::Refused);
        }
        Ok(info)
    }
    async fn connected(&self, c: &mut Conn) -> Result<(), String> {
        self.0
            .transport
            .assert_noeviction(c)
            .await
            .map_err(|e| e.0)?;
        let server: String = cmd("INFO")
            .arg("server")
            .query(c)
            .await
            .map_err(|_| "cannot inspect Valkey version")?;
        let version = server
            .lines()
            .find_map(|line| line.strip_prefix("valkey_version:"))
            .or_else(|| {
                server
                    .lines()
                    .find_map(|line| line.strip_prefix("redis_version:"))
            })
            .and_then(|v| v.trim().split('.').next()?.parse::<u32>().ok())
            .ok_or("cannot establish Valkey version")?;
        if version < 8 {
            return Err("Valkey v4 requires server 8 or newer".into());
        }
        let cluster: String = cmd("INFO")
            .arg("cluster")
            .query(c)
            .await
            .map_err(|_| "cannot inspect cluster topology")?;
        if !cluster
            .lines()
            .any(|line| line.trim() == "cluster_enabled:0")
        {
            return Err("Valkey Cluster unsupported: endpoint routing and complete legacy namespace inspection are required".into());
        }
        let role: Value = cmd("ROLE")
            .query(c)
            .await
            .map_err(|_| "cannot inspect authoritative role")?;
        if !matches!(role,Value::Array(ref rows) if rows.first()==Some(&Value::Data(b"master".to_vec())))
        {
            return Err("v4 requires an authoritative writable primary".into());
        }
        let config: Vec<(String, String)> = cmd("CONFIG")
            .arg("GET")
            .arg("appendonly")
            .arg("appendfsync")
            .arg("no-appendfsync-on-rewrite")
            .query(c)
            .await
            .map_err(|_| "cannot inspect durability configuration")?;
        let configured =
            |k: &str, v: &str| config.iter().any(|(key, value)| key == k && value == v);
        let persistence: String = cmd("INFO")
            .arg("persistence")
            .query(c)
            .await
            .map_err(|_| "cannot inspect persistence status")?;
        let durable = configured("appendonly", "yes")
            && configured("appendfsync", "always")
            && configured("no-appendfsync-on-rewrite", "no")
            && persistence.lines().any(|v| v.trim() == "aof_enabled:1")
            && persistence
                .lines()
                .any(|v| v.trim() == "aof_last_write_status:ok");
        if self.0.local && !durable {
            return Err("local durability requires healthy AOF with appendfsync always and no fsync suppression".into());
        }
        let args = vec![
            persistent(self.0.proposed),
            prefix(self.0.proposed).into_bytes(),
        ];
        let answer = eval(c, CONNECT, &args)
            .await
            .map_err(|_| "v4 metadata initialization failed; reopen to inspect persistent state")?;
        let bytes = match answer.as_slice() {
            [tag, bytes] if tag == b"metadata" => bytes,
            _ => return Err("v4 refuses existing legacy or incomplete namespace".into()),
        };
        let mut info = metadata::decode(bytes).map_err(|_| "malformed v4 metadata")?;
        if info.physical_version != 1 || info.durability != Durability::Ephemeral {
            return Err("unsupported persistent v4 physical metadata".into());
        }
        info.durability = if self.0.local {
            Durability::Local
        } else {
            Durability::Ephemeral
        };
        if *self.0.info.get_or_init(|| info) != info {
            return Err("opened dataset metadata changed".into());
        }
        Ok(())
    }
    async fn maintain(&self, c: &mut Conn, writer: [u8; 16]) -> Result<(), Failure> {
        // An ephemeral acknowledgement does not establish a durable retirement.
        if self.info().durability != Durability::Local {
            return Ok(());
        }
        let info = self.info();
        let base = prefix(info);
        let address = record(&base, control::NAMESPACE.0, &control::writer_key(writer));
        let observed = self
            .native_eval(
                c,
                READ,
                &[
                    persistent(info),
                    Vec::new(),
                    Vec::new(),
                    address.as_bytes().to_vec(),
                ],
            )
            .await
            .map_err(|e| fault(e, false))?;
        let encoded = match observed.as_slice() {
            [tag, _, bytes] if tag == b"values" => bytes,
            _ => return Err(Failure::Corrupt),
        };
        let mut input = encoded.as_slice();
        if take(&mut input, 1)? != [1] {
            return Ok(());
        }
        let state = control::Writer::decode(framed(&mut input)?).ok_or(Failure::Corrupt)?;
        if !input.is_empty() {
            return Err(Failure::Corrupt);
        }
        let floor = {
            let mut horizons = self.0.horizons.lock().map_err(|_| Failure::Corrupt)?;
            let now = Instant::now();
            if !horizons.contains_key(&writer) {
                horizons.try_reserve(1).map_err(|_| Failure::Overloaded)?;
            }
            horizons
                .entry(writer)
                .or_insert_with(|| Horizon::new(state.retired_through, now))
                .observe(state.retired_through, now)?
        };
        if floor == 0 {
            return Ok(());
        }
        let reply = self
            .native_eval(
                c,
                GC,
                &[
                    persistent(info),
                    address.into_bytes(),
                    floor.to_le_bytes().to_vec(),
                    format!("{base}o:{}:", hex(&writer)).into_bytes(),
                ],
            )
            .await
            .map_err(|e| fault(e, false))?;
        if reply.as_slice() != [b"ok".to_vec()] {
            return Err(Failure::Corrupt);
        }
        Ok(())
    }
    fn commit_args(
        &self,
        candidate: &PreparedCandidate<Own>,
        info: BackendInfo,
    ) -> Result<zeroize::Zeroizing<Vec<Vec<u8>>>, Failure> {
        let source = candidate.candidate();
        source.validate().map_err(|_| Failure::Refused)?;
        let base = prefix(info);
        let id = source.id;
        let bounds = guard(source.time);
        let mut args = zeroize::Zeroizing::new(vec![
            persistent(info),
            base.as_bytes().to_vec(),
            info.dataset.0.to_vec(),
            format!("{base}o:{}:{}", hex(&id.writer), hex(&id.operation)).into_bytes(),
            candidate.fingerprint().to_vec(),
            id.execution_epoch.to_le_bytes().to_vec(),
            id.writer_epoch.to_le_bytes().to_vec(),
            record(&base, control::NAMESPACE.0, control::DATASET_KEY).into_bytes(),
            record(&base, control::NAMESPACE.0, &control::writer_key(id.writer)).into_bytes(),
            bounds[0].clone(),
            bounds[1].clone(),
            if control::initialization(source, info.dataset) {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            },
            source.result.expose_own(&self.0.owner).clone(),
            record_prefix(&base, control::NAMESPACE.0).into_bytes(),
            record_prefix(&base, control::GENERATION_NAMESPACE.0).into_bytes(),
            source.predicates.len().to_string().into_bytes(),
        ]);
        for item in &source.predicates {
            args.push(record(&base, item.address.namespace, &item.address.key).into_bytes());
            args.push(match &item.expected {
                ExpectedValue::Absent => vec![0],
                ExpectedValue::Exact(v) => {
                    let mut value = vec![1];
                    value.extend_from_slice(v.expose_own(&self.0.owner));
                    value
                }
            });
        }
        args.push(source.mutations.len().to_string().into_bytes());
        for item in &source.mutations {
            let (kind, key, value, namespace) = match item {
                Mutation::Put { address, value } => (
                    b"put".to_vec(),
                    record(&base, address.namespace, &address.key),
                    value.expose_own(&self.0.owner).clone(),
                    address.namespace,
                ),
                Mutation::Delete(address) => (
                    b"delete".to_vec(),
                    record(&base, address.namespace, &address.key),
                    Vec::new(),
                    address.namespace,
                ),
                Mutation::DeleteRange {
                    namespace,
                    prefix: raw,
                    exact_key_length,
                } => {
                    let before = record_prefix(&base, namespace.0);
                    let bytes = usize::try_from(*exact_key_length)
                        .ok()
                        .and_then(|n| n.checked_mul(2))
                        .and_then(|n| n.checked_add(before.len()))
                        .ok_or(Failure::Refused)?;
                    (
                        b"range".to_vec(),
                        format!("{before}{}", hex(raw)),
                        bytes.to_string().into_bytes(),
                        namespace.0,
                    )
                }
            };
            args.extend([kind, key.into_bytes(), value, hex(&namespace).into_bytes()]);
        }
        Ok(args)
    }
}
impl Backend for OwnBackend {
    fn connect_prepared(
        &self,
        op: &mut Op<'_>,
        binding: &p::lifecycle::OpenBinding,
    ) -> Step<Result<(), String>> {
        self.connect_native_prepared(op, binding)
    }
    fn bootstrap(
        &self,
        op: &mut Op<'_>,
        request: &p::lifecycle::Request<Own>,
    ) -> Step<Result<p::lifecycle::Response<Own>, p::lifecycle::Error>> {
        self.bootstrap_native(op, request)
    }

    type Owner = Own;
    fn owner(&self) -> &Own {
        &self.0.owner
    }
    fn input_budget(&self) -> usize {
        self.0.budget
    }
    fn validate(bytes: &[u8]) -> Result<(), String> {
        let (bytes, _, _) = settings(bytes)?;
        ValkeyStore::from_settings(&bytes).map(drop)
    }
    fn open(
        bytes: &[u8],
        secrets: &[&[u8]],
        _: Option<Host<busbar_contract::plugin::markers::StoreKind>>,
    ) -> Result<Self, String> {
        let (bytes, budget, local) = settings(bytes)?;
        let transport = ValkeyStore::from_settings_lent(&bytes, secrets)?;
        fn id() -> Result<[u8; 16], String> {
            let mut value = [0; 16];
            getrandom::fill(&mut value).map_err(|_| "OS identity allocation failed")?;
            if value == [0; 16] {
                return Err("OS identity allocation returned zero".into());
            }
            Ok(value)
        }
        let proposed = BackendInfo {
            dataset: DatasetId(id()?),
            atomic_domain: id()?,
            clock_authority: id()?,
            physical_version: 1,
            durability: Durability::Ephemeral,
        };
        Ok(Self(Arc::new(State {
            transport,
            owner: Own::here(),
            info: OnceLock::new(),
            proposed,
            budget,
            local,
            horizons: Mutex::new(HashMap::new()),
            bootstrap: Mutex::new(bootstrap::Session::default()),
            bootstrap_channels: busbar_contract::abi::sdk::store::wire::Channels::new(2),
        })))
    }
    fn connect(&self, op: &mut Op<'_>) -> Step<Result<(), String>> {
        let me = self.clone();
        let pool = me.0.transport.pool().clone();
        drive_kept(op, &pool, move |wire| {
            Box::pin(async move {
                let mut c = me.0.transport.conn(wire, None).await.map_err(|e| e.0)?;
                let result = me.connected(&mut c).await;
                c.settle();
                result
            })
        })
    }
    fn info(&self) -> BackendInfo {
        *self.0.info.get().expect("metadata requested after connect")
    }
    fn read(&self, op: &mut Op<'_>, request: &p::Read) -> Step<Result<ReadResult<Own>, Failure>> {
        let info = match self.checked_info(request.dataset) {
            Ok(v) => v,
            Err(e) => return Step::Ready(Err(e)),
        };
        let base = prefix(info);
        let bounds = guard(request.time);
        let mut args = vec![persistent(info), bounds[0].clone(), bounds[1].clone()];
        args.extend(
            request
                .addresses
                .iter()
                .map(|a| record(&base, a.namespace, &a.key).into_bytes()),
        );
        let count = request.addresses.len();
        operation!(self, op, me, c, {
            let rows = me
                .native_eval(&mut c, READ, &args)
                .await
                .map_err(|e| fault(e, false))?;
            match rows.as_slice() {
                [tag, time] if tag == b"time" => Ok(ReadResult::TimeGuardFailed {
                    observed_at: me.observation(time)?,
                }),
                [tag, time, bytes] if tag == b"values" => {
                    let mut input = bytes.as_slice();
                    let mut values = Vec::new();
                    values
                        .try_reserve_exact(count)
                        .map_err(|_| Failure::Overloaded)?;
                    for _ in 0..count {
                        let tag = take(&mut input, 1)?[0];
                        values.push(match tag {
                            0 => None,
                            1 => Some(Secret::held(owned(framed(&mut input)?)?)),
                            _ => return Err(Failure::Corrupt),
                        });
                    }
                    if !input.is_empty() {
                        return Err(Failure::Corrupt);
                    }
                    Ok(ReadResult::Values {
                        observed_at: me.observation(time)?,
                        values,
                    })
                }
                [tag] if tag == b"corrupt" => Err(Failure::Corrupt),
                _ => Err(Failure::Corrupt),
            }
        })
    }
    fn scan(&self, op: &mut Op<'_>, request: &p::Scan) -> Step<Result<Page<Own>, Failure>> {
        let info = match self.checked_info(request.dataset) {
            Ok(v) => v,
            Err(e) => return Step::Ready(Err(e)),
        };
        if request.max_items == 0 || request.max_bytes == 0 {
            return Step::Ready(Err(Failure::Refused));
        }
        let base = prefix(info);
        let ns = request.namespace.0;
        let args = vec![
            persistent(info),
            base.as_bytes().to_vec(),
            record(&base, control::GENERATION_NAMESPACE.0, &ns).into_bytes(),
            request
                .generation
                .map(|v| v.to_le_bytes().to_vec())
                .unwrap_or_default(),
            if request.allow_change {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            },
            request
                .after
                .as_ref()
                .map(|v| hex(v).into_bytes())
                .unwrap_or_default(),
            request.max_items.to_string().into_bytes(),
            request.max_bytes.to_string().into_bytes(),
            record_prefix(&base, ns).into_bytes(),
            hex(&request.prefix).into_bytes(),
            if request.after.is_some() {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            },
        ];
        operation!(self, op, me, c, {
            let response = me
                .native_eval(&mut c, SCAN, &args)
                .await
                .map_err(|e| fault(e, false))?;
            let _ = &me;
            match response.as_slice() {
                [tag, generation, bytes, next, more] if tag == b"page" => {
                    let mut input = bytes.as_slice();
                    let mut rows = Vec::new();
                    while !input.is_empty() {
                        let key = owned(framed(&mut input)?)?;
                        let value = Secret::held(owned(framed(&mut input)?)?);
                        rows.try_reserve(1).map_err(|_| Failure::Overloaded)?;
                        rows.push((Address { namespace: ns, key }, value));
                    }
                    let next = match more.as_slice() {
                        b"0" if next.is_empty() => None,
                        b"1" => Some(next.clone()),
                        _ => return Err(Failure::Corrupt),
                    };
                    Ok(Page {
                        generation: u64bytes(generation)?,
                        rows,
                        next,
                    })
                }
                [tag] if tag == b"stale" => Err(Failure::StaleScan),
                [tag] if tag == b"refused" => Err(Failure::Refused),
                _ => Err(Failure::Corrupt),
            }
        })
    }
    fn commit(
        &self,
        op: &mut Op<'_>,
        request: &PreparedCandidate<Own>,
    ) -> Step<Result<Committed<Own>, Failure>> {
        let info = match self.checked_info(request.candidate().id.dataset) {
            Ok(v) => v,
            Err(e) => return Step::Ready(Err(e)),
        };
        let args = match self.commit_args(request, info) {
            Ok(v) => v,
            Err(e) => return Step::Ready(Err(e)),
        };
        let mut maintain = vec![request.candidate().id.writer];
        for mutation in &request.candidate().mutations {
            if let Mutation::Put { address, .. } = mutation {
                if address.namespace == control::NAMESPACE.0 {
                    if let Some(control::Key::Writer(writer)) = control::Key::decode(&address.key) {
                        maintain.push(writer)
                    }
                }
            }
        }
        operation!(self, op, me, c, {
            let response = me
                .native_eval(&mut c, COMMIT, &args)
                .await
                .map_err(|e| fault(e, true))?;
            // A maintenance failure cannot erase the definitive publication answer.
            for writer in maintain {
                if me.maintain(&mut c, writer).await.is_err() {
                    break;
                }
            }
            match response.as_slice() {
                [tag] if tag == b"refused" => Err(Failure::Refused),
                [tag] if tag == b"corrupt" => Err(Failure::Corrupt),
                [tag, time, result] if tag == b"applied" => Ok(Committed {
                    // The server confirmed the commit landed. A garbled timestamp
                    // must not surface as Corrupt (which implies data damage).
                    observed_at: me.observation(time).map_err(|_| Failure::Unknown)?,
                    decision: Decision::Applied(Secret::held(
                        owned(result).map_err(|_| Failure::Unknown)?,
                    )),
                }),
                [tag, time] => {
                    let observed_at = me.observation(time)?;
                    let decision = match tag.as_slice() {
                        b"opconflict" => Decision::OpIdConflict,
                        b"expired" => Decision::ExpiredUnknown,
                        b"time" => Decision::TimeGuardFailed { observed_at },
                        b"condition" => Decision::ConditionConflict,
                        _ => return Err(Failure::Unknown),
                    };
                    Ok(Committed {
                        observed_at,
                        decision,
                    })
                }
                _ => Err(Failure::Unknown),
            }
        })
    }
    fn clock(
        &self,
        op: &mut Op<'_>,
        dataset: DatasetId,
    ) -> Step<Result<ClockObservation, Failure>> {
        let info = match self.checked_info(dataset) {
            Ok(v) => v,
            Err(e) => return Step::Ready(Err(e)),
        };
        let args = vec![persistent(info), Vec::new(), Vec::new()];
        operation!(self, op, me, c, {
            let response = me
                .native_eval(&mut c, READ, &args)
                .await
                .map_err(|e| fault(e, false))?;
            match response.as_slice() {
                [tag, time, bytes] if tag == b"values" && bytes.is_empty() => me.observation(time),
                _ => Err(Failure::Corrupt),
            }
        })
    }
}

#[cfg(test)]
mod tests;
