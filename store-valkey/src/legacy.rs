// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE v6 → v7 UPGRADE, IN PLACE.** busbar 1.6.0 replaced the protocol-named durable methods with
//! the kind-neutral plane-record verbs. A v6 namespace (every released store-valkey before this one)
//! holds the typed rows those methods wrote; this copies each into the plane keyspace ([`crate::plane`])
//! as the exact body the 1.6.0 plane decodes, then removes the typed keys.
//!
//! | v6 keyspace | v7 plane record |
//! |---|---|
//! | `busbar:task:row:<id>` + `busbar:tasks` + `busbar:tasks:byupdated` | kind `task`, id = task id, seq 0, ts = `updated_at`, TERMINAL iff the state is |
//! | `busbar:task:events:<id>` (ZSET by seq) | kind `task_event`, parent = task id, seq, ts |
//! | `busbar:mcp:demotions` (HASH server → row) | kind `demotion`, id = server, seq 0, ts = `recorded_at` |
//! | `busbar:askstate:<nonce>` (`SET NX EX`) | a redeemed `ask` token, with the remaining TTL |
//!
//! The sidecar each record gets is exactly what the 1.6.0 engine writes for the same row
//! (`TaskRow::to_plane_record` / `TaskEventRow::to_plane_record` / the demotion's), so an engine replay
//! of a migrated event is the identical append it is meant to be, not a fork.
//!
//! `busbar:mcp:*` (the v6 MCP tool-call log) is deliberately NOT migrated, and NOT removed. The 1.6.0
//! `call` body is a framed digest stream the engine seals itself; a backend re-encoding a typed row
//! into it would be forging the chain the engine verifies, and busbar ships no `call` migration
//! either. The keys stay where they are, unread, so no evidence is destroyed by an upgrade.
//! (store-sqlite, store-postgres and store-mysql make the same four moves and the same exception.)
//!
//! IDEMPOTENT, and that is what makes it crash-safe without one giant transaction: every record goes in
//! through [`crate::plane::append_if_absent`] (a position already holding a record — a newer 1.6.0
//! write, or this same copy from a run a crash interrupted — is left as it is), a typed key is removed
//! only after its records are in, and the schema marker is written last by the caller. A crash
//! anywhere re-runs the whole upgrade on the next connect and lands in the same place.

use crate::resp::{cmd, pipe, Conn};
use crate::{plane, RecordStoreError, RecordStoreResult, ValkeyStore};
use busbar_contract::records::{PlaneDisposition, PlaneRecord};

/// v6 key names — read once, here, by the upgrade, and by nothing else in 1.6.0.
pub(crate) const TASK_ROW_PREFIX: &str = "busbar:task:row:";
pub(crate) const TASKS_INDEX: &str = "busbar:tasks";
pub(crate) const TASKS_BY_UPDATED: &str = "busbar:tasks:byupdated";
pub(crate) const TASK_EVENTS_PREFIX: &str = "busbar:task:events:";
pub(crate) const MCP_DEMOTIONS_HASH: &str = "busbar:mcp:demotions";
pub(crate) const ASK_STATE_PREFIX: &str = "busbar:askstate:";

/// The task states that are TERMINAL — a closed set, as the 1.6.0 task plane's own.
const TERMINAL_TASK_STATES: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

/// The v6 row shapes, as v6 wrote them (`serde_json` of the typed rows). Read with exactly the fields
/// the 1.6.0 plane's own rows carry, and written back out in the same field order, so the migrated
/// body is the body the plane would have encoded. A v6 event carries no `digest_version`, and none is
/// added: the plane reads its absence as the framing those rows were sealed under, and writing one
/// would claim a framing the stored `hash` was never computed with.
pub(crate) mod rows {
    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
    pub struct Task {
        pub task_id: String,
        pub context_id: String,
        pub principal: String,
        pub direction: String,
        pub state: String,
        pub agent_id: String,
        pub artifact_cursor: u64,
        pub push_callback: String,
        pub created_at: u64,
        pub updated_at: u64,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
    pub struct TaskEvent {
        pub task_id: String,
        pub seq: u64,
        pub ts: u64,
        pub kind: String,
        pub context_id: String,
        pub principal: String,
        pub agent_id: String,
        pub state: String,
        pub request_id: String,
        pub prev_hash: String,
        pub hash: String,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
    pub struct Demotion {
        pub server: String,
        pub reason: String,
        pub recorded_at: u64,
    }
}

/// The plane kinds the upgrade writes, as the 1.6.0 engine names them.
pub(crate) const KIND_TASK: &str = "task";
pub(crate) const KIND_TASK_EVENT: &str = "task_event";
pub(crate) const KIND_DEMOTION: &str = "demotion";
pub(crate) const KIND_ASK: &str = "ask";

/// A v6 row that will not decode stops the upgrade: silently dropping it would lose a task, a
/// provenance link or a quarantine, and leaving the typed keys behind (the upgrade removes a key only
/// after its records are in) means nothing is lost while an operator repairs the row.
fn decode<T: serde::de::DeserializeOwned>(
    what: &str,
    key: &str,
    raw: &[u8],
) -> RecordStoreResult<T> {
    serde_json::from_slice(raw).map_err(|e| {
        RecordStoreError(format!(
            "v6 -> v7 upgrade: the {what} at {key} does not decode ({e}); the upgrade stops here and \
             leaves every v6 key in place"
        ))
    })
}

/// Copy one v6 row into the plane keyspace as `kind` at `(id, seq)`, unless that position is taken.
#[allow(clippy::too_many_arguments)]
async fn copy<T: serde::Serialize>(
    store: &ValkeyStore,
    c: &mut Conn,
    kind: &str,
    id: String,
    parent: Option<String>,
    (seq, ts): (u64, u64),
    disposition: PlaneDisposition,
    row: &T,
) -> RecordStoreResult<()> {
    let body = serde_json::to_vec(row)
        .map_err(|e| RecordStoreError(format!("v6 -> v7 upgrade: encode a plane body: {e}")))?;
    let record = PlaneRecord {
        kind: kind.into(),
        id,
        parent,
        seq,
        ts,
        disposition,
        body,
    };
    plane::append_if_absent(store, c, record.view()).await
}

/// Run the upgrade. See the module doc.
pub(crate) async fn migrate_v6_to_v7(store: &ValkeyStore, c: &mut Conn) -> RecordStoreResult<()> {
    // TASK EVENTS first, then tasks: a task's events are in before the task row that owns them, so
    // there is no instant at which a migrated task exists with its chain still behind.
    for key in store.scan(c, &format!("{TASK_EVENTS_PREFIX}*")).await? {
        let members: Vec<Vec<u8>> = with_conn!(store, |c| c.zrange(&key, 0, -1).await)?;
        for raw in members {
            let e: rows::TaskEvent = decode("task event", &key, &raw)?;
            let (id, at) = (e.task_id.clone(), (e.seq, e.ts));
            let active = PlaneDisposition::Active;
            copy(
                store,
                c,
                KIND_TASK_EVENT,
                id.clone(),
                Some(id),
                at,
                active,
                &e,
            )
            .await?;
        }
        with_conn!(store, |c| c.del::<_, ()>(&key).await)?;
    }

    for key in store.scan(c, &format!("{TASK_ROW_PREFIX}*")).await? {
        let raw: Option<Vec<u8>> = with_conn!(store, |c| c.get(&key).await)?;
        if let Some(raw) = raw {
            let t: rows::Task = decode("task", &key, &raw)?;
            let disposition = if TERMINAL_TASK_STATES.contains(&t.state.as_str()) {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            };
            let (id, at) = (t.task_id.clone(), (0, t.updated_at));
            copy(store, c, KIND_TASK, id, None, at, disposition, &t).await?;
        }
        with_conn!(store, |c| c.del::<_, ()>(&key).await)?;
    }
    with_conn!(store, |c| c
        .del::<_, ()>(&[TASKS_INDEX, TASKS_BY_UPDATED])
        .await)?;

    let demotions: Vec<(String, Vec<u8>)> =
        with_conn!(store, |c| c.hgetall(MCP_DEMOTIONS_HASH).await)?;
    for (server, raw) in demotions {
        let d: rows::Demotion = decode("demotion", MCP_DEMOTIONS_HASH, &raw)?;
        let (at, active) = ((0, d.recorded_at), PlaneDisposition::Active);
        copy(store, c, KIND_DEMOTION, server, None, at, active, &d).await?;
    }
    with_conn!(store, |c| c.del::<_, ()>(MCP_DEMOTIONS_HASH).await)?;

    // SPENT APPROVALS: each keeps its own remaining life. A key already past its TTL is gone on the
    // server and needs nothing; one with no TTL (never written by v6, which always set EX) is
    // carried with the ten-year bound the redeem verb applies.
    for key in store.scan(c, &format!("{ASK_STATE_PREFIX}*")).await? {
        let nonce = &key[ASK_STATE_PREFIX.len()..];
        let (value, ttl): (Option<String>, i64) =
            with_conn!(store, |c| pipe().get(&key).ttl(&key).query(c).await)?;
        if let Some(value) = value {
            let ttl = if ttl > 0 { ttl } else { 315_360_000 };
            let target = plane::token_key(KIND_ASK, nonce);
            with_conn!(store, |c| {
                cmd("SET")
                    .arg(&target)
                    .arg(&value)
                    .arg("NX")
                    .arg("EX")
                    .arg(ttl)
                    .query::<Option<String>>(c)
                    .await
            })?;
        }
        with_conn!(store, |c| c.del::<_, ()>(&key).await)?;
    }
    Ok(())
}
