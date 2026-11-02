// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The v6 → v7 upgrade, in place.** The protocol-named durable methods were replaced by the

use crate::resp::Conn;
use crate::{plane, RecordStoreError, RecordStoreResult, ValkeyStore};
use busbar_contract::records::{PlaneDisposition, PlaneRecord};

/// v6 key names — read once, here, by the upgrade, and by nothing else.
pub(crate) const TASK_ROW_PREFIX: &str = "busbar:task:row:";
pub(crate) const TASKS_INDEX: &str = "busbar:tasks";
pub(crate) const TASKS_BY_UPDATED: &str = "busbar:tasks:byupdated";
pub(crate) const TASK_EVENTS_PREFIX: &str = "busbar:task:events:";
pub(crate) const MCP_DEMOTIONS_HASH: &str = "busbar:mcp:demotions";
pub(crate) const ASK_STATE_PREFIX: &str = "busbar:askstate:";

/// The task states that are TERMINAL — a closed set, as the task plane's own.
const TERMINAL_TASK_STATES: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

/// The v6 row shapes, as v6 wrote them (`serde_json` of the typed rows). Read with exactly the fields
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

/// The plane kinds the upgrade writes, as the engine names them.
pub(crate) const KIND_TASK: &str = "task";
pub(crate) const KIND_TASK_EVENT: &str = "task_event";
pub(crate) const KIND_DEMOTION: &str = "demotion";
pub(crate) const KIND_ASK: &str = "ask";

/// The nonce of a v6 spent-approval key. A server or proxy that returns a SCAN key outside the
/// MATCH pattern is refused with the key named, never byte-sliced (which could panic).
pub(crate) fn ask_nonce(key: &str) -> RecordStoreResult<&str> {
    key.strip_prefix(ASK_STATE_PREFIX).ok_or_else(|| {
        RecordStoreError(format!(
            "v6 -> v7 upgrade: SCAN returned key outside busbar:askstate:* ({key:?}); the upgrade \
             stops here and leaves every v6 key in place"
        ))
    })
}

/// A v6 row that will not decode stops the upgrade: silently dropping it would lose a task, a
fn decode<T: serde::de::DeserializeOwned>(
    what: &str,
    key: &str,
    raw: &[u8],
) -> RecordStoreResult<T> {
    serde_json::from_slice(raw).map_err(|e| {
        RecordStoreError(format!(
            "v6 -> v7 upgrade: the {what} at {key} does not decode ({}); the upgrade stops here; \
             unprocessed v6 keys remain in place",
            crate::decode_text(&e)
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
) -> RecordStoreResult<bool> {
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
    for key in store.scan(c, &format!("{TASK_EVENTS_PREFIX}*")).await? {
        let members: Vec<Vec<u8>> = with_conn!(store, |c| c.zrange(&key, 0, -1).await)?;

        let mut forked = false;
        for raw in members {
            let e: rows::TaskEvent = decode("task event", &key, &raw)?;
            let (id, at) = (e.task_id.clone(), (e.seq, e.ts));
            let active = PlaneDisposition::Active;
            let kind = KIND_TASK_EVENT;
            forked |= copy(store, c, kind, id.clone(), Some(id), at, active, &e).await?;
        }
        if !forked {
            with_conn!(store, |c| c.del::<_, ()>(&key).await)?;
        }
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

    for key in store.scan(c, &format!("{ASK_STATE_PREFIX}*")).await? {
        let nonce = ask_nonce(&key)?;
        let target = plane::token_key(KIND_ASK, nonce);
        with_conn!(store, |c| plane::MIGRATE_SPENT_TOKEN
            .key(&key)
            .key(&target)
            .invoke::<i64>(c)
            .await)?;
    }
    Ok(())
}
