// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Atomic correction over the ordinary key, usage and metering keyspace.

use super::*;
use busbar_contract::abi::sdk::store::dedupe::Seen;

impl ValkeyStore {
    /// Only a definitive WATCH abort retries. A lost EXEC reply retains the immutable request
    /// for receipt reconciliation by the caller; this operation never reconnects and replays.
    pub(super) async fn v3_usage_correction(
        &self,
        c: &mut Conn,
        request: &correction::Request,
    ) -> OpResult<correction::Decision> {
        use correction::Decision;

        let receipt = op_key(request.op_id);
        let dedupe = Dedupe::usage_correction(request);
        let owner = format!("{}{}", crate::KEY_PREFIX, request.key_id);
        let day = metering_set(request.day_start);
        let usage: Vec<_> = request
            .usage
            .iter()
            .map(|change| usage_key(&change.address.bucket_id, change.address.window_start))
            .collect();
        let mut watched = vec![receipt.as_str(), owner.as_str(), day.as_str()];
        watched.extend(usage.iter().map(String::as_str));

        for _ in 0..crate::resp::MAX_TRANSACTION_ATTEMPTS {
            if let Err(error) = cmd("WATCH").arg(&watched).exec(c).await {
                return Err(if error.is_crossslot() {
                    OpRefused::Refused("usage correction requires keys on one Valkey node".into())
                } else {
                    OpRefused::Failed(self.err(error, "usage correction WATCH").0)
                });
            }
            let mut submitted = false;
            let attempted = crate::resp::rr(async {
                require_type(c, &receipt, "hash").await?;
                let prior: Option<Vec<u8>> = c.hget(&receipt, "b").await?;
                match dedupe.seen(prior.as_deref()) {
                    Seen::Replay => return Ok(Some(Ok(Decision::Applied))),
                    Seen::Conflict => return Ok(Some(Err(OpRefused::Conflict))),
                    Seen::New => {}
                }

                require_type(c, &owner, "string").await?;
                require_type(c, &day, "set").await?;
                for key in &usage {
                    require_type(c, key, "hash").await?;
                }

                let rows: Vec<String> = c.smembers(&day).await?;
                if !rows.is_empty() {
                    cmd("WATCH").arg(&rows).exec(c).await?;
                }
                // Keep the complete watched set, but fetch full cells only for this owner.
                let mut identities = pipe();
                for row in &rows {
                    identities.cmd("HGET").arg(row).arg("key_id");
                }
                let owners: Vec<Option<String>> = identities.query(c).await?;
                if owners.len() != rows.len() {
                    return Err(RedisError::refused("metering owner reply length mismatch"));
                }
                let mut metering = Vec::new();
                for (row, owner) in rows.iter().zip(owners) {
                    if owner.as_deref() != Some(request.key_id.as_str()) {
                        continue;
                    }
                    let fields: Vec<(String, String)> = c.hgetall(row).await?;
                    if !fields.is_empty() {
                        let row = crate::metering_from_fields(fields)
                            .map_err(|error| RedisError::refused(error.0))?;
                        if row.key_id == request.key_id {
                            metering.push(row);
                        }
                    }
                }
                correction::canonical_metering(&mut metering);
                let raw: Option<String> = c.get(&owner).await?;
                let live = raw
                    .as_deref()
                    .map(crate::key_from_json)
                    .transpose()
                    .map_err(|error| RedisError::refused(error.0))?
                    .is_some_and(|key| key.id == request.key_id && key.deleted_at.is_none());
                let mut matches = live && metering == request.metering;
                for (change, key) in request.usage.iter().zip(&usage) {
                    let fields: Vec<(String, String)> = c.hgetall(key).await?;
                    let mut actual = crate::usage_from_fields(fields)
                        .map_err(|error| RedisError::refused(error.0))?;
                    correction::canonical_ledger(&mut actual).map_err(RedisError::refused)?;
                    matches &= actual == change.expected;
                }
                if !matches {
                    let mut validation = pipe();
                    validation.atomic().cmd("PING").ignore();
                    return validation
                        .query::<Option<()>>(c)
                        .await
                        .map(|stable| stable.map(|()| Ok(Decision::ConditionConflict)));
                }

                let mut transaction = pipe();
                transaction.atomic();
                for (change, key) in request.usage.iter().zip(&usage) {
                    let ledger = &change.replacement;
                    transaction.del(key).ignore();
                    transaction.hset(key, "requests", ledger.requests).ignore();
                    transaction
                        .hset(key, "billable_requests", ledger.billable_requests)
                        .ignore();
                    for model in &ledger.models {
                        for (unit, count) in &model.usage_units {
                            transaction
                                .hset(key, crate::usage_field(&model.model, unit), *count)
                                .ignore();
                        }
                    }
                }
                transaction
                    .hset(&receipt, "b", &dedupe.body()[..])
                    .ignore()
                    .cmd("EXPIRE")
                    .arg(&receipt)
                    .arg(OP_ID_RETENTION_SECS)
                    .ignore();
                submitted = true;
                transaction
                    .query::<Option<()>>(c)
                    .await
                    .map(|committed| committed.map(|()| Ok(Decision::Applied)))
            })
            .await;
            match attempted {
                Ok(None) => continue,
                Ok(Some(answer)) => {
                    if c.watching() {
                        cmd("UNWATCH").exec(c).await.map_err(|error| {
                            OpRefused::Failed(self.err(error, "usage correction UNWATCH").0)
                        })?;
                    }
                    return answer;
                }
                Err(error) => {
                    if !error.is_connection_error() && c.watching() {
                        let _ = cmd("UNWATCH").exec(c).await;
                    }
                    return Err(if error.is_crossslot() {
                        OpRefused::Refused(
                            "usage correction requires keys on one Valkey node".into(),
                        )
                    } else if error.is_refusal() || !submitted {
                        OpRefused::Refused(error.to_string())
                    } else {
                        OpRefused::Failed(
                            self.err(
                                error,
                                "usage correction outcome unknown; replay exact id and body",
                            )
                            .0,
                        )
                    });
                }
            }
        }
        Err(OpRefused::Failed(
            "usage correction contention exhausted; replay the same id and body".into(),
        ))
    }
}

async fn require_type(c: &mut Conn, key: &str, expected: &str) -> crate::resp::RedisResult<()> {
    let actual: String = cmd("TYPE").arg(key).query(c).await?;
    if actual != "none" && actual != expected {
        return Err(RedisError::refused(
            "usage correction storage has the wrong type",
        ));
    }
    Ok(())
}
