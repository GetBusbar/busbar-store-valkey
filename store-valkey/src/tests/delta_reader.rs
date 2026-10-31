// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_delta_cannot_advance_past_a_row_inserted_between_index_and_value_reads() {
    let Some(fast) = live_store() else { return };
    let url = std::env::var("VALKEY_URL").unwrap();
    for credentials in [false, true] {
        let owner = uid("vk_delta_owner");
        let a = uid("vk_delta_a");
        let b = uid("vk_delta_b");
        fast.put_key(&vk(&owner)).unwrap();
        let (a_id, b_id, a_row, old_revision) = if credentials {
            let old = cred(&owner, &a, 0);
            let next = cred(&owner, &b, 1);
            fast.put_credential(&old).unwrap();
            let held = fast.lookup_credential_secret("sigv4", &a).unwrap().unwrap();
            (
                old.meta.id,
                next.meta.id,
                cred_row_key(&owner, "sigv4", 0),
                held.meta.revision,
            )
        } else {
            fast.put_key(&vk(&a)).unwrap();
            let held = fast.get_key(&a).unwrap().unwrap();
            (
                a.clone(),
                b.clone(),
                format!("{KEY_PREFIX}{a}"),
                held.revision,
            )
        };
        let gate = interleave::gate(&url, true, move |chunk| {
            interleave::contains(chunk, b"GET") && interleave::contains(chunk, a_row.as_bytes())
        });
        let slow = ValkeyStore::connect(&gate.url).unwrap();
        let reader = std::thread::spawn(move || -> RecordStoreResult<Vec<(String, u64)>> {
            if credentials {
                slow.list_credentials_since(old_revision - 1).map(|rows| {
                    rows.into_iter()
                        .map(|row| (row.meta.id, row.meta.revision))
                        .collect()
                })
            } else {
                slow.list_keys_since(old_revision - 1)
                    .map(|rows| rows.into_iter().map(|row| (row.id, row.revision)).collect())
            }
        });
        let held = gate.held.recv_timeout(std::time::Duration::from_secs(10));
        let writes = (|| -> RecordStoreResult<(u64, u64)> {
            if held.is_err() {
                return Ok((0, 0));
            }
            if credentials {
                fast.put_credential(&cred(&owner, &b, 1))?;
                fast.revoke_credential(&a_id, "changed during delta read")?;
                let rows = fast.list_credentials(&owner)?;
                Ok((
                    rows.iter().find(|r| r.id == a_id).unwrap().revision,
                    rows.iter().find(|r| r.id == b_id).unwrap().revision,
                ))
            } else {
                fast.put_key(&vk(&b))?;
                let mut changed = vk(&a);
                changed.name = "changed during delta read".into();
                fast.put_key(&changed)?;
                Ok((
                    fast.get_key(&a)?.unwrap().revision,
                    fast.get_key(&b)?.unwrap().revision,
                ))
            }
        })();
        let _ = gate.release.send(());
        let rows = reader.join().unwrap();
        held.expect("the reader paused before fetching A after its index snapshot");
        let (new_a_revision, b_revision) = writes.unwrap();
        let rows = rows.unwrap();
        assert!(b_revision > old_revision && new_a_revision > b_revision);
        assert!(rows
            .iter()
            .any(|(id, rev)| id == &a_id && *rev == new_a_revision));
        assert!(
            rows.iter()
                .any(|(id, rev)| id == &b_id && *rev == b_revision),
            "the returned newer A stamp must not skip the intervening B row"
        );
    }
}
