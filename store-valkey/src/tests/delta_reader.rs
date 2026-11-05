// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// Scores only select candidates; adjacent revisions remain distinct beyond a double's precision.
#[test]
fn hydration_watermarks_compare_exact_revisions_above_double_precision() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(5);
    let url = url_for_db(5);
    let store = ValkeyStore::connect(&url).unwrap();
    const EDGE: u64 = 1 << 53;

    for edge in [EDGE, (1 << 54) + 4, (1 << 55) + 8] {
        raw.set::<_, _, ()>(REVISION_KEY, edge - 2).unwrap();
        let mut expected_keys = Vec::new();
        let mut expected_creds = Vec::new();
        for n in 0..4 {
            let owner = uid("vk_exact_revision");
            let public = uid("AKIA_EXACT_REVISION");
            let offered = cred(&owner, &public, 0);
            store
                .put_key_with_credential(&vk(&owner), &offered)
                .unwrap();
            if n % 2 == 0 {
                store.delete_key(&owner).unwrap();
            } else if n == 1 {
                store
                    .revoke_credential(&offered.meta.id, "exact revision")
                    .unwrap();
            }
            expected_keys.push(store.get_key(&owner).unwrap().unwrap());

            if n % 2 != 0 {
                expected_creds.push(
                    store
                        .list_credentials_since(0)
                        .unwrap()
                        .into_iter()
                        .find(|row| row.meta.id == offered.meta.id)
                        .unwrap(),
                );
            }
        }
        let reopened = ValkeyStore::connect(&url).unwrap();
        let top: u64 = raw.get(REVISION_KEY).unwrap();
        reopened
            .revoke_credential(&expected_creds[0].meta.id, "already revoked")
            .unwrap();

        for since in edge - 2..=top + 1 {
            for reader in [&store, &reopened] {
                let keys = reader.list_keys_since(since).unwrap();
                let creds = reader.list_credentials_since(since).unwrap();
                for expected in &expected_keys {
                    assert_eq!(
                        keys.iter().any(|row| row.id == expected.id),
                        expected.revision > since,
                        "key revision {} since {since}",
                        expected.revision
                    );
                }
                for expected in &expected_creds {
                    assert_eq!(
                        creds.iter().any(|row| row.meta.id == expected.meta.id),
                        expected.meta.revision > since,
                        "credential revision {} since {since}",
                        expected.meta.revision
                    );
                }
            }
        }
        assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), top);

        raw.zadd::<_, _, _, ()>(KEYS_BYREV, &expected_keys[0].id, 0)
            .unwrap();
        raw.zadd::<_, _, _, ()>(CREDS_BYREV, slot_pointer(&expected_creds[0].meta), 0)
            .unwrap();
        for since in [0, top, u64::MAX] {
            let keys = reopened.list_keys_since(since).unwrap();
            let creds = reopened.list_credentials_since(since).unwrap();
            assert_eq!(
                keys.iter().filter(|r| r.id == expected_keys[0].id).count(),
                1
            );
            assert_eq!(
                creds
                    .iter()
                    .filter(|r| r.meta.id == expected_creds[0].meta.id)
                    .count(),
                1
            );
        }
    }
}

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
                old.meta.id.clone(),
                next.meta.id.clone(),
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
        let reader = gate.spawn(move || -> RecordStoreResult<Vec<(String, u64)>> {
            if credentials {
                slow.list_credentials_since(old_revision - 1).map(|rows| {
                    rows.into_iter()
                        .map(|row| (row.meta.id.clone(), row.meta.revision))
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
