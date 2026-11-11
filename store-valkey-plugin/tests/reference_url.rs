// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `url` is reference-capable rather than a declared secret field; literal 1.5.5 URLs remain accepted.

use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4 as Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};

const URL: &str = "redis://cache.internal:6379/0";

fn linked() -> (Plugin<Store>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let bind = Bind {
        instance: Arc::from("reference-url"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of(busbar_store_valkey::door).expect("the row renders");
    (load_linked::<Store>(&row, bind).expect("the door loads"), d)
}

#[test]
fn the_url_is_not_declared_secret() {
    let (p, _d) = linked();
    assert!(
        !p.secret_refs().iter().any(|f| f == "url"),
        "{:?}",
        p.secret_refs()
    );
}

#[test]
fn a_reference_at_the_url_resolves_as_the_kernel_resolves_it() {
    let (p, _d) = linked();
    // Admitted source metadata expands shorthand before this context-free step.
    let expected = busbar_contract::secret_ref::SecretRef::Source(
        busbar_contract::secret_ref::SourceReference {
            module: "env".into(),
            settings: serde_json::Map::from_iter([("key".into(), "REFCAP_URL_FOR_TEST".into())])
                .into(),
        },
    );
    let mut resolutions = 0;
    let out = resolve_settings(
        &p,
        br#"{"url":{"module":"env","settings":{"key":"REFCAP_URL_FOR_TEST"}}}"#,
        |field, reference| {
            assert_eq!(field, "url");
            assert_eq!(reference, &expected);
            resolutions += 1;
            Ok(URL.to_string())
        },
    )
    .expect("a reference at the url resolves");
    assert_eq!(resolutions, 1);
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["url"], URL);
}

#[test]
fn a_literal_url_passes_as_written() {
    let (p, _d) = linked();
    let settings = format!(r#"{{"url":"{URL}"}}"#);
    let out = resolve_settings(&p, settings.as_bytes(), |_, _| {
        Err("a literal url resolves nothing".to_string())
    })
    .expect("a literal url passes as written");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["url"], URL);
}

fn resolve_settings(
    p: &Plugin<Store>,
    settings: &[u8],
    resolve: impl FnMut(&str, &busbar_contract::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<Vec<u8>, String> {
    let mut tree: serde_json::Value =
        serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    busbar_contract::secret_fields::resolve_declared_fields(
        &mut tree,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        resolve,
    )?;
    Ok(tree.to_string().into_bytes())
}
