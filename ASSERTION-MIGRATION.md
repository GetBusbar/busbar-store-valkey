# Valkey ordinary test migration

Authored baseline: `0beaeee`; Busbar API pin remains `a35493a5e74cc935ff7dcc15c1af869290da91cb`. No SDK/peer/lock/publication/policy pin changes. This change removes the authored test-kit dependency and both conformance macro consumers. It does not certify compilation against a later SDK.

## Product assertions

`store-valkey-plugin/tests/conformance.rs` retains every pre-existing direct test and its transcript comparisons, perturbation negative arm, malformed Statement and wrong-kind refusals. `tests/e2e.rs` keeps its actual dropped-library durability, independent Redis-client readback, and real-admin-process cases.

The former store-kind script is explicit in `tests/support/store_behavior.rs`, called separately with the actual linked door and actual cdylib by `linked_and_dropped_preserve_every_store_operation`. It preserves all 87 named observations (including facts/open/ready), exact first-invocation crossing counts, lease-release counts, replay/conflict arms, and the original contract outcome assertions. Counter reads use the public doc-hidden authored-pin instance fields and subtract resumes exactly as the pinned script did. Assertions are inline; there is no Subject/Recorder/Leg framework or copied store implementation. Both forms use a locked, flushed private database 14; Database still rejects the shared VALKEY_URL database. The migrated live suite requires VALKEY_URL, preserving its strict service requirement.

| Former generated case | Ordinary owner |
| --- | --- |
| both-ways store script, facts/open/ready, all store slots | `linked_and_dropped_preserve_every_store_operation` + `support/store_behavior.rs` |
| mismatched Statement, linked and dropped | `a_statement_one_byte_off_is_refused` |
| kind ABI ±1 (pack/linked admission and dropped manifest) and incompatible layout xor1/zero | `actual_valkey_door_rejects_incompatible_abi_and_layout` |
| all six other plugin kinds, both forms | `both_actual_doors_refuse_every_other_plugin_kind` |
| networked door without table; probe admission | `networked_store_requires_a_connection_table_in_both_forms` |
| undeclared needs 1/MAX; foreign write/read/close; owner remains usable | `support/connection_ownership.rs::actual_valkey_instances_refuse_undeclared_needs_and_foreign_connections` over actual CONN_SLOTS + actual Connector/TCP |
| failed READY; exact error; one READY/one genuine cleanup CLOSE/three first crossings | `a_failed_ready_closes_the_actual_opened_valkey_store_once` (minimal malformed lifecycle input, unchanged real Valkey store slots) |
| forward schema refusal | `schema_newer_than_this_build_is_refused_through_both_doors` |
| declares needs equal Statement; requested release profile | `support/connection_ownership.rs::valkey_declares_exactly_its_statement_needs_and_requested_profile` |
| host TLS trusts private CA; withheld trust refuses | `linked_and_dropped_store_use_the_hosts_tls_trust_and_refuse_untrusted_peers`, actual Valkey behind a TLS terminator and actual production connector |
| reference-capable URL resolves; literal passes; URL not a declared secret | unchanged three tests in `reference_url.rs`, direct contract `resolve_declared_fields` |
| configured credential confidentiality | existing `debug_output_redacts_the_url_password`, `the_unix_socket_query_password_never_reaches_an_error_or_a_debug`, `unix_url_query_password_is_scrubbed_from_errors`, timeout password assertion, and credential-auth tests retain canary/redaction checks; former generic inputs had no configured secret reference |

`BUSBAR_PLUGIN_CDYLIB` accepts only an absolute own-product path. Missing artifacts fail. Deterministic developer fallback is the current test binary's `deps` directory. The e2e helper retains source-mtime freshness checks. Coordinated CI must freshly build and export the exact actual library; source does not infer freshness from an arbitrary directory scan.

## Deliberately retired framework self-checks / inapplicable generated branches

The moved-count RED arm tested the removed Fold comparator rather than Valkey; exact actual per-step count assertions remain. The plane unreported billable class, transport frame-piece layout, plane answer layout, and three outbound-auth mutation arms are inapplicable to a store and previously returned without exercising Valkey behavior. They are not replacement tests. Generic suite environment initialization is unnecessary because the checked-in inputs declare no `env` block. No private runtime or framework is introduced.

The removed host macro's production destination-guard policy proof (private/default-loopback/metadata refusal, no refused dial, infrastructure loopback admission) requires an explicit core-owner mapping before claiming full fleet assertion equivalence. It exercised the kit host's production guard, not Valkey's declared operator-infrastructure need. This repository does not add a kernel-config dependency solely to rebuild that removed kit host.

## Narrow unit-test host values

`test-support/valkey_io.rs` binds the actual TCP door through the actual production Connector and TLS implementation; it implements no transport/store protocol. Normal logic and integration tests use it.

`store-valkey/src/tests/socket_observer.rs` retains 402 lines solely for existing assertions requiring observable dial timeouts and a concrete TestTls handshaker's certificate-error evidence. It has no configurable transport facts, destination-guard seam, late-dial mode, protocol parser, fake store, generic TLS trait, exported package, or new framework. Its concrete ValkeyWireObserver supports only TCP, Unix and this module's TestTlsStream. Unix support is consumed by `a_unix_socket_url_reaches_the_server`. The consumers are:

- `the_store_keeps_one_connection_across_ops`
- `with_conn_transparently_reconnects_after_the_connection_is_dropped`
- `a_no_retry_write_on_a_dropped_connection_fails_and_the_next_op_dials_fresh`
- `a_unix_socket_url_reaches_the_server`
- `connect_timeout_ms_is_the_dial_timeout`
- `a_rediss_url_is_secured_through_the_hosts_connector` (including exact UnknownIssuer witness)
- `connect_timeout_ms_bounds_the_handshake_after_the_dial`
- `rediss_insecure_skips_certificate_verification`
- `a_malformed_reply_discards_the_kept_connection`
- `usage_cleanup_continues_empty_scan_pages_deduplicates_and_counts_delete_replies`
- `usage_cleanup_never_reconnects_and_replays_a_delete_whose_reply_was_lost`

A production Connector does not expose the concrete TestTls `last_verify_off`/`last_handshake_error` observations or the ordered dial-timeout values used by these unchanged assertions. ClockOnly directly implements the required HostServices refusals and clock; it is no generic services adapter. Credential-auth's fragmented RESP peer remains its pre-existing assertion-specific input.

## Qualification

`cargo fmt --all` and `git diff --check` pass. No build or runtime test has been run: resource-lane approval is required, and no approval has yet been received. Cargo.lock intentionally remains unchanged under the lane instructions; dependency resolution/locked-build impact must be reconciled by the authorized root integration lane. DB-backed green results, fresh actual dlopen execution, and final-SDK compatibility remain unqualified until that lane runs them.

Source follow-up: the authored TCP pin b896c5e6 exports its macro door through public `linked::MACRO_DOOR`; the bridge uses that path rather than its private `door` module. Verified with `git show b896c5e6:transport-tcp/src/lib.rs`; no build run.

Native authored-pin follow-up: the coordinated lane built the actual library successfully, then reported nine conformance-test compile errors. This source correction imports the Valkey helper names (removing stale SQLite names), preserves the loader-generated raw door in the mismatched row, and explicitly selects synchronous RecordStore calls in the TLS roundtrip. No local compile or runtime execution was performed for this follow-up.
