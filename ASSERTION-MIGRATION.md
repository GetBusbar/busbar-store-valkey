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

`store-valkey/src/tests/recorded_connector.rs` is a 184-line observation/forwarding value around the actual production Connector/TCP host. It records only effective requested dial timeouts and the actual connector's security-failure cause before connection retirement. It delegates socket I/O, message flags, tickets, waits, security upgrades, facts, landed status, closure and instance forgetting without substitution. It implements no socket, ConnSlab, TLS client, polling or framing. The previous 402-line socket implementation and 137 lines of custom TestTls/TestTlsStream/AnyCertificate helpers were deleted. The consumers remain:

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

The trusted/untrusted TLS test now supplies EgressTrust extra anchors to the actual connector, then checks the actual CAUSE_SECURITY and the exact rustls UnknownIssuer error string. Its original UnknownIssuer check and host refusal-prefix checks remain. The trusted readback/one-kept-connection case and insecure verified-refusal/unverified-success/two-accepted-connections case remain. The production cause is also explicitly pinned by core `connector_tests::a_trust_refusal_names_its_cause_and_the_trusted_twin_is_reached` and `compose_close_deadline_tests::an_untrusted_midstream_upgrade_records_the_security_cause`; no behavior assertion is retired. ClockOnly directly implements the required HostServices refusals and clock; credential-auth's pre-existing fragmented RESP peer remains assertion-specific input.

## Qualification

`cargo fmt --all` and `git diff --check` pass. No build or runtime test has been run: resource-lane approval is required, and no approval has yet been received. Cargo.lock intentionally remains unchanged under the lane instructions; dependency resolution/locked-build impact must be reconciled by the authorized root integration lane. DB-backed green results, fresh actual dlopen execution, and final-SDK compatibility remain unqualified until that lane runs them.

Source follow-up: the authored TCP pin b896c5e6 exports its macro door through public `linked::MACRO_DOOR`; the bridge uses that path rather than its private `door` module. Verified with `git show b896c5e6:transport-tcp/src/lib.rs`; no build run.

Native authored-pin follow-up: the coordinated lane built the actual library successfully, then reported nine conformance-test compile errors. This source correction imports the Valkey helper names (removing stale SQLite names), preserves the loader-generated raw door in the mismatched row, and explicitly selects synchronous RecordStore calls in the TLS roundtrip. No local compile or runtime execution was performed for this follow-up.

## Private Monday-audit composition

This normal merge composes diet source `2aaf45364242cbd0a7421734e9f83cb3c9eb8373` with exact read-only donor `aa869cf2ead3e4665d0054ec473169532f5b018d` (34 commits from common ancestor `55280f44201dfbb57237ab9f9a89bce04fccde2c`). It changes no SDK/peer/publication/policy pin or lock. No branch was pushed or published and no foreign worktree/ref changed.

Conflicts were resolved as follows:

- `lib.rs`: keep schema 12, metering-attribution/token-expiry migrations, full-width canonical ledger decoding/corrections and inclusive-score delta snapshots; add audit noeviction-before-migration and compare-and-set schema marking by value. Both key and credential deltas retain the baseline WATCH of index plus revision and decoded-u64 filtering, which also preserves the audit snapshot guarantee. Unreadable usage-field refusal is applied to the shared canonical decoder and the public read adds the bucket row context. Credential revocation keeps the stricter baseline row/pointer validation while adding audit pointer/occupant diagnostics. Audit numeric-timeout explanation and malformed-query credential masking remain.
- `legacy.rs`: use audit checked `ask_nonce` validation together with baseline atomic spent-token migration/TTL preservation; do not restore the older client-side TTL migration.
- `resp.rs`: keep SDK-sealed authentication and discarded malformed-stream handling; add audit incremental linear measuring, negative-length rejection and backend transaction-exhaustion error. The direct parse helper is test-only as in the audit donor.
- `slots.rs`/`plane.rs`: retain baseline slots/corrections and add exhaustive Retention match plus named UPSERT_SEQ reads; omit stale donor schema-10 descriptive header.
- `tests.rs`: retain both appended regression blocks, all stronger baseline assertions and audit assertions. Audit fixture calls now retain the existing Database custody guard. The always-aborting test uses donor database 4 with baseline bounded worker/proxy retirement. The baseline handshake test already explicitly checks database 0 and the selected target, so both assertions remain. Credential metadata checks retain serialized and Debug secret absence plus audit concrete metadata-type check. Audit per-run credential identifiers and hash-probe distinctions remain.
- `tests/interleave.rs`: retain baseline socket/worker retirement and add audit script-cache read custody; proxy URLs keep the actual baseline Proxy owner.
- `tests/slots_tests.rs`: keep private Database custody and apply audit SCRIPT FLUSH exclusion, cold-EVALSHA fallback counts and replay assertion; pass the actual proxy URL to the linked-door connection helper.
- `tests/store_conformance.rs`: retain audit corrected provenance description.
- `tests/e2e.rs`: retain kit-free real connector and canonical actual-artifact selection/freshness assertion, replace the nested mtime walker with the audit factored walker and its test-only-source regression.

A source inventory found every donor-added function/test name present in the composed sources. Kit/macro Rust-source census is zero. Formatting and diff checks pass. No cargo build/test/clippy or database run was launched in this composition lane. Earlier pre-audit native results do not qualify this merge; the parent native lane must build and exercise this exact composed tree.


The bounded actual-host replacement was source-reviewed after baseline `011454069f432f13a612c63900164901de639172`: all eleven named consumers retain their outcomes and exact timeout/cardinality/error assertions; only their connection implementation and certificate evidence source change. Formatting/diff checks pass; no local builds or tests were launched. Native qualification must use this final source and the parent-owned service base database 0, keeping private database 14 guarded against FLUSHDB of a shared database.

## Post-composition native failure causes and source corrections

The parent-owned baseline `0114540` native receipt found four source composition failures (separately from the shared-database-14 environment refusal):

- The earlier audit ask_nonce guard omitted the later baseline guard's ask-state-key/namespace diagnostic context. The production error now retains both contexts; both malformed-key regressions and their no-unwind/no-target controls remain unchanged.
- The audit's appended whole-metering field assertion assumed priced_from_ms=0, contradicting the baseline fixture's explicit 1_780_000_000_123 timestamp and its existing matching assertion. The appended timestamp assertion now checks that same written timestamp; no metering field assertion is dropped.
- Audit revocation errors preserved pointer/occupant identities but lost the baseline credential row key. Production dangling/stale-pointer errors now include both identities and the actual row key. The nonmutation/revision/secret-canary assertions are unchanged.
- Audit boundary rows stamped 10 were accidentally combined with the baseline cutoff above 2^53, making them genuinely old. The purge test now independently executes the original ordinary cutoff-10 old-active/terminal/equality scenario and the full-width cutoff scenario, each with the original exact 1200/1200/0 counts. Explicit row readbacks additionally prove active retention, later active removal and both dispositions surviving their actual exclusive age cutoff. No observed count was copied into an expected count.

The four ignored logic tests remain unmodified: `connect_refuses_to_start_under_an_eviction_policy` and `a_start_refused_for_eviction_policy_does_not_migrate` change the server-wide maxmemory policy and require a serialized dedicated run; the latter was already ignored in the audit donor, and the former in both parents. `a_pre_v6_namespace_is_refused_not_wiped_and_keeps_refund_shaped_data` and `a_namespace_with_keys_but_no_marker_refuses_to_connect_and_keeps_every_key` were already ignored in both parents as destructive namespace fixtures; they now use private locked database custody, so that historical rationale needs a separate execution/classification decision. Neither ignore was introduced by this composition or source correction. The donor's two ignored 1.5.5 replay tests retain the diet parent's already-unignored guarded execution. No ignore status is changed here.

These corrections pass formatting/diff checks only. No local build/test was launched; the parent must qualify the final exact source with the owned service base URL selecting database 0.
