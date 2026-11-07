# Native RDB preservation oracle (CI only)

These C/Python tools are retained only as an independent native Valkey oracle for
historical RDB fixtures, including expired keys, binary cells and hash-field-expiry
refusal. They are not packaged with the Store plugin or used by automatic startup.
The retired manual Rust exporter and live reader have no external consumers and
were removed. Native startup uses the pinned parser, protected chunk storage and
host connection lifecycle in `store-valkey/src/historical/snapshot.rs`.

Build and run the retained native witnesses in an explicitly disposable directory:

```sh
python3 testing/native-rdb-oracle/build.py --output "$TASK_TMP/oracle.so"
PYTHONDONTWRITEBYTECODE=1 python3 testing/native-rdb-oracle/tests.py \
  --module "$TASK_TMP/oracle.so" --scratch-root "$TASK_TMP"
```

`tests.py` covers expired-key preservation and hash-field-expiry refusal against
actual Valkey9.1.3. `fence_tests.py` archives the original manual fencing oracle
source; it requires the retired exporter and is no longer an executable product
acceptance command. Current fencing/resume acceptance is the four ignored
`native_bootstrap_` tests in `store-valkey/src/v4/tests.rs`.
Keep source fixtures and their recorded hashes unchanged. These tools produce
independent CI evidence; they do not establish production startup authority.

The unchanged vendored header is from official tag `9.1.3`,
`https://raw.githubusercontent.com/valkey-io/valkey/9.1.3/src/valkeymodule.h`, SHA256
`1006fc046f0836322ab95178f75e0362fba2bf37b6595329207b6bff02b60793`.
`vendor/VALKEY-COPYING` retains the upstream license and notices.
