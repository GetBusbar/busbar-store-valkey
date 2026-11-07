# Parser source custody

Parser-only upstream baseline `nmvk/valkey-rdb-tools` commit
`364d0e0379414ae9e44281e61510b424c9526624` (BSD-3-Clause). Original
license and per-file SHA256 inventory retained. Baseline src is 5,193 lines,
including existing tests. No Arrow, CLI, Python or analytics dependency is included.

The owning backend carries finite strict-profile, aggregate resource-budget and
byte-custody changes required by CoreFix section 10.4. The generic upstream format
decoders remain the implementation; this is not a replacement RDB protocol.
The consuming backend repository revision pins the reviewed patch at integration.
