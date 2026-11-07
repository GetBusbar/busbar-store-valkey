//! Constructor-time aggregate admission for the strict native snapshot profile.
use crate::RdbError;

/// Explicit bounds. Allocation and element allowances apply per yielded entry
/// or chunk; callers bound custody of previously yielded outputs. Input, metadata
/// and work remain cumulative across the entire stream.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum bytes read, including checksum and trailing-byte check.
    pub input_bytes: u64,
    /// Maximum parser allocation for one yielded entry/chunk, excluding metadata.
    pub allocated_bytes: u64,
    /// Cumulative raw AUX storage.
    pub metadata_bytes: u64,
    /// Maximum single string or compact block, before allocation/decompression.
    pub string_bytes: u64,
    /// Maximum elements per yielded entry/chunk (compact blocks charge a safe upper bound).
    pub elements: u64,
    /// Cumulative work units (input bytes plus conservative expansion units).
    pub work: u64,
}
pub(crate) fn refused() -> RdbError {
    RdbError::ResourceLimit
}
pub(crate) fn debit(left: &mut u64, count: u64) -> Result<(), RdbError> {
    *left = left.checked_sub(count).ok_or_else(refused)?;
    Ok(())
}
pub(crate) fn vector<T>(capacity: usize) -> Result<Vec<T>, RdbError> {
    let mut value = Vec::new();
    value.try_reserve_exact(capacity).map_err(|_| refused())?;
    Ok(value)
}
pub(crate) fn copy(bytes: &[u8]) -> Result<Vec<u8>, RdbError> {
    let mut out = vector(bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(out)
}
pub(crate) fn push<T>(values: &mut Vec<T>, value: T) -> Result<(), RdbError> {
    values.try_reserve_exact(1).map_err(|_| refused())?;
    values.push(value);
    Ok(())
}
