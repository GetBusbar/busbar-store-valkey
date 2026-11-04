// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn malformed_scan_pairs_are_refused() {
    assert!(scan_pairs(vec![Some(vec![1])]).is_err());
    assert!(scan_pairs(vec![None, Some(vec![1])]).is_err());
    assert!(scan_pairs(vec![Some(vec![1]), None]).is_err());
    assert_eq!(
        scan_pairs(vec![Some(vec![1]), Some(vec![2])])
            .unwrap()
            .len(),
        1
    );
}
