//! Deduplication indexes have independent finite cardinality and key-byte budgets.

use super::*;

#[test]
fn dedup_indexes_reject_new_items_at_the_cap() -> Result<(), Box<dyn std::error::Error>> {
    let first = tempfile::tempfile()?;
    let second = tempfile::tempfile()?;
    let first = first.metadata()?;
    let second = second.metadata()?;
    let mut seen = Seen::new(1, 3);
    assert!(seen.remember("one", &first)?);
    assert!(!seen.remember("one", &first)?);
    assert!(!seen.remember("two", &first)?);
    assert_eq!(seen.remember("two", &second), Err(Error::Budget));
    assert_eq!(seen.keys.len(), 1);
    assert_eq!(seen.identities.len(), 1);
    assert_eq!(seen.bytes, 3);
    let mut bytes = Seen::new(2, 5);
    assert!(bytes.remember("one", &first)?);
    assert_eq!(bytes.remember("two", &second), Err(Error::Budget));
    assert_eq!(bytes.bytes, 3);
    Ok(())
}
