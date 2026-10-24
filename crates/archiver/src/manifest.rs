//! Bounded all-history snapshots: data arrays, bounded index pages, then one small commit root.
//! Only publishing the root marks completion. Manifests never grant deletion authority.

use disk_archive_storage::{CancellationToken, ObjectStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Error,
    blocking::BlockingPool,
    state::{MAX_MANIFEST_PAGE, Writer},
};

const INDEX_ENTRIES: usize = 512;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    name: String,
    rows: u64,
    sha256: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format: String,
    parts: Vec<Part>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    format: String,
    rows: u64,
    data_parts: u64,
    index_pages: u64,
    index_chain_sha256: [u8; 32],
}

/// Reserve room for a full u64 ordinal filename before ANY source mutation.
/// Parts live at `<root-key>.parts/{part,index}-<20-digit ordinal>.json`.
pub(crate) fn validate_key(key: &str) -> Result<(), Error> {
    if key.is_empty() || key.len().checked_add(38).is_none_or(|n| n > 1024) {
        return Err(Error::Configuration);
    }
    Ok(())
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Io)?;
    if bytes.len() > MAX_MANIFEST_PAGE {
        return Err(Error::Budget);
    }
    Ok(bytes)
}

struct Publisher<'a> {
    base: String,
    store: &'a dyn ObjectStore,
    pool: &'a BlockingPool,
    cancel: CancellationToken,
}

impl Publisher<'_> {
    async fn index(
        &self,
        ordinal: u64,
        parts: Vec<Part>,
        mut chain: Sha256,
    ) -> Result<Sha256, Error> {
        let (bytes, chain) = self
            .pool
            .run(&CancellationToken::new(), move || {
                let bytes = encode(&Index {
                    format: "disk-archive-index-v1".into(),
                    parts,
                })?;
                chain.update(
                    u64::try_from(bytes.len())
                        .map_err(|_| Error::Budget)?
                        .to_be_bytes(),
                );
                chain.update(&bytes);
                Ok((bytes, chain))
            })
            .await?;
        self.store
            .put_manifest(
                &format!("{}index-{ordinal:020}.json", self.base),
                &bytes,
                self.cancel.clone(),
            )
            .await
            .map_err(|_| Error::Store)?;
        Ok(chain)
    }
}

/// Publish ALL state rows without an all-history allocation or lifetime row/byte ceiling.
/// A bounded page is uploaded at a time; each index describes at most 512 data pages. The
/// constant-size root names the consecutive ordinal ranges and commits their ordered digest.
/// Call only after every state producer has drained; keys must belong to an exclusive namespace.
///
/// # Errors
/// Errors before the final root request omit it. Cancellation/response loss during that last
/// request can have an unknown remote commit outcome. Already-published pages may remain;
/// neither pages nor roots authorize source deletion.
pub async fn publish(
    writer: &Writer,
    store: &dyn ObjectStore,
    pool: &BlockingPool,
    key: &str,
    cancel: CancellationToken,
) -> Result<(), Error> {
    publish_with_index_limit(writer, store, pool, key, cancel, INDEX_ENTRIES).await
}

async fn publish_with_index_limit(
    writer: &Writer,
    store: &dyn ObjectStore,
    pool: &BlockingPool,
    key: &str,
    cancel: CancellationToken,
    index_limit: usize,
) -> Result<(), Error> {
    validate_key(key)?;
    if !(1..=INDEX_ENTRIES).contains(&index_limit) {
        return Err(Error::Configuration);
    }
    let publisher = Publisher {
        base: format!("{key}.parts/"),
        store,
        pool,
        cancel: cancel.clone(),
    };
    let mut after = None;
    let mut parts = Vec::with_capacity(index_limit);
    let mut data_parts = 0_u64;
    let mut rows = 0_u64;
    let mut indexes = 0_u64;
    let mut chain = Sha256::new();
    loop {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let page = writer.manifest_page(after).await?;
        if page.rows == 0 {
            break;
        }
        let (page, digest) = pool
            .run(&CancellationToken::new(), move || {
                let digest: [u8; 32] = Sha256::digest(&page.bytes).into();
                Ok((page, digest))
            })
            .await?;
        let name = format!("part-{data_parts:020}.json");
        store
            .put_manifest(
                &format!("{}{name}", publisher.base),
                &page.bytes,
                cancel.clone(),
            )
            .await
            .map_err(|_| Error::Store)?;
        let count = u64::try_from(page.rows).map_err(|_| Error::Budget)?;
        parts.push(Part {
            name,
            rows: count,
            sha256: digest,
        });
        rows = rows.checked_add(count).ok_or(Error::Budget)?;
        data_parts = data_parts.checked_add(1).ok_or(Error::Budget)?;
        let done = page.next.is_none();
        after = page.next;
        if parts.len() == index_limit || done {
            chain = publisher
                .index(
                    indexes,
                    std::mem::replace(&mut parts, Vec::with_capacity(index_limit)),
                    chain,
                )
                .await?;
            indexes = indexes.checked_add(1).ok_or(Error::Budget)?;
        }
        if done {
            break;
        }
    }
    let bytes = pool
        .run(&CancellationToken::new(), move || {
            encode(&Root {
                format: "disk-archive-manifest-v2".into(),
                rows,
                data_parts,
                index_pages: indexes,
                index_chain_sha256: chain.finalize().into(),
            })
        })
        .await?;
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    store
        .put_manifest(key, &bytes, cancel)
        .await
        .map_err(|_| Error::Store)
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
