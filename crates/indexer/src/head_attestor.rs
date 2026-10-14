//! When the first cosigned head covered a ledger entry and the latest cosigned head time of its shard.
//! The recovery delay runs between the two, never on a node's clock; a head counts at a witness quorum.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::{PgConnection, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::IndexError;

/// A ledger entry and the cosigned heads around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAttestation {
    pub kind: String,
    pub event_id: Uuid,
    pub subject: String,
    /// Lowercase hex of the entry's payload hash.
    pub payload_hash: String,
    /// Time of the earliest cosigned head covering the entry; `None` until one does.
    pub covered_at: Option<OffsetDateTime>,
    /// Time of the latest cosigned head of the entry's shard.
    pub reference_at: Option<OffsetDateTime>,
}

#[async_trait]
pub trait HeadAttestor: Send + Sync {
    /// The entry with this lowercase hex entry hash, if the node holds it.
    async fn by_entry_hash(
        &self,
        conn: &mut PgConnection,
        entry_hash: &str,
    ) -> Result<Option<EntryAttestation>, IndexError>;

    /// Every held entry of this event id (an id is not unique across shards).
    async fn by_event_id(
        &self,
        conn: &mut PgConnection,
        event_id: Uuid,
    ) -> Result<Vec<EntryAttestation>, IndexError>;
}

/// Witnesses that must cosign a head before it counts; 0 when the known list has at most one member.
pub type QuorumFn = Arc<dyn Fn() -> usize + Send + Sync>;

/// Reads heads from `signed_tree_heads` (this node's shard) and `observed_sths` (mirrored shards).
pub struct SqlHeadAttestor {
    network_id: String,
    own_shard_id: String,
    quorum: QuorumFn,
}

impl SqlHeadAttestor {
    pub fn new(
        network_id: impl Into<String>,
        own_shard_id: impl Into<String>,
        quorum: QuorumFn,
    ) -> Self {
        Self {
            network_id: network_id.into(),
            own_shard_id: own_shard_id.into(),
            quorum,
        }
    }
}

struct Head {
    tree_size: i64,
    root_hash: String,
    created_at: OffsetDateTime,
}

struct Located {
    shard_id: String,
    own: bool,
    seq: i64,
    kind: String,
    event_id: Uuid,
    subject: String,
    payload_hash: String,
}

impl SqlHeadAttestor {
    /// The shard's heads by ascending size, each with its quorum time when cosigned by enough witnesses.
    async fn cosigned_heads(
        &self,
        conn: &mut PgConnection,
        shard_id: &str,
        own: bool,
        from_size: i64,
    ) -> Result<Vec<(Head, OffsetDateTime)>, IndexError> {
        let rows = if own {
            sqlx::query(
                "SELECT tree_size, root_hash, created_at FROM signed_tree_heads \
                 WHERE network_id = $1 AND tree_size >= $2 ORDER BY tree_size",
            )
            .bind(&self.network_id)
            .bind(from_size)
            .fetch_all(&mut *conn)
            .await?
        } else {
            sqlx::query(
                "SELECT DISTINCT tree_size, root_hash, created_at FROM observed_sths \
                 WHERE network_id = $1 AND shard_id = $2 AND tree_size >= $3 ORDER BY tree_size",
            )
            .bind(&self.network_id)
            .bind(shard_id)
            .bind(from_size)
            .fetch_all(&mut *conn)
            .await?
        };
        let quorum = (self.quorum)();
        let mut out = Vec::new();
        for row in rows {
            let head = Head {
                tree_size: row.try_get("tree_size")?,
                root_hash: row.try_get("root_hash")?,
                created_at: row.try_get("created_at")?,
            };
            if quorum == 0 {
                let at = head.created_at;
                out.push((head, at));
                continue;
            }
            // The quorum-th latest cosignature time: at least `quorum` witnesses had seen the head by then.
            let times: Vec<OffsetDateTime> = sqlx::query_scalar(
                "SELECT observed_at FROM witness_cosignatures \
                 WHERE network_id = $1 AND shard_id = $2 AND tree_size = $3 AND root_hash = $4 \
                 ORDER BY observed_at DESC",
            )
            .bind(&self.network_id)
            .bind(shard_id)
            .bind(head.tree_size)
            .bind(&head.root_hash)
            .fetch_all(&mut *conn)
            .await?;
            if let Some(at) = times.get(quorum - 1) {
                let at = (*at).max(head.created_at);
                out.push((head, at));
            }
        }
        Ok(out)
    }

    async fn attest(
        &self,
        conn: &mut PgConnection,
        entry: Located,
    ) -> Result<EntryAttestation, IndexError> {
        let heads = self
            .cosigned_heads(conn, &entry.shard_id, entry.own, entry.seq)
            .await?;
        // `covered_at` is the signed head time; `reference_at` is the cosignature time of the latest head.
        let covered_at = heads.first().map(|(head, _)| head.created_at);
        let reference_at = heads.last().map(|(_, at)| *at);
        Ok(EntryAttestation {
            kind: entry.kind,
            event_id: entry.event_id,
            subject: entry.subject,
            payload_hash: entry.payload_hash,
            covered_at,
            reference_at,
        })
    }

    fn located(
        row: &sqlx::postgres::PgRow,
        shard_id: String,
        own: bool,
    ) -> Result<Located, IndexError> {
        Ok(Located {
            shard_id,
            own,
            seq: row.try_get("seq")?,
            kind: row.try_get("kind")?,
            event_id: row.try_get("event_id")?,
            subject: row.try_get("subject")?,
            payload_hash: row.try_get("payload_hash")?,
        })
    }
}

#[async_trait]
impl HeadAttestor for SqlHeadAttestor {
    async fn by_entry_hash(
        &self,
        conn: &mut PgConnection,
        entry_hash: &str,
    ) -> Result<Option<EntryAttestation>, IndexError> {
        let own = sqlx::query(
            "SELECT seq, kind, event_id, subject, payload_hash FROM ledger_entries WHERE entry_hash = $1",
        )
        .bind(entry_hash)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(row) = own {
            let located = Self::located(&row, self.own_shard_id.clone(), true)?;
            return self.attest(conn, located).await.map(Some);
        }
        let mirrored = sqlx::query(
            "SELECT shard_id, seq, kind, event_id, subject, payload_hash FROM mirrored_entries \
             WHERE network_id = $1 AND entry_hash = $2",
        )
        .bind(&self.network_id)
        .bind(entry_hash)
        .fetch_optional(&mut *conn)
        .await?;
        match mirrored {
            Some(row) => {
                let shard_id: String = row.try_get("shard_id")?;
                let located = Self::located(&row, shard_id, false)?;
                self.attest(conn, located).await.map(Some)
            }
            None => Ok(None),
        }
    }

    async fn by_event_id(
        &self,
        conn: &mut PgConnection,
        event_id: Uuid,
    ) -> Result<Vec<EntryAttestation>, IndexError> {
        let mut found = Vec::new();
        let own = sqlx::query(
            "SELECT seq, kind, event_id, subject, payload_hash FROM ledger_entries WHERE event_id = $1",
        )
        .bind(event_id)
        .fetch_all(&mut *conn)
        .await?;
        for row in own {
            found.push(Self::located(&row, self.own_shard_id.clone(), true)?);
        }
        let mirrored = sqlx::query(
            "SELECT shard_id, seq, kind, event_id, subject, payload_hash FROM mirrored_entries \
             WHERE network_id = $1 AND event_id = $2",
        )
        .bind(&self.network_id)
        .bind(event_id)
        .fetch_all(&mut *conn)
        .await?;
        for row in mirrored {
            let shard_id: String = row.try_get("shard_id")?;
            found.push(Self::located(&row, shard_id, false)?);
        }
        let mut out = Vec::new();
        for located in found {
            out.push(self.attest(conn, located).await?);
        }
        Ok(out)
    }
}
