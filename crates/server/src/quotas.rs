//! Per-user "My Cloud" quota resolution.
//!
//! ── Why a default quota needs a row, not just a number ───────────────────────
//! Two invariants already govern allocation, both enforced in `handlers::admin`:
//!
//!   * the sum of every `user_quota.quota_bytes` may not exceed the node's
//!     `node_local.contributed_bytes` (`set_quota`);
//!   * the contribution may not be lowered below what is already allocated
//!     (`set_contribution`).
//!
//! Both read the SAME table. So an instance-wide default quota applied only in
//! the upload check — an implicit allowance that exists nowhere in the table —
//! would be invisible to both: the console would keep offering capacity that
//! implicit grants had already spent, and an administrator could shrink the
//! contribution under storage users are entitled to. The over-commitment would
//! only surface as a full disk.
//!
//! Hence: the default is MATERIALISED as a real `user_quota` row on the account's
//! first upload, capped by the capacity still unallocated at that instant. The
//! grant is therefore always backed by contributed storage, both guards keep
//! seeing the truth, and the administrator sees the account in the quota list
//! exactly as if they had allocated it by hand — which they can then adjust.
//!
//! When nothing is left to allocate no row is created and the upload is refused
//! with the message it always used: an unbacked promise is worse than a refusal.

use kubuno_db::{dialect::Backend, params, DbPool};
use uuid::Uuid;

use crate::{
    errors::{P2pError, Result},
    state::AppState,
};

/// Logs a DB failure at the point it happens, before it becomes a 500.
fn db_err(op: &'static str) -> impl Fn(sqlx::Error) -> P2pError {
    move |e| {
        tracing::error!(error = %e, op, "p2pnas quotas: erreur base de données");
        P2pError::Db(e)
    }
}

/// `(quota_bytes, used_bytes)` of an existing row, or `None` if the account has
/// never been allocated anything.
async fn read_row(db: &DbPool, user_id: Uuid) -> Result<Option<(i64, i64)>> {
    db.fetch_optional_as(
        "SELECT quota_bytes, used_bytes FROM p2pnas.user_quota WHERE user_id = $1",
        params![user_id],
    )
    .await
    .map_err(db_err("read_row"))
}

/// The quota an account may rely on RIGHT NOW, without writing anything.
///
/// Returns `(quota_bytes, used_bytes, provisional)`. `provisional` is true when
/// the account has no row yet and the figure is what `ensure` would grant it on
/// its first upload — it is an announcement, not an allocation, so a second
/// account reading at the same moment may be told the same capacity.
pub async fn effective(st: &AppState, user_id: Uuid) -> Result<(i64, i64, bool)> {
    if let Some((quota, used)) = read_row(&st.db, user_id).await? {
        return Ok((quota, used, false));
    }

    let default_quota = st.instance().default_quota_bytes;
    if default_quota <= 0 {
        return Ok((0, 0, false));
    }
    Ok((default_quota.min(unallocated(&st.db).await?), 0, true))
}

/// Contributed storage not yet allocated to any user. Never negative: a
/// contribution lowered by hand below the allocated total (possible on a node
/// migrated from an older version) means "nothing left", not "owed".
async fn unallocated(db: &DbPool) -> Result<i64> {
    let contributed: i64 = db
        .fetch_scalar("SELECT contributed_bytes FROM p2pnas.node_local WHERE id = 1", params![])
        .await
        .map_err(db_err("unallocated/contributed"))?;
    let allocated: i64 = db
        .fetch_scalar(
            &format!("SELECT {} FROM p2pnas.user_quota", db.backend().sum_bigint("quota_bytes")),
            params![],
        )
        .await
        .map_err(db_err("unallocated/allocated"))?;
    Ok((contributed - allocated).max(0))
}

/// The quota to charge this upload against, materialising the instance default
/// as a real row the first time the account stores anything.
///
/// Returns `(quota_bytes, used_bytes)`. `(0, 0)` when no default is configured or
/// no capacity is left — the caller then refuses the upload as it always did.
pub async fn ensure(st: &AppState, user_id: Uuid) -> Result<(i64, i64)> {
    if let Some(row) = read_row(&st.db, user_id).await? {
        return Ok(row);
    }

    let default_quota = st.instance().default_quota_bytes;
    if default_quota <= 0 {
        return Ok((0, 0));
    }

    // One transaction, and a row lock on the single `node_local` row: the grant
    // is decided from a total that a concurrent first upload could otherwise be
    // changing, and two accounts must not both be handed the last free gigabyte.
    // `FOR UPDATE` is used where the engine has it (PostgreSQL, MySQL); on SQLite
    // the transaction already holds the single-writer permit, so the lock is
    // implicit and the clause is omitted (SQLite has no `FOR UPDATE`).
    let be = st.db.backend();
    let now = be.now();
    let lock = if be == Backend::Sqlite { "" } else { " FOR UPDATE" };

    let mut tx = st.db.begin().await.map_err(db_err("ensure/begin"))?;

    let contributed: i64 = tx
        .fetch_optional_scalar(
            &format!("SELECT contributed_bytes FROM p2pnas.node_local WHERE id = 1{lock}"),
            params![],
        )
        .await
        .map_err(db_err("ensure/lock"))?
        .ok_or_else(|| db_err("ensure/lock")(sqlx::Error::RowNotFound))?;

    // Re-read under the lock: another request for the same account may have won.
    let existing: Option<(i64, i64)> = tx
        .fetch_optional_row(
            "SELECT quota_bytes, used_bytes FROM p2pnas.user_quota WHERE user_id = $1",
            params![user_id],
        )
        .await
        .map_err(db_err("ensure/reread"))?
        .map(|r| Ok::<_, P2pError>((r.try_get::<i64>("quota_bytes")?, r.try_get::<i64>("used_bytes")?)))
        .transpose()?;
    if let Some(row) = existing {
        tx.commit().await.map_err(db_err("ensure/commit"))?;
        return Ok(row);
    }

    let allocated: i64 = tx
        .fetch_optional_scalar(
            &format!("SELECT {} FROM p2pnas.user_quota", be.sum_bigint("quota_bytes")),
            params![],
        )
        .await
        .map_err(db_err("ensure/allocated"))?
        .unwrap_or(0);

    let granted = default_quota.min((contributed - allocated).max(0));
    if granted <= 0 {
        tx.commit().await.map_err(db_err("ensure/commit"))?;
        tracing::warn!(
            %user_id, default_quota, contributed, allocated,
            "quota par défaut non attribué : capacité contribuée entièrement allouée"
        );
        return Ok((0, 0));
    }

    tx.execute(
        &format!(
            "INSERT {ignore}INTO p2pnas.user_quota (user_id, quota_bytes, updated_at)
             VALUES ($1, $2, {now}){conflict}",
            ignore = be.insert_ignore_prefix(),
            conflict = be.on_conflict_do_nothing(&["user_id"]),
        ),
        params![user_id, granted],
    )
    .await
    .map_err(db_err("ensure/insert"))?;

    // Leaves a trace in the admin event log: an allocation nobody made by hand
    // must still be explainable after the fact.
    if let Err(e) = tx
        .execute(
            "INSERT INTO p2pnas.events (kind, payload) VALUES ('quota_defaulted', $1)",
            params![serde_json::json!({ "user_id": user_id, "quota_bytes": granted })],
        )
        .await
    {
        tracing::error!(error = %e, %user_id, "journalisation de l'attribution du quota par défaut");
    }

    tx.commit().await.map_err(db_err("ensure/commit"))?;
    tracing::info!(%user_id, granted, "quota par défaut attribué au premier envoi");
    Ok((granted, 0))
}
