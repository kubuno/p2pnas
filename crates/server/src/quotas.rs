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
async fn read_row(db: &sqlx::PgPool, user_id: Uuid) -> Result<Option<(i64, i64)>> {
    sqlx::query_as("SELECT quota_bytes, used_bytes FROM p2pnas.user_quota WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(db)
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
async fn unallocated(db: &sqlx::PgPool) -> Result<i64> {
    let contributed: i64 = sqlx::query_scalar("SELECT contributed_bytes FROM p2pnas.node_local WHERE id = 1")
        .fetch_one(db)
        .await
        .map_err(db_err("unallocated/contributed"))?;
    let allocated: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(quota_bytes), 0)::BIGINT FROM p2pnas.user_quota")
        .fetch_one(db)
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
    let mut tx = st.db.begin().await.map_err(db_err("ensure/begin"))?;

    let contributed: i64 =
        sqlx::query_scalar("SELECT contributed_bytes FROM p2pnas.node_local WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err("ensure/lock"))?;

    // Re-read under the lock: another request for the same account may have won.
    let existing: Option<(i64, i64)> =
        sqlx::query_as("SELECT quota_bytes, used_bytes FROM p2pnas.user_quota WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err("ensure/reread"))?;
    if let Some(row) = existing {
        tx.commit().await.map_err(db_err("ensure/commit"))?;
        return Ok(row);
    }

    let allocated: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(quota_bytes), 0)::BIGINT FROM p2pnas.user_quota")
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("ensure/allocated"))?;

    let granted = default_quota.min((contributed - allocated).max(0));
    if granted <= 0 {
        tx.commit().await.map_err(db_err("ensure/commit"))?;
        tracing::warn!(
            %user_id, default_quota, contributed, allocated,
            "quota par défaut non attribué : capacité contribuée entièrement allouée"
        );
        return Ok((0, 0));
    }

    sqlx::query(
        "INSERT INTO p2pnas.user_quota (user_id, quota_bytes, updated_at)
         VALUES ($1, $2, now())
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(granted)
    .execute(&mut *tx)
    .await
    .map_err(db_err("ensure/insert"))?;

    // Leaves a trace in the admin event log: an allocation nobody made by hand
    // must still be explainable after the fact.
    if let Err(e) = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('quota_defaulted', $1)")
        .bind(serde_json::json!({ "user_id": user_id, "quota_bytes": granted }))
        .execute(&mut *tx)
        .await
    {
        tracing::error!(error = %e, %user_id, "journalisation de l'attribution du quota par défaut");
    }

    tx.commit().await.map_err(db_err("ensure/commit"))?;
    tracing::info!(%user_id, granted, "quota par défaut attribué au premier envoi");
    Ok((granted, 0))
}
