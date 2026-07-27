//! Authorization: three named roles over two grant tables (PRD §3), shared by the DDNS endpoint, the
//! native API and the Cloudflare facade.
//!
//! The roles are **nested scopes**, not degrees of privilege, and a grant *is* the existence of its
//! row — there is no level column anywhere and no arithmetic:
//!
//! | Role | Held by | May |
//! |---|---|---|
//! | **Superadmin** | membership of the `admin` group ([`crate::app::ADMIN_GROUP`]) | everything: the operator console, and creating/deleting zones |
//! | **Zone Manager** | a `zone_role` row for the zone | everything *inside* that zone — any record type, create, update, delete |
//! | **RR Manager** | an `rr_role` row for a `(zone, label)` | create/update the **A/AAAA** set at exactly that name: what a DDNS client needs, and nothing more |
//!
//! The caller is whoever authenticated (see [`crate::principal`]): a console session, HTTP Basic, or a
//! bearer token — and a token carries **no rights of its own**. It is simply its owner, resolved from
//! the database on every request, so deleting a grant, removing a group membership or deactivating the
//! account disarms that user's keys at once, with no key bookkeeping.
//!
//! Two predicates express the whole model and every surface calls one of them. Mind the nesting: a Zone
//! Manager satisfies [`rr_manager`] anywhere in their zone and a Superadmin satisfies both everywhere,
//! but it does **not** nest the other way — an RR Manager cannot delete records or touch other record
//! types, because the DDNS path they exist for never needs to.

use relativelylight::auth::group;
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};

/// Whether the caller may manage **this zone**: every record in it, of any type, including deletes.
/// True for a Superadmin, or for a Zone Manager grant on the zone.
pub async fn zone_manager<C: ConnectionTrait>(
    db: &C,
    group_ids: &[i32],
    is_superadmin: bool,
    zone_id: i32,
) -> Result<bool, DbErr> {
    if is_superadmin {
        return Ok(true);
    }
    if group_ids.is_empty() {
        return Ok(false);
    }
    Ok(crate::model::zone_role::Entity::find()
        .filter(crate::model::zone_role::Column::GroupId.is_in(group_ids.to_vec()))
        .filter(crate::model::zone_role::Column::ZoneId.eq(zone_id))
        .one(db)
        .await?
        .is_some())
}

/// Whether the caller may create or update the **A/AAAA set at this exact name**: an RR Manager grant
/// on `(zone, label)`, or anyone who manages the whole zone.
pub async fn rr_manager<C: ConnectionTrait>(
    db: &C,
    group_ids: &[i32],
    is_superadmin: bool,
    zone_id: i32,
    label: &str,
) -> Result<bool, DbErr> {
    if zone_manager(db, group_ids, is_superadmin, zone_id).await? {
        return Ok(true);
    }
    Ok(crate::model::rr_role::Entity::find()
        .filter(crate::model::rr_role::Column::GroupId.is_in(group_ids.to_vec()))
        .filter(crate::model::rr_role::Column::ZoneId.eq(zone_id))
        .filter(crate::model::rr_role::Column::Label.eq(label))
        .one(db)
        .await?
        .is_some())
}

/// Resolve a user's group ids + names and Superadmin flag in one place. The flag is membership of
/// [`crate::app::ADMIN_GROUP`]: the group is named `admin` (it is relativelylight's
/// `Auth::admin_group` too, which gates the console), and the *role* it confers is Superadmin.
pub async fn user_groups<C: ConnectionTrait>(
    db: &C,
    user_id: i32,
) -> Result<(Vec<i32>, Vec<String>, bool), DbErr> {
    use relativelylight::auth::user_group;
    let ids: Vec<i32> = user_group::Entity::find()
        .filter(user_group::Column::UserId.eq(user_id))
        .all(db)
        .await?
        .into_iter()
        .map(|r| r.group_id)
        .collect();
    if ids.is_empty() {
        return Ok((ids, vec![], false));
    }
    let names: Vec<String> = group::Entity::find()
        .filter(group::Column::Id.is_in(ids.clone()))
        .all(db)
        .await?
        .into_iter()
        .map(|g| g.name)
        .collect();
    let is_superadmin = names.iter().any(|n| n == crate::app::ADMIN_GROUP);
    Ok((ids, names, is_superadmin))
}
