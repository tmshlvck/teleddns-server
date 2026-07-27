//! The L1/L2/L3 authorization model (PRD §3). Pure level algebra + the effective-level lookup, shared
//! by the DDNS endpoint, the native API, and the Cloudflare facade. The `min()` cap ensures a leaked
//! low-level token never escalates past its own level.

use relativelylight::auth::group;
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};

/// Access level, ordered so comparisons express "at least".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    None = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}

impl Level {
    pub fn from_i32(n: i32) -> Level {
        match n {
            n if n >= 3 => Level::L3,
            2 => Level::L2,
            1 => Level::L1,
            _ => Level::None,
        }
    }
    pub fn as_i32(self) -> i32 {
        self as i32
    }
    /// The lower of two levels (the token-cap rule).
    pub fn cap(self, other: Level) -> Level {
        if self <= other {
            self
        } else {
            other
        }
    }
}

/// `min(token_level, effective) >= need` — the single authorization predicate.
pub fn allowed(token_level: Level, effective: Level, need: Level) -> bool {
    token_level.cap(effective) >= need
}

/// The level a caller holds **globally**, with no zone to scope against: L3 for the admin group, and
/// nothing otherwise — a zone-role or rr-role grant is scoped to its target and confers no global
/// authority. Pair it with [`allowed`] for operations that have no zone to check yet (creating one) or
/// whose blast radius is the whole zone plus its contents (deleting one), so those go through the
/// token cap like every other decision instead of reading `is_admin` directly.
pub fn global_level(is_admin: bool) -> Level {
    if is_admin {
        Level::L3
    } else {
        Level::None
    }
}

/// The level a set of groups grants at a specific `(zone, label)`. `label = None` asks only about
/// zone-wide authority (admin/L2). Admin group → L3; a zone-role → L2; an rr-role on the label → L1.
pub async fn effective_level<C: ConnectionTrait>(
    db: &C,
    group_ids: &[i32],
    is_admin: bool,
    zone_id: i32,
    label: Option<&str>,
) -> Result<Level, DbErr> {
    if is_admin {
        return Ok(Level::L3);
    }
    if group_ids.is_empty() {
        return Ok(Level::None);
    }
    let has_zone = crate::model::zone_role::Entity::find()
        .filter(crate::model::zone_role::Column::GroupId.is_in(group_ids.to_vec()))
        .filter(crate::model::zone_role::Column::ZoneId.eq(zone_id))
        .one(db)
        .await?
        .is_some();
    if has_zone {
        return Ok(Level::L2);
    }
    if let Some(label) = label {
        let has_rr = crate::model::rr_role::Entity::find()
            .filter(crate::model::rr_role::Column::GroupId.is_in(group_ids.to_vec()))
            .filter(crate::model::rr_role::Column::ZoneId.eq(zone_id))
            .filter(crate::model::rr_role::Column::Label.eq(label))
            .one(db)
            .await?
            .is_some();
        if has_rr {
            return Ok(Level::L1);
        }
    }
    Ok(Level::None)
}

/// The highest level a user could ever hold (for capping the token-mint picker): L3 if admin, else L2
/// if they hold any zone-role, else L1 if any rr-role, else None.
pub async fn user_max_level<C: ConnectionTrait>(
    db: &C,
    group_ids: &[i32],
    is_admin: bool,
) -> Result<Level, DbErr> {
    if is_admin {
        return Ok(Level::L3);
    }
    if group_ids.is_empty() {
        return Ok(Level::None);
    }
    let any_zone = crate::model::zone_role::Entity::find()
        .filter(crate::model::zone_role::Column::GroupId.is_in(group_ids.to_vec()))
        .one(db)
        .await?
        .is_some();
    if any_zone {
        return Ok(Level::L2);
    }
    let any_rr = crate::model::rr_role::Entity::find()
        .filter(crate::model::rr_role::Column::GroupId.is_in(group_ids.to_vec()))
        .one(db)
        .await?
        .is_some();
    Ok(if any_rr { Level::L1 } else { Level::None })
}

/// Resolve a user's group ids + names and admin flag in one place.
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
    let is_admin = names.iter().any(|n| n == crate::app::ADMIN_GROUP);
    Ok((ids, names, is_admin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_and_allowed() {
        // An L1 token held by an admin (effective L3) can still only do L1.
        assert!(allowed(Level::L1, Level::L3, Level::L1));
        assert!(!allowed(Level::L1, Level::L3, Level::L2));
        // An L3 token with only L2 effective is capped to L2.
        assert!(allowed(Level::L3, Level::L2, Level::L2));
        assert!(!allowed(Level::L3, Level::L2, Level::L3));
        // No effective access denies everything.
        assert!(!allowed(Level::L3, Level::None, Level::L1));
    }

    #[test]
    fn a_capped_token_cannot_reach_a_global_operation() {
        // Zone create/delete need L3 *through the cap*: an admin who deliberately minted a
        // low-level key must not be able to create or delete zones with it, which is the whole
        // promise of the level picker ("an L1 key for a router can't escalate").
        let admin = global_level(true);
        assert!(allowed(Level::L3, admin, Level::L3), "an L3 token of an admin: yes");
        assert!(!allowed(Level::L2, admin, Level::L3), "an L2 token of an admin: no");
        assert!(!allowed(Level::L1, admin, Level::L3), "an L1 token of an admin: no");
        // A non-admin holds nothing globally, whatever their token says or their zone grants are.
        assert_eq!(global_level(false), Level::None);
        assert!(!allowed(Level::L3, global_level(false), Level::L3));
    }

    #[test]
    fn level_from_i32() {
        assert_eq!(Level::from_i32(0), Level::None);
        assert_eq!(Level::from_i32(1), Level::L1);
        assert_eq!(Level::from_i32(5), Level::L3);
    }
}
