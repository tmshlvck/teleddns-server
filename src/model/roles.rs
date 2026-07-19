//! Access-grant entities. Both join one of the user's groups to a scope; the grant *is* the row's
//! existence (no level column). `zone_role` = L2 (a whole zone); `rr_role` = L1 (a `(zone, label)`
//! record set). Uniqueness is enforced in app code (and by an index in the migrator).

pub mod zone_role {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "zone_role")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        /// FK → relativelylight auth `auth_group`.
        pub group_id: i32,
        /// FK → `zone`.
        pub zone_id: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "relativelylight::auth::group::Entity",
            from = "Column::GroupId",
            to = "relativelylight::auth::group::Column::Id"
        )]
        Group,
        #[sea_orm(
            belongs_to = "crate::model::zone::Entity",
            from = "Column::ZoneId",
            to = "crate::model::zone::Column::Id"
        )]
        Zone,
    }

    impl Related<relativelylight::auth::group::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Group.def()
        }
    }
    impl Related<crate::model::zone::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Zone.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod rr_role {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "rr_role")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        /// FK → relativelylight auth `auth_group`.
        pub group_id: i32,
        /// FK → `zone`.
        pub zone_id: i32,
        /// The record label this grant is scoped to (`@` for apex).
        pub label: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "relativelylight::auth::group::Entity",
            from = "Column::GroupId",
            to = "relativelylight::auth::group::Column::Id"
        )]
        Group,
        #[sea_orm(
            belongs_to = "crate::model::zone::Entity",
            from = "Column::ZoneId",
            to = "crate::model::zone::Column::Id"
        )]
        Zone,
    }

    impl Related<relativelylight::auth::group::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Group.def()
        }
    }
    impl Related<crate::model::zone::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Zone.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}
