//! Resource-record entities — one SeaORM table per RR type (matching the one-table-per-type model,
//! which maps 1:1 to relativelylight's per-entity CRUD/admin). Every record shares
//! `(id, zone_id, label, ttl)` plus type-specific rdata. The DDNS path only ever touches A and AAAA.
//!
//! Each submodule is a standard SeaORM entity with a `belongs_to` relation to `zone` (so the admin UI
//! shows a zone picker). Shared behavior (BIND rendering, validation, the unified API view) lives in
//! `backend::zonefile` and `api::record_view`, keyed off these structs.

/// Generate a standard RR entity module: common columns + the given extra rdata columns, plus the
/// `belongs_to zone` relation. `$table` is the SQL table name (also the type discriminator source).
macro_rules! rr_entity {
    ($modname:ident, $table:literal, { $( $(#[$fattr:meta])* $field:ident : $ty:ty ),* $(,)? }) => {
        pub mod $modname {
            use sea_orm::entity::prelude::*;

            #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
            #[sea_orm(table_name = $table)]
            pub struct Model {
                #[sea_orm(primary_key)]
                pub id: i32,
                pub zone_id: i32,
                pub label: String,
                pub ttl: i32,
                $( $(#[$fattr])* pub $field : $ty, )*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {
                #[sea_orm(
                    belongs_to = "crate::model::zone::Entity",
                    from = "Column::ZoneId",
                    to = "crate::model::zone::Column::Id"
                )]
                Zone,
            }

            impl Related<crate::model::zone::Entity> for Entity {
                fn to() -> RelationDef {
                    Relation::Zone.def()
                }
            }

            // On create/update through ANY path (the admin UI, the API, DDNS), bump the parent zone's
            // serial and enqueue a backend push. Deletes are enqueued explicitly by the write paths
            // (bulk deletes bypass per-row hooks).
            #[async_trait::async_trait]
            impl ActiveModelBehavior for ActiveModel {
                async fn after_save<C>(model: Model, db: &C, _insert: bool) -> Result<Model, DbErr>
                where
                    C: ConnectionTrait,
                {
                    crate::sync::on_rr_saved(db, model.zone_id).await?;
                    Ok(model)
                }
            }
        }
    };
}

rr_entity!(a, "rr_a", { value: String });
rr_entity!(aaaa, "rr_aaaa", { value: String });
rr_entity!(ns, "rr_ns", { value: String });
rr_entity!(ptr, "rr_ptr", { value: String });
rr_entity!(cname, "rr_cname", { value: String });
rr_entity!(txt, "rr_txt", { value: String });
rr_entity!(mx, "rr_mx", { priority: i32, value: String });
rr_entity!(srv, "rr_srv", { priority: i32, weight: i32, port: i32, value: String });
rr_entity!(caa, "rr_caa", { flag: i32, tag: String, value: String });
rr_entity!(sshfp, "rr_sshfp", { algorithm: i32, hash_type: i32, fingerprint: String });
rr_entity!(tlsa, "rr_tlsa", { cert_usage: i32, selector: i32, matching_type: i32, cert_data: String });
rr_entity!(dnskey, "rr_dnskey", { flags: i32, protocol: i32, algorithm: i32, public_key: String });
rr_entity!(ds, "rr_ds", { key_tag: i32, algorithm: i32, digest_type: i32, digest: String });
rr_entity!(naptr, "rr_naptr", { order: i32, preference: i32, flags: String, service: String, regexp: String, replacement: String });

/// The set of RR type tags, in a stable order (used for iteration, metrics, the admin UI).
pub const RR_TYPES: &[&str] = &[
    "A", "AAAA", "NS", "PTR", "CNAME", "TXT", "MX", "SRV", "CAA", "SSHFP", "TLSA", "DNSKEY", "DS",
    "NAPTR",
];
