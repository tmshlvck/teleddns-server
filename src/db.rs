//! Database connection + migrations. The engine is inferred from the DSN scheme; a SQLite file DSN
//! is normalized so the file is created on first run.

use sea_orm::{Database, DatabaseConnection, DbErr};

/// Connect using the configured DSN. For `sqlite://<path>` we append `?mode=rwc` so the file is
/// created if missing (matching the original server's behavior). `sqlite::memory:` is passed through.
pub async fn connect(dsn: &str) -> Result<DatabaseConnection, DbErr> {
    let normalized = normalize_dsn(dsn);
    Database::connect(&normalized).await
}

/// Turn a bare `sqlite://file` DSN into one that creates the file if absent.
fn normalize_dsn(dsn: &str) -> String {
    if let Some(rest) = dsn.strip_prefix("sqlite://") {
        if rest.starts_with(':') || rest.contains("mode=") {
            return dsn.to_string(); // memory or already parameterized
        }
        return format!("sqlite://{rest}?mode=rwc");
    }
    dsn.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_file_gets_rwc() {
        assert_eq!(normalize_dsn("sqlite://teleddns.sqlite"), "sqlite://teleddns.sqlite?mode=rwc");
        assert_eq!(normalize_dsn("sqlite::memory:"), "sqlite::memory:");
        assert_eq!(
            normalize_dsn("postgres://u:p@h/db"),
            "postgres://u:p@h/db"
        );
    }
}
