package model

import (
	"log/slog"

	"gorm.io/gorm"
)

// registerMutationLog installs GORM after-callbacks that emit one INFO line per
// write — create / update / delete — naming the operation, table and the number
// of rows affected. This makes every DB change visible at the default log level
// (the full parameterized SQL, with values, remains a DEBUG-only gorm trace).
//
// Raw column values are deliberately not logged here: rows can carry password
// or token hashes, and the table+rows summary is enough to audit "what changed"
// without leaking secrets into the journal.
func registerMutationLog(db *gorm.DB, log *slog.Logger) error {
	l := log.With("component", "db")
	mk := func(op string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			if tx.Error != nil || tx.Statement == nil {
				return
			}
			l.Info("write", "op", op, "table", tx.Statement.Table, "rows", tx.Statement.RowsAffected)
		}
	}
	if err := db.Callback().Create().After("gorm:create").Register("teleddns:log_create", mk("create")); err != nil {
		return err
	}
	if err := db.Callback().Update().After("gorm:update").Register("teleddns:log_update", mk("update")); err != nil {
		return err
	}
	return db.Callback().Delete().After("gorm:delete").Register("teleddns:log_delete", mk("delete"))
}
