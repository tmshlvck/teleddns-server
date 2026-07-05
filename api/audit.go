package api

import "log/slog"

// Audit emits the structured audit line shared by the write surfaces. It mirrors
// the admin CRUD observer (web, source=ui) so every mutation — operator UI, the
// JSON API, and the Cloudflare facade — is greppable by the same keys
// (action/type/id/actor), distinguished only by source.
func Audit(log *slog.Logger, source, action, typ, id, actor string) {
	if log == nil {
		return
	}
	log.Info("audit", "source", source, "action", action, "type", typ, "id", id, "actor", actor)
}
