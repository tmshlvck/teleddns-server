package web

import (
	"fmt"
	"net/http"
)

// SwaggerHandler serves a minimal Swagger UI page (loaded from the unpkg CDN)
// wired to the OpenAPI spec at specURL (e.g. "/openapi.json"). It is a static,
// unauthenticated page — like the spec itself — so mount it outside the
// CSRF/session group.
func SwaggerHandler(specURL string) http.HandlerFunc {
	page := fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>teleddns-server API — Swagger UI</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
<script>
window.onload = () => {
  window.ui = SwaggerUIBundle({ url: %q, dom_id: '#swagger-ui' });
};
</script>
</body>
</html>`, specURL)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	}
}
