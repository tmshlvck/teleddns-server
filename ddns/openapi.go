package ddns

import "github.com/danielgtaylor/huma/v2"

// DocumentOpenAPI adds the DDNS endpoints to a Huma API's generated OpenAPI
// document **for documentation only** — the routes are served by chi (see
// RegisterRoutes), not by Huma. dyndns2 is a plain-text, status-code protocol
// that doesn't fit Huma's typed request/response model, so we describe the
// contract by writing path items directly into api.OpenAPI().Paths (a
// sanctioned bypass) rather than registering Huma operations that would try to
// handle the routes.
//
// The "basic" and "bearer" security schemes referenced here must be declared
// on the API config's Components (the caller sets those up once for the whole
// API). Call this after creating the Huma API and before serving.
func DocumentOpenAPI(api huma.API) {
	oapi := api.OpenAPI()
	if oapi.Paths == nil {
		oapi.Paths = map[string]*huma.PathItem{}
	}
	for _, p := range []struct{ path, id string }{
		{"/nic/update", "ddns-nic-update"},
		{"/ddns/update", "ddns-update"},
		{"/update", "ddns-update-short"},
	} {
		oapi.Paths[p.path] = &huma.PathItem{Get: ddnsOperation(p.id)}
	}
}

func ddnsOperation(id string) *huma.Operation {
	str := func() *huma.Schema { return &huma.Schema{Type: "string"} }
	return &huma.Operation{
		OperationID: id,
		Tags:        []string{"DDNS"},
		Summary:     "dyndns2 dynamic DNS update",
		Description: "Update the A/AAAA record set for a host. Served by a plain " +
			"chi handler; the HTTP status code is the authoritative success/" +
			"failure signal and the text/plain body carries the dyndns2 code " +
			"(good/nochg/nohost/badauth/!yours/notfqdn/abuse/911). Authenticate " +
			"with HTTP Basic or a Bearer API key (Bearer wins; Basic is rejected " +
			"for users with TOTP/SSO/passkey).",
		Security: []map[string][]string{{"basic": {}}, {"bearer": {}}},
		Parameters: []*huma.Param{
			{Name: "hostname", In: "query", Required: true, Description: "FQDN to update (trailing dot tolerated).", Schema: str()},
			{Name: "myip", In: "query", Description: "IPv4 or IPv6 literal; address family auto-detected.", Schema: str()},
			{Name: "myipv6", In: "query", Description: "IPv6 literal; processed independently of myip.", Schema: str()},
		},
		Responses: map[string]*huma.Response{
			"200": textResp("good <ip> (created/updated) or nochg <ip> (already current)."),
			"400": textResp("notfqdn — hostname invalid or myip/myipv6 not a valid address."),
			"401": textResp("badauth — missing/bad credentials, or Basic used by a 2FA/SSO/passkey user."),
			"403": textResp("!yours — authenticated but not authorized for the resolved record."),
			"404": textResp("nohost — no matching zone, or no pre-existing record at the label."),
			"429": textResp("abuse — rate limit exceeded."),
			"500": textResp("911 — internal error."),
		},
	}
}

func textResp(desc string) *huma.Response {
	return &huma.Response{
		Description: desc,
		Content:     map[string]*huma.MediaType{"text/plain": {Schema: &huma.Schema{Type: "string"}}},
	}
}
