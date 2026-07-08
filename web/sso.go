package web

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/tmshlvck/gone/auth"

	"github.com/tmshlvck/teleddns-server/model"
)

// RegisterSSO builds gone OIDC providers from config and registers them on ag.
// It MUST be called before ag.RegisterRoutes (RegisterAdmin), which reads the
// provider list to render the "Sign in with X" buttons. AddOIDCProvider performs
// OIDC discovery against each issuer, so a misconfigured or unreachable provider
// fails startup with a clear error. Group provisioning (rules → managed-set
// reconcile on every login) is handled inside gone; see PRD §9.7.
func RegisterSSO(ag *auth.AuthGORM, cfg model.Config, log *slog.Logger) error {
	if len(cfg.SSOProviders) == 0 {
		return nil
	}
	base := strings.TrimRight(cfg.PublicURL, "/")
	if base == "" {
		return fmt.Errorf("public_url is required when sso_providers is set")
	}
	for _, p := range cfg.SSOProviders {
		if p.Name == "" || p.Issuer == "" || p.ClientID == "" {
			return fmt.Errorf("sso provider %q: name, issuer and client_id are all required", p.Name)
		}
		prov := auth.OIDCProvider{
			Name:              p.Name,
			DisplayName:       p.DisplayName,
			IssuerURL:         p.Issuer,
			ClientID:          p.ClientID,
			ClientSecret:      p.ClientSecret,
			RedirectURL:       base + "/login/sso/" + p.Name + "/callback",
			Scopes:            p.Scopes,
			GroupRules:        toSSORules(p.GroupRules),
			CreateGroups:      p.CreateGroups,
			AutoLinkByEmail:   p.AutoLinkByEmail,
			DisableAutoCreate: p.DisableAutoCreate,
		}
		if err := ag.AddOIDCProvider(prov); err != nil {
			return fmt.Errorf("sso provider %q: %w", p.Name, err)
		}
		log.Info("registered SSO provider", "name", p.Name, "issuer", p.Issuer, "group_rules", len(p.GroupRules))
	}
	return nil
}

// toSSORules maps the config rules onto gone's auth.SSOGroupRule (identical
// shape; kept separate so config isn't coupled to the auth package).
func toSSORules(rules []model.SSOGroupRule) []auth.SSOGroupRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]auth.SSOGroupRule, len(rules))
	for i, r := range rules {
		out[i] = auth.SSOGroupRule{Claim: r.Claim, Equals: r.Equals, Regex: r.Regex, Groups: r.Groups}
	}
	return out
}
