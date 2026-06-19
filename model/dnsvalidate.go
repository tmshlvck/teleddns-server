package model

import (
	"fmt"
	"strings"

	"github.com/tmshlvck/gone/crud"
)

// DNS field validators (PRD Part A §4.2). These are gone crud.Validator
// values — func(any) error — composed onto MetaField.FieldValidate in the
// admin wiring.

// ValLabel checks an RR label: either the literal "@" (apex), or a name that
// is not all-digits, does not start/end with "-", uses only [A-Za-z0-9.-], and
// is ≤ 63 chars. Empty passes (pair with crud.NotEmpty when required). Go's
// RE2 has no look-around, so this is hand-rolled rather than a single regexp.
func ValLabel(value any) error {
	s, ok := value.(string)
	if !ok || s == "" || s == "@" {
		return nil
	}
	if len(s) > 63 {
		return fmt.Errorf("must be at most 63 characters")
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return fmt.Errorf("must not start or end with '-'")
	}
	allDigits := true
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			allDigits = false
		case r == '.' || r == '-':
			allDigits = false
		default:
			return fmt.Errorf("may contain only letters, digits, '.' and '-'")
		}
	}
	if allDigits {
		return fmt.Errorf("must not be all digits")
	}
	return nil
}

// ValDNSName checks a hostname-shaped value (e.g. an NS/CNAME/MX target):
// dot-separated labels of [A-Za-z0-9-] not starting/ending with '-', optional
// trailing dot. Empty passes.
func ValDNSName(value any) error {
	s, ok := value.(string)
	if !ok || s == "" {
		return nil
	}
	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return fmt.Errorf("must be a valid DNS name")
	}
	for _, lbl := range strings.Split(name, ".") {
		if lbl == "" || len(lbl) > 63 || strings.HasPrefix(lbl, "-") || strings.HasSuffix(lbl, "-") {
			return fmt.Errorf("must be a valid DNS name")
		}
		for _, r := range lbl {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
				return fmt.Errorf("must be a valid DNS name")
			}
		}
	}
	return nil
}

// ValFQDN is ValDNSName plus a required trailing dot — used for a zone origin.
func ValFQDN(value any) error {
	s, ok := value.(string)
	if !ok || s == "" {
		return nil
	}
	if !strings.HasSuffix(s, ".") {
		return fmt.Errorf("must be fully qualified (end with '.')")
	}
	return ValDNSName(s)
}

// OneOfString fails for a non-empty string not in allowed. Empty passes.
func OneOfString(allowed ...string) crud.Validator {
	return func(value any) error {
		s, ok := value.(string)
		if !ok || s == "" {
			return nil
		}
		for _, a := range allowed {
			if s == a {
				return nil
			}
		}
		return fmt.Errorf("must be one of: %s", strings.Join(allowed, ", "))
	}
}
