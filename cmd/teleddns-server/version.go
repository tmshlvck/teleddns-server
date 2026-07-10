package main

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
)

// version is the release version. It is "dev" for a plain `go build` and is
// overridden at release time with:
//
//	go build -ldflags "-X main.version=v0.3.0" ./cmd/teleddns-server
//
// When the binary is produced with `go install <module>@vX.Y.Z`, the module
// version from the build info is used instead (see resolveVersion).
var version = "dev"

// pseudoVersion matches Go module pseudo-versions like
// v0.0.0-20260710200817-3e6171d97430 — the synthetic version go build stamps
// for an untagged commit. We show the short VCS revision ourselves, so a
// pseudo-version is just noise; a plain local build stays "dev".
var pseudoVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+-(\d+\.)?\d{14}-[0-9a-f]{12}`)

// resolveVersion returns the release version and the short VCS revision (with a
// "-dirty" suffix for an uncommitted tree), drawn from -ldflags or the embedded
// build info.
func resolveVersion() (ver, revision string) {
	ver = version
	if bi, ok := debug.ReadBuildInfo(); ok {
		// go install module@vX.Y.Z stamps the module version; prefer it over
		// the "dev" default, but never over an explicit -ldflags value, and
		// never a noisy pseudo-version (we show the revision separately).
		if ver == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" &&
			!pseudoVersion.MatchString(bi.Main.Version) {
			ver = bi.Main.Version
		}
		var modified bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if len(s.Value) >= 7 {
					revision = s.Value[:7]
				} else {
					revision = s.Value
				}
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if modified && revision != "" {
			revision += "-dirty"
		}
	}
	return ver, revision
}

// versionString is the full one-line version for `--version` and logs, e.g.
// "teleddns-server v0.3.0 (a1b2c3d, go1.26.4)".
func versionString() string {
	ver, revision := resolveVersion()
	parts := ""
	if revision != "" {
		parts = revision + ", "
	}
	return fmt.Sprintf("teleddns-server %s (%s%s)", ver, parts, runtime.Version())
}

// versionShort is the compact version for the web footer, e.g. "v0.3.0" or
// "dev (a1b2c3d-dirty)".
func versionShort() string {
	ver, revision := resolveVersion()
	if revision != "" {
		return fmt.Sprintf("%s (%s)", ver, revision)
	}
	return ver
}
