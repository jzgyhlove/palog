// Package palog carries build metadata for the palog binary. It has no logic of
// its own beyond the release version embedded from the VERSION file.
package palog

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionRaw string

// Version is the release version embedded from the VERSION file at build time
// (e.g. "1.0.1"). It is reported by GET /api/health and shown in the console.
var Version = strings.TrimSpace(versionRaw)
