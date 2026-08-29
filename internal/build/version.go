package build

import "fmt"

var (
	// Version is the current version string.
	Version = "1.0.0"
	// Commit is the build commit hash.
	Commit = "none"
	// BuildDate is the timestamp of compilation.
	BuildDate = "unknown"
)

// String returns formatted build info string.
func String() string {
	return fmt.Sprintf("ZeroTrust v%s (commit: %s, built: %s)", Version, Commit, BuildDate)
}
