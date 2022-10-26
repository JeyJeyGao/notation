package version

var (
	// Version shows the current notation version, optionally with pre-release.
	Version = "v0.11.0-alpha.4"

	// BuildMetadata stores the build metadata.
	// it will be overridden by environment variable `BUILD_METADATA` when
	// execute `make build` command.
	//
	// if tag was
	BuildMetadata = "unreleased"

	// GitCommit stores the git HEAD commit id
	GitCommit = ""
)

// GetVersion returns the version string in SemVer 2.
func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "+" + BuildMetadata
}
