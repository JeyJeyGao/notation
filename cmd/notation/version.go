package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/notaryproject/notation/internal/version"
	"github.com/spf13/cobra"
)

func versionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show the notation version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersion()
		},
	}

	return cmd
}

func runVersion() error {
	fmt.Printf("Notation: Notary v2, A tool to sign, store, and verify artifacts.\n\n")

	fmt.Printf("Version:     %s\n", version.Version)
	fmt.Printf("Go version:  %s\n", runtime.Version())

	// please build with `make build` command to include git commit information
	// BuildMetadata = {CommitId}.{TreeStatus}
	if version.BuildMetadata != "" {
		if metadata := strings.Split(version.BuildMetadata, "."); len(metadata) == 2 {
			fmt.Printf("Git commit:  %s\n", metadata[0])
		}
	}
	return nil
}
