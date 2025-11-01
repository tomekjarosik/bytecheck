package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/tomekjarosik/bytecheck/pkg/generator"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"github.com/tomekjarosik/bytecheck/pkg/ui"
	"io"
	"time"
)

func printWriteResult(w io.Writer, result generator.Stats) {
	totalDirectories := result.DirsProcessed + result.CachedProcessed

	if totalDirectories == 0 {
		ui.PrintWarning("no directories processed")
		return
	}
	fmt.Fprintf(w, "processed %d directory(s) (%d cached)\n", totalDirectories, result.CachedProcessed)
	for _, m := range result.ManifestsGenerated {
		fmt.Fprintf(w, "manifest '%s' generated\n", m)
	}
}

func NewWriteCmd() *cobra.Command {
	writeCmd := cobra.Command{
		Use:   "write [directory]",
		Short: "Generate and write manifest files recursively",
		Long: `Generate and write manifest files recursively starting from the specified directory.
If no directory is provided, the current directory is used.

The write command can be optimized using the --skip-recent flag to avoid
recalculating directories where the manifest is newer than the freshness limit.`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) > 0 {
				targetDir = args[0]
			}

			progressCh := make(chan scanner.Stats, 10)
			sc := scanner.New(scanner.WithManifestFreshnessLimit(5*time.Second), scanner.WithProgressChannel(progressCh))
			gen := generator.New(sc)

			go ui.PrintProgress(progressCh, false)

			err := gen.Generate(cmd.Context(), targetDir)

			if err != nil {
				return err
			}
			stats := gen.GetStats()
			printWriteResult(cmd.OutOrStdout(), stats)
			return nil
		},
	}

	return &writeCmd
}
