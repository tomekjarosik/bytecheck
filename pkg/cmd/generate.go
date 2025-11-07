package cmd

import (
	"github.com/spf13/cobra"
	"github.com/tomekjarosik/bytecheck/pkg/generator"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"github.com/tomekjarosik/bytecheck/pkg/ui"
	"time"
)

func NewGenerateCmd() *cobra.Command {
	var freshnessInterval time.Duration
	generateCmd := cobra.Command{
		Use:   "generate [directory]",
		Short: "Generate and write manifest files recursively",
		Long: `Generate and write manifest files recursively starting from the specified directory.
If no directory is provided, the current directory is used.

The generate command can be optimized using the --freshness-interval flag to avoid
recalculating directories where the manifest is newer than the freshness interval.`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) > 0 {
				targetDir = args[0]
			}

			progressCh := make(chan *scanner.Stats, 10)
			scannerOpts := []scanner.Option{scanner.WithProgressChannel(progressCh)}
			if freshnessInterval > 0 {
				scannerOpts = append(scannerOpts, scanner.WithManifestFreshnessLimit(freshnessInterval))
			}
			sc := scanner.New(scannerOpts...)
			gen := generator.New(sc)

			go ui.PrintProgress(progressCh, false)

			err := gen.Generate(cmd.Context(), targetDir)

			if err != nil {
				return err
			}
			stats := gen.GetStats()
			ui.PrintWriteResult(cmd.OutOrStdout(), stats.DirsProcessed(), stats.CachedProcessed(), stats.ManifestsGenerated)
			return nil
		},
	}
	generateCmd.Flags().DurationVarP(&freshnessInterval, "freshness-interval", "", 0,
		"Generate will reuse recently generated manifests if they are not older than this interval,"+
			" (e.g., 5s, 1m, 24h)")
	return &generateCmd
}
