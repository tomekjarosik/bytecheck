package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"github.com/tomekjarosik/bytecheck/pkg/ui"
	"github.com/tomekjarosik/bytecheck/pkg/verify"
)

func NewVerifyCommand() *cobra.Command {
	var freshnessInterval time.Duration
	verifyCmd := cobra.Command{
		Use:   "verify [directory]",
		Short: "Verify manifest files recursively",
		Long: `Verify manifest files recursively starting from the specified directory.
If no directory is provided, the current directory is used.

This command checks that all manifest files are up-to-date and match
the current state of the files in each directory.`,
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
			verifier := verify.New(sc)
			done := make(chan bool)
			go func() {
				ui.PrintProgress(progressCh, false)
				done <- true
			}()

			result, err := verifier.Verify(cmd.Context(), targetDir)

			close(progressCh)
			<-done

			if err != nil {
				return err
			}

			// Convert verify.Result to ui.VerificationResult
			uiFailures := make([]ui.VerificationFailure, len(result.Failures))
			for i, failure := range result.Failures {
				uiFailures[i] = ui.VerificationFailure{
					Path:        failure.Path,
					Differences: failure.Differences,
				}
			}

			uiResult := ui.ConvertVerificationResult(
				result.ManifestsFound,
				result.ManifestsVerified,
				result.ManifestSkipped,
				result.AllValid,
				uiFailures,
			)

			ui.PrintVerificationResult(cmd.OutOrStdout(), uiResult)
			return nil
		},
	}
	verifyCmd.Flags().DurationVarP(&freshnessInterval, "freshness-interval", "", 0,
		"Verify will reuse recently generated manifests if they are not older than this interval,"+
			" (e.g., 5s, 1m, 24h)")
	return &verifyCmd
}
