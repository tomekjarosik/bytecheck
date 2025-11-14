package cmd

import (
	"github.com/tomekjarosik/bytecheck/pkg/trust"
	"time"

	"github.com/spf13/cobra"

	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"github.com/tomekjarosik/bytecheck/pkg/ui"
	"github.com/tomekjarosik/bytecheck/pkg/verifier"
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
			manifestAuditor := verifier.NewSimpleManifestAuditor()
			trustVerifier := trust.NewMultiSourceVerifier(trust.NewGitHubIssuerVerifier())
			verifier := verifier.New(sc, manifestAuditor, trustVerifier)
			pm := ui.NewProgressMonitor(3 * time.Second)
			pm.MonitorInBackground(cmd.Context(), cmd.OutOrStdout(), progressCh)
			result, err := verifier.Verify(cmd.Context(), targetDir)
			close(progressCh)
			pm.Wait()
			if err != nil {
				return err
			}

			pm.PrintFinalLine(cmd.OutOrStdout(), result.Stats) // final progress line
			ui.PrintVerificationResult(cmd.OutOrStdout(), result)

			return nil
		},
	}
	verifyCmd.Flags().DurationVarP(&freshnessInterval, "freshness-interval", "", 0,
		"Verify will reuse recently generated manifests if they are not older than this interval,"+
			" (e.g., 5s, 1m, 24h)")
	return &verifyCmd
}
