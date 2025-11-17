package cmd

import (
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/issuer"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"github.com/tomekjarosik/bytecheck/pkg/ui"
	"github.com/tomekjarosik/bytecheck/pkg/verifier"
)

// AuditorSchemesFlag is a custom flag type for auditor schemes
type AuditorSchemesFlag struct {
	schemes []issuer.SchemeConfig
}

// NewAuditorSchemesFlag creates a new instance
func NewAuditorSchemesFlag() *AuditorSchemesFlag {
	return &AuditorSchemesFlag{
		schemes: []issuer.SchemeConfig{},
	}
}

// String implements pflag.Value
func (a *AuditorSchemesFlag) String() string {
	var strs []string
	for _, scheme := range a.schemes {
		strs = append(strs, fmt.Sprintf("%s:%s", scheme.Name, scheme.Template))
	}
	return strings.Join(strs, ", ")
}

// Set implements pflag.Value
func (a *AuditorSchemesFlag) Set(value string) error {
	config, err := issuer.ParseSchemeConfig(value)
	if err != nil {
		return err
	}
	// Check for duplicate scheme names
	for _, existing := range a.schemes {
		if existing.Name == config.Name {
			return fmt.Errorf("auditor scheme '%s' already defined", config.Name)
		}
	}
	fmt.Printf("Adding auditor scheme '%s' with template '%s'\n", config.Name, config.Template)
	a.schemes = append(a.schemes, *config)
	return nil
}

// Type implements pflag.Value
func (a *AuditorSchemesFlag) Type() string {
	return "auditor-scheme"
}

// GetSchemes returns the parsed schemes
func (a *AuditorSchemesFlag) GetSchemes() []issuer.SchemeConfig {
	return a.schemes
}

func NewVerifyCommand() *cobra.Command {
	var freshnessInterval time.Duration
	var schemesFlag *AuditorSchemesFlag
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
			schemes := schemesFlag.GetSchemes()
			customTrustVerifiers := issuer.CreateVerifiersFromSchemes(schemes)
			builtinTrustVerifier := issuer.NewMultiSourceVerifier(issuer.NewGitHubIssuerVerifier())
			sc := scanner.New(scannerOpts...)
			manifestAuditor := verifier.NewSimpleManifestAuditor()
			auditorTrustVerifier := issuer.NewMultiSourceVerifier(append(customTrustVerifiers, builtinTrustVerifier)...)
			vr := verifier.New(sc, manifestAuditor, auditorTrustVerifier)
			pm := ui.NewProgressMonitor(3 * time.Second)
			pm.MonitorInBackground(cmd.Context(), cmd.OutOrStdout(), progressCh)
			result, err := vr.Verify(cmd.Context(), targetDir)
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
	// Initialize and register the flag
	schemesFlag = NewAuditorSchemesFlag()
	verifyCmd.Flags().VarP(schemesFlag, "auditor-scheme", "",
		"Auditor scheme in format 'name:url-template'. Can be specified multiple times.")
	return &verifyCmd
}
