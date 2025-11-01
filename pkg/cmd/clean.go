package cmd

import (
	"context"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/traverse"
	"github.com/tomekjarosik/bytecheck/pkg/ui"
	"os"
	"path/filepath"
)

func NewCleanCommand() *cobra.Command {
	cleanCmd := cobra.Command{
		Use:   "clean [directory]",
		Short: "Remove all manifest files recursively",
		Long: `Remove all manifest files recursively starting from the specified directory.
If no directory is provided, the current directory is used.

This command will permanently delete all manifest files found in the
directory tree. Use with caution.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) > 0 {
				targetDir = args[0]
			}

			count := 0
			errors := 0

			err := traverse.WalkPostOrder(cmd.Context(), targetDir, func(ctx context.Context, dirPath string, err error) error {
				if err != nil {
					errors++
					return nil // Continue processing
				}
				manifestPath := filepath.Join(dirPath, manifest.DefaultName)
				if _, statErr := os.Stat(manifestPath); statErr == nil {
					if removeErr := os.Remove(manifestPath); removeErr != nil {
						errors++
						return nil // Continue processing
					}
					count++
				}
				return nil
			})

			// Print summary
			if count == 0 && errors == 0 {
				ui.PrintWarning("No manifests found to clean")
			} else if errors == 0 {
				ui.PrintSuccess("Removed %d manifest%s", count, ui.Pluralize(count, "", "s"))
			} else {
				fmt.Printf("%sCOMPLETED WITH ERRORS%s - Removed %d manifest%s, %d error%s\n",
					ui.ColorYellow, ui.ColorReset, count, ui.Pluralize(count, "", "s"),
					errors, ui.Pluralize(errors, "", "s"))
			}

			if err != nil {
				return err
			}

			if errors > 0 {
				return fmt.Errorf("encountered %d error(s) during cleaning", errors)
			}

			return nil
		},
	}
	return &cleanCmd
}
