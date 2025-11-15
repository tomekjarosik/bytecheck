package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"io/fs"
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

			// To avoid dependency
			manifestName := ".bytecheck.manifest"

			// Use filepath.WalkDir for simpler recursive traversal
			err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					errors++
					return nil // Continue despite errors
				}

				// Skip directories, only process files
				if d.IsDir() {
					return nil
				}

				// Check if filename matches our pattern
				filename := filepath.Base(path)
				if filename == manifestName {
					if removeErr := os.Remove(path); removeErr != nil {
						fmt.Printf("Error removing %s: %v\n", path, removeErr)
						errors++
					} else {
						fmt.Printf("Removed: %s\n", path)
						count++
					}
				}

				return nil
			})

			// Print summary
			fmt.Printf("\nSummary: Removed %d file%s", count, pluralize(count))
			if errors > 0 {
				fmt.Printf(", %d error%s", errors, pluralize(errors))
			}
			fmt.Println()

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

// Simple pluralize helper
func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
