package cmd

import (
	"context"
	"fmt"

	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

func InitializeCommands() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "bytecheck",
		Short: "A tool for generating and verifying manifest files",
		Long: `Bytecheck is a command-line tool that helps you generate and verify manifest files recursively in your project directories.
Each manifest file contains a list of checksums for files and directories in the directory.`,
		Version: "0.2",
	}

	rootCmd.AddCommand(NewGenerateCmd())
	rootCmd.AddCommand(NewVerifyCommand())
	rootCmd.AddCommand(NewCleanCommand())
	rootCmd.AddCommand(NewCmdVersion())
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	return rootCmd
}

func Execute(rootCmd *cobra.Command) {
	rootCmd.Version = Version
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
