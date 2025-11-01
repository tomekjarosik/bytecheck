package cmd

import (
	"context"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
)

func InitializeCommands() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:     "bytecheck",
		Short:   "A tool for generating, verifying, and managing manifest files",
		Long:    `Bytecheck is a command-line tool that helps you generate, verify, and manage manifest files recursively in your project directories.`,
		Version: "0.2",
	}

	rootCmd.AddCommand(NewWriteCmd())
	rootCmd.AddCommand(NewVerifyCommand())
	rootCmd.AddCommand(NewCleanCommand())

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
