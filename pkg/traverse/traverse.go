package traverse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// WalkFunc is the type of the function called by Walk for each directory.
// The path argument contains the directory being visited.
// The entities argument contains the scanned entities in that directory.
// If an error occurs during scanning, the incoming error describes it
// and the function can decide how to handle that error.
// If the function returns a non-nil error, Walk stops and returns that error.
type WalkFunc func(ctx context.Context, dirPath string, err error) error

// WalkPostOrder performs a post-order traversal of the directory tree
func WalkPostOrder(ctx context.Context, dirPath string, walkFn WalkFunc) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		// Call walkFn with the error and let it decide how to handle it
		return walkFn(ctx, dirPath, fmt.Errorf("failed to read directory: %w", err))
	}

	// Sort entries for a consistent processing order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	// Recursively process all subdirectories first (post-order)
	for _, entry := range entries {
		if entry.IsDir() {
			childPath := filepath.Join(dirPath, entry.Name())
			if err := WalkPostOrder(ctx, childPath, walkFn); err != nil {
				return err
			}
		}
	}

	return walkFn(ctx, dirPath, nil)
}
