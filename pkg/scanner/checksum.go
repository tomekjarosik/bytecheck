package scanner

import (
	"context"
	"fmt"
	"github.com/minio/sha256-simd"
	"io"
	"os"
)

// CalculateFileChecksumWithStats calculates SHA-256 checksum of a file and tracks bytes processed
func calculateChecksum(ctx context.Context, fpath string, stats *Stats) (string, error) {
	file, err := os.Open(fpath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	stats.SetCurrentFile(fpath)

	hash := sha256.New()

	// Use a custom writer that counts bytes
	counter := &byteCounter{
		ctx:    ctx,
		stats:  stats,
		writer: hash,
	}

	buf := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(counter, file, buf); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
