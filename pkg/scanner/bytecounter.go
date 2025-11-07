package scanner

import (
	"context"
	"io"
)

// byteCounter wraps an io.Writer and counts bytes written
type byteCounter struct {
	ctx    context.Context
	stats  *Stats
	writer io.Writer
}

func (bc *byteCounter) Write(p []byte) (int, error) {
	n, err := bc.writer.Write(p)
	if n > 0 {
		bc.stats.AddBytesProcessed(int64(n))
	}
	if err == nil && bc.ctx.Err() != nil {
		return n, bc.ctx.Err()
	}
	return n, err
}
