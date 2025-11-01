package scanner

import "io"

// byteCounter wraps an io.Writer and counts bytes written
type byteCounter struct {
	stats  *Stats
	writer io.Writer
}

func (bc *byteCounter) Write(p []byte) (int, error) {
	n, err := bc.writer.Write(p)
	if n > 0 {
		bc.stats.AddBytesProcessed(int64(n))
	}
	return n, err
}
