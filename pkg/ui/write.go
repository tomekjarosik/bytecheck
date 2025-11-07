package ui

import (
	"fmt"
	"io"
)

func PrintWriteResult(w io.Writer, dirsProcessed, dirsCached int64, manifestsGenerated []string) {
	totalDirectories := dirsProcessed + dirsCached

	if totalDirectories == 0 {
		PrintWarning("no directories processed")
		return
	}
	fmt.Fprintf(w, "processed %d directory(s) (%d cached)\n", totalDirectories, dirsCached)
	for _, m := range manifestsGenerated {
		fmt.Fprintf(w, "manifest '%s' generated\n", m)
	}
}
