package generator

import (
	"context"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"path/filepath"
)

// Generator handles manifest generation with optimization features
type Generator struct {
	scanner            *scanner.Scanner
	progressCh         chan scanner.Stats
	manifestsGenerated []string
}

type Stats struct {
	scanner.Stats
	ManifestsGenerated []string
}

// New creates a new Generator instance with default settings
func New(sc *scanner.Scanner) *Generator {
	return &Generator{
		scanner: sc,
	}
}

// Generate generates manifests for all directories starting from rootPath
// Thanks to WalkDir's post-order traversal, child manifests are created before
// parent directory checksums are calculated, solving the dependency issue naturally.
// With optimization enabled, it skips directories with recent manifests.
func (g *Generator) Generate(ctx context.Context, rootPath string) error {
	return g.scanner.Walk(ctx, rootPath, func(ctx context.Context, dirPath string, m *manifest.Manifest, cached bool, err error) error {
		if err != nil {
			return err
		}

		if cached {
			return nil
		}

		g.manifestsGenerated = append(g.manifestsGenerated, dirPath)
		return m.Save(filepath.Join(dirPath, g.scanner.GetManifestName()))
	})
}

func (g *Generator) GetStats() Stats {
	return Stats{
		Stats:              g.scanner.GetStats(),
		ManifestsGenerated: g.manifestsGenerated,
	}
}
