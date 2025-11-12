package generator

import (
	"context"
	"errors"
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/certification"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
)

// Generator handles manifest generation with optimization features
type Generator struct {
	scanner            *scanner.Scanner
	signer             certification.Signer
	progressCh         chan scanner.Stats
	manifestsGenerated []string
}

type Stats struct {
	*scanner.Stats
	ManifestsGenerated []string
}

// New creates a new Generator instance
func New(sc *scanner.Scanner, signer certification.Signer) *Generator {
	return &Generator{
		scanner: sc,
		signer:  signer,
	}
}

// Generate generates manifests using the appropriate processor based on signer capabilities
func (g *Generator) Generate(ctx context.Context, rootPath string) error {
	processor, err := g.createProcessor()
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}

	return g.scanner.Walk(ctx, rootPath, func(ctx context.Context, dirPath string, m *manifest.Manifest, cached bool, err error) error {
		if err != nil {
			return err
		}
		if cached {
			return nil
		}
		return processor.Process(dirPath, m, g.scanner.GetManifestName())
	})
}

// createProcessor determines which processor to use based on signer capabilities
func (g *Generator) createProcessor() (ManifestProcessor, error) {
	// Test if signer supports signing
	_, err := g.signer.Sign([]byte("test"))
	if errors.Is(err, certification.ErrNotImplemented) {
		return NewUnsignedProcessor(&g.manifestsGenerated), nil
	}
	if err != nil {
		return nil, fmt.Errorf("signer test failed: %w", err)
	}

	return NewSignedProcessor(g.signer, &g.manifestsGenerated)
}

func (g *Generator) GetStats() Stats {
	return Stats{
		Stats:              g.scanner.GetStats(),
		ManifestsGenerated: g.manifestsGenerated,
	}
}
