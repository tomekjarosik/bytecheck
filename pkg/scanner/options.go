package scanner

import (
	"runtime"
	"time"
)

type options struct {
	workersCount           int
	manifestName           string
	manifestFreshnessLimit *time.Duration
	progressChannel        chan *Stats
	reportInterval         time.Duration
}

type Option func(opts *options)

func makeOptions(opts ...Option) *options {
	res := &options{
		workersCount:           max(2, runtime.NumCPU()-2),
		progressChannel:        make(chan *Stats, 10),
		reportInterval:         200 * time.Millisecond,
		manifestName:           ".bytecheck.manifest",
		manifestFreshnessLimit: nil,
	}

	for _, o := range opts {
		o(res)
	}

	return res
}

func WithWorkersCount(workersCount int) Option {
	return func(o *options) {
		o.workersCount = workersCount
	}
}

func WithProgressChannel(progressChannel chan *Stats) Option {
	return func(o *options) {
		o.progressChannel = progressChannel
	}
}

func WithManifestFreshnessLimit(limit time.Duration) Option {
	return func(o *options) {
		o.manifestFreshnessLimit = &limit
	}
}

func WithManifestName(name string) Option {
	return func(o *options) {
		o.manifestName = name
	}
}
