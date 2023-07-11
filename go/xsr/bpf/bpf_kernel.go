package bpf

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
)

func load() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_EmbdeddedXDP)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("Loading XDP code failed: %w", err)
	}
	return spec, err
}

//go:embed xsr_ebpf.o
var _EmbdeddedXDP []byte
