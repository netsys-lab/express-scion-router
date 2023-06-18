package main

import (
	"context"
	"fmt"

	"github.com/netsys-lab/express-scion-router/topology"
	"gopkg.in/yaml.v3"
)

type Router interface {
	Configure(topo *topology.Topology, key []byte) error
	Run(ctx context.Context) error
}

type DummyRouter struct {
}

func (r *DummyRouter) Configure(topo *topology.Topology, key []byte) error {
	if b, err := yaml.Marshal(topo); err == nil {
		fmt.Printf("Configuration:\n%s\n", b)
	}
	return nil
}

func (r *DummyRouter) Run(ctx context.Context) error {
	done := ctx.Done()
	<-done
	return nil
}
