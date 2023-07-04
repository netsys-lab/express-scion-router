package bpf

import (
	"context"
	"fmt"
	"log"
	"net/netip"

	"github.com/netsys-lab/express-scion-router/config"
	"github.com/netsys-lab/express-scion-router/topology"
	"github.com/scionproto/scion/pkg/addr"
)

type BpfRouter struct {
	// Local address
	name    string
	localIA addr.IA

	// Interfaces
	externalIfs map[uint32]config.ExternalIface
	siblingIfs  map[uint32]netip.AddrPort
	internalIfs map[int]config.InternalIface

	// Routing
	// Mapping from SVC address to AS services
	services map[uint32][]netip.AddrPort
	fib      config.Fib

	// Key for SCION hop field verification
	hfKey [16]byte
}

func NewBpfRouter(name string) *BpfRouter {
	return &BpfRouter{
		name: name,
	}
}

func (r *BpfRouter) Configure(topo *topology.Topology) error {
	var err error

	log.Printf("### Configuring Router %s ###\n", r.name)
	br, ok := topo.BorderRouters[r.name]
	if !ok {
		return fmt.Errorf("no configuration for BR %s in topology", r.name)
	}

	// Local IA
	if r.localIA, err = addr.ParseIA(topo.IA); err != nil {
		return err
	}
	log.Printf("Local IA: %s\n", r.localIA)

	// Services
	r.services = make(map[uint32][]netip.AddrPort, 2)
	r.services[uint32(addr.SvcCS)], err = config.ParseCSes(topo.ControlServices)
	log.Print("Control services:\n")
	for _, svc := range r.services[uint32(addr.SvcCS)] {
		log.Printf("  - %v\n", svc)
	}
	if err != nil {
		return err
	}
	r.services[uint32(addr.SvcDS)], err = config.ParseDSes(topo.DiscoveryServices)
	log.Print("Discovery services:\n")
	for _, svc := range r.services[uint32(addr.SvcDS)] {
		log.Printf("  - %v\n", svc)
	}
	if err != nil {
		return err
	}

	// External interfaces
	r.externalIfs, err = config.ParseExtIFs(br.ExtInterfaces)
	log.Print("External interfaces:\n")
	for ifid, iface := range r.externalIfs {
		log.Printf("%3d: %v\n", ifid, iface)
	}
	if err != nil {
		return err
	}

	// Sibling interfaces
	r.siblingIfs, err = config.ParseSibIFs(topo.BorderRouters, r.name)
	log.Print("Sibling interfaces:\n")
	for ifid, iface := range r.siblingIfs {
		log.Printf("%3d: %v\n", ifid, iface)
	}
	if err != nil {
		return err
	}

	// Internal interfaces
	r.internalIfs, err = config.ParseIntIFs(br.Internal.Interfaces)
	log.Print("Internal interfaces:\n")
	for index, iface := range r.internalIfs {
		log.Printf("%3d: %v\n", index, iface)
	}
	if err != nil {
		return err
	}

	// Static internal routes
	r.fib, err = config.ParseStaticFIB(&br.Internal)
	log.Printf("FIB:\n%v", r.fib)
	if err != nil {
		return err
	}

	return nil
}

func (r *BpfRouter) SetAsKey(key [16]byte) {
	// TODO: Key derivation
	r.hfKey = key
}

func (r *BpfRouter) Run(ctx context.Context) error {
	return nil
}
