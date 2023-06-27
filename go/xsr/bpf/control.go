package bpf

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/netsys-lab/express-scion-router/topology"
	"github.com/scionproto/scion/pkg/addr"
)

// A physical device port
type physicalPort struct {
	index int
	name  string
}

// VLAN tag
type vlan struct {
	tag    int
	tagged bool
}

// A BR interface
type logicalPort struct {
	physical physicalPort   // Physical connection
	vlan     vlan           // Underlay VLAN
	mac      [6]byte        // HW address
	underlay netip.AddrPort // SCION underlay address
}

// Addressing information for a foreign border router
type remoteIface struct {
	vlan     vlan           // Underlay VLAN
	mac      [6]byte        // HW address
	underlay netip.AddrPort // SCION underlay address
}

// Address of an AS service (e.g. control service)
type serviceAddr struct {
}

// An internal interface is an interface to an AS-internal network.
type internalIface struct {
	ifindex int
	address logicalPort
}

// Get a network interface by IP address.
func interfaceByIp(ip netip.Addr) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			switch a := addr.(type) {
			case *net.IPNet:
				if ifip, ok := netip.AddrFromSlice(a.IP); ok && ifip == ip {
					return &iface, nil
				}
			default:
				continue
			}
		}
	}
	return nil, fmt.Errorf("no interface with IP %v found", ip)
}

func parsePhysicalPort(port *topology.PhysicalPort, underlay netip.Addr) (*physicalPort, error) {
	var index = port.Index

	// Determine interface index if not given explicitly
	if index == 0 { // TODO: Is zero a valid index?
		var iface *net.Interface
		var err error
		if port.Name != "" {
			iface, err = net.InterfaceByName(port.Name)
		} else {
			iface, err = interfaceByIp(underlay)
		}
		if err != nil {
			return nil, err
		}
		index = iface.Index
	}

	return &physicalPort{
		index: index,
		name:  port.Name,
	}, nil
}

func parseLogicalPort(port *topology.LogicalPort) (*logicalPort, error) {
	// SCION underlay address
	ip, err := netip.ParseAddr(port.IP)
	if err != nil || (ip.Is6() != port.IsIP6) {
		return nil,
			fmt.Errorf("%s is not a valid IP address of the specified type", port.IP)
	}

	// Physical port
	phy, err := parsePhysicalPort(&port.PhysicalPort, ip)
	if err != nil {
		return nil, err
	}

	// HW address
	hwAddr, err := net.ParseMAC(port.MAC)
	if err != nil || len(hwAddr) != 6 {
		return nil,
			fmt.Errorf("%s is not a valid Ethernet MAC", port.MAC)
	}

	return &logicalPort{
		physical: *phy,
		vlan:     vlan{tag: port.VLAN.Tag, tagged: port.VLAN.Tagged},
		mac:      ([6]byte)(hwAddr[:6]),
		underlay: netip.AddrPortFrom(ip, uint16(port.Port)),
	}, nil
}

// TODO: The user space router and the eBPF router can share most of this code
type BpfRouter struct {
	name        string
	localIA     addr.IA
	internalIfs []internalIface
	services    map[uint32][]serviceAddr // Mapping from SVC address to AS services
	hfKeys      [8][16]byte              // Keys for SCION hop field verification
	running     bool
}

func (r *BpfRouter) Configure(topo *topology.Topology, key []byte) error {
	var err error

	log.Printf("Configuring router %s\n", r.name)
	br, ok := topo.BorderRouters[r.name]
	if !ok {
		return fmt.Errorf("no configuration for BR %s in topology", r.name)
	}

	// Set IA
	if r.localIA, err = addr.ParseIA(topo.IA); err != nil {
		return err
	}
	log.Printf("Local IA: %s\n", r.localIA)

	// Internal interfaces
	for _, iface := range br.Internal.Interfaces {
		adr, err := parseLogicalPort(&iface.Address)
		if err != nil {
			return err
		}
		r.internalIfs = append(r.internalIfs, internalIface{
			ifindex: 0,
			address: *adr,
		})
	}

	return nil
}

func (r *BpfRouter) Run(ctx context.Context) error {
	return nil
}
