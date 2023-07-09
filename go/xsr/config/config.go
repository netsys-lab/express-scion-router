package config

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/netsys-lab/express-scion-router/topology"
	"github.com/scionproto/scion/pkg/addr"
)

// VLAN tag
type Vlan struct {
	Tag    int
	Tagged bool
}

func (vlan Vlan) String() string {
	return fmt.Sprintf("{tag: %d, tagged: %v}", vlan.Tag, vlan.Tagged)
}

// A physical device port
type PhysicalPort struct {
	Index int
	Name  string
}

func (port PhysicalPort) String() string {
	return fmt.Sprintf("{index: %d, name: %s}", port.Index, port.Name)
}

// A BR interface
type LogicalPort struct {
	Physical PhysicalPort   // Physical connection
	Vlan     Vlan           // Underlay VLAN
	Mac      [6]byte        // HW address
	Underlay netip.AddrPort // SCION underlay address
}

func (port LogicalPort) String() string {
	return fmt.Sprintf("{phy: %v, vlan: %v, mac: %s, underlay: %v}",
		port.Physical, port.Vlan, net.HardwareAddr(port.Mac[:]), port.Underlay)
}

// Addressing information for a foreign border router
type RemotePort struct {
	Vlan     Vlan           // Underlay VLAN
	Mac      [6]byte        // HW address
	Underlay netip.AddrPort // SCION underlay address
}

func (port RemotePort) String() string {
	return fmt.Sprintf("{vlan: %v, mac: %s, underlay: %v}",
		port.Vlan, net.HardwareAddr(port.Mac[:]), port.Underlay)
}

type BfdConfig struct {
	Disabled bool
}

func (bfd BfdConfig) String() string {
	return fmt.Sprintf("{disabled: %v}", bfd.Disabled)
}

// An external interface is a local link to another AS
type ExternalIface struct {
	Ia     addr.IA
	Local  LogicalPort
	Remote RemotePort
	Bfd    BfdConfig
}

func (ext ExternalIface) String() string {
	return fmt.Sprintf("{\n    Neighbor: %v\n    Local: %v\n    Remote: %v\n    BFD: %v\n}",
		ext.Ia, ext.Local, ext.Remote, ext.Bfd)
}

// An internal interface is an interface to an AS-internal network
type InternalIface struct {
	Address LogicalPort
	Bfd     BfdConfig
}

func (intf InternalIface) String() string {
	return fmt.Sprintf("{\n    Address: %v\n    BFD: %v\n}", intf.Address, intf.Bfd)
}

// Forwarding Information Base for AS-internal routing
type Fib struct {
	Routes   []StaticRoute
	NextHops []NextHop
}

func (fib Fib) String() string {
	var sb strings.Builder
	for _, route := range fib.Routes {
		nh := fib.NextHops[route.NextHop]
		sb.WriteString(fmt.Sprintf("  - %v -> %v\n", route.Prefix, nh))
	}
	return sb.String()
}

type StaticRoute struct {
	Prefix  netip.Prefix
	NextHop int
}

type NextHop struct {
	Iface int     // Index of the (internal) interface to transmit on
	Mac   [6]byte // Destination MAC
}

func (nh NextHop) String() string {
	return fmt.Sprintf("{iface: %d, mac: %s}", nh.Iface, net.HardwareAddr(nh.Mac[:]))
}

////////////
// Public //
////////////

// Parse control services from topology
func ParseCSes(topo_cses map[string]*topology.ServiceAddress) ([]netip.AddrPort, error) {
	cses := make([]netip.AddrPort, 0, len(topo_cses))
	for name, addr := range topo_cses {
		service, err := parseServiceAddr(addr)
		if err != nil {
			return cses, fmt.Errorf("control service %s: %w", name, err)
		}
		cses = append(cses, service)
	}
	return cses, nil
}

// Parse control services from topology
func ParseDSes(topo_dses map[string]*topology.ServiceAddress) ([]netip.AddrPort, error) {
	dses := make([]netip.AddrPort, 0, len(topo_dses))
	for name, addr := range topo_dses {
		service, err := parseServiceAddr(addr)
		if err != nil {
			return dses, fmt.Errorf("discovery service %s: %w", name, err)
		}
		dses = append(dses, service)
	}
	return dses, nil
}

// Parse external interfaces
func ParseExtIFs(ifs map[int]*topology.ExtInterface) (map[uint32]ExternalIface, error) {
	var err error
	extifs := make(map[uint32]ExternalIface, len(ifs))
	for ifid, ext := range ifs {
		extif := ExternalIface{}
		extif.Ia, err = addr.ParseIA(ext.IA)
		if err != nil {
			return extifs, err
		}
		extif.Local, err = parseLogicalPort(ext.Local)
		if err != nil {
			return extifs, err
		}
		extif.Remote, err = parseRemotePort(ext.Remote)
		if err != nil {
			return extifs, err
		}
		extif.Bfd, err = parseBfdConfig(ext.Bfd)
		if err != nil {
			return extifs, nil
		}
		extifs[(uint32)(ifid)] = extif
	}
	return extifs, nil
}

// Parse sibling interfaces
func ParseSibIFs(topo_brs map[string]*topology.BorderRouter, local string) (
	map[uint32]netip.AddrPort, error) {

	siblings := make(map[uint32]netip.AddrPort)
	for name, br := range topo_brs {
		if name == local {
			continue
		}
		for ifid, _ := range br.ExtInterfaces {
			addr, err := parseServiceAddr(&br.Internal.Address)
			if err != nil {
				return siblings, err
			}
			siblings[(uint32)(ifid)] = addr
		}
	}
	return siblings, nil
}

// Parse internal interfaces
func ParseIntIFs(ifs map[int]*topology.IntInterface) (map[int]InternalIface, error) {
	var err error
	intifs := make(map[int]InternalIface, len(ifs))
	for i, iface := range ifs {
		intif := InternalIface{}
		intif.Address, err = parseLogicalPort(iface.Address)
		if err != nil {
			return intifs, err
		}
		intif.Bfd, err = parseBfdConfig(iface.Bfd)
		if err != nil {
			return intifs, err
		}
		intifs[i] = intif
	}
	return intifs, nil
}

// Parse static routes and next hop table
func ParseStaticFIB(internal *topology.Internal) (Fib, error) {
	var err error
	fib := Fib{
		Routes:   make([]StaticRoute, 0, len(internal.StaticRoutes)),
		NextHops: make([]NextHop, 0, len(internal.NextHops)),
	}
	if internal.IPRouting == "static" {
		// Next hops
		for _, nh := range internal.NextHops {
			hop := NextHop{}
			if _, ok := internal.Interfaces[nh.Interface]; !ok {
				return fib, fmt.Errorf("invalid next hop interface")
			}
			hop.Iface = nh.Interface
			hop.Mac, err = parseMac(nh.MAC)
			if err != nil {
				return fib, fmt.Errorf("invalid next hop MAC")
			}
			fib.NextHops = append(fib.NextHops, hop)
		}
		// Routes
		for _, sr := range internal.StaticRoutes {
			route := StaticRoute{}
			route.Prefix, err = parsePrefix(sr.Prefix, sr.IsIP6)
			if err != nil {
				return fib, fmt.Errorf("invalid route prefix")
			}
			if sr.NextHop >= 0 && sr.NextHop < len(fib.NextHops) {
				route.NextHop = sr.NextHop
			} else {
				return fib, fmt.Errorf("invalid route next hop")
			}
			fib.Routes = append(fib.Routes, route)
		}
	}
	return fib, nil
}

/////////////
// Private //
/////////////

// Parse the IP and UDP port of a SCION service
func parseServiceAddr(addr *topology.ServiceAddress) (netip.AddrPort, error) {
	ip, err := parseIpAddr(addr.IP, addr.IsIP6)
	ip_port := netip.AddrPortFrom(ip, uint16(addr.Port))
	return ip_port, err
}

// Parse an IP address of the given type
func parseIpAddr(addr string, is_ipv6 bool) (netip.Addr, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil || (ip.Is6() != is_ipv6) {
		return ip, fmt.Errorf("%s is not a valid IP address of the specified type", addr)
	}
	return ip, nil
}

// Parse an IP prefix (address + subnet mask) of the given type
func parsePrefix(prefix string, is_ipv6 bool) (netip.Prefix, error) {
	net, err := netip.ParsePrefix(prefix)
	if err != nil || (net.Addr().Is6() != is_ipv6) {
		return net, fmt.Errorf("%s is not a valid IP prefix of the specified type", prefix)
	}
	return net, nil
}

// Parse an Ethernet MAC address
func parseMac(mac string) ([6]byte, error) {
	hwAddr, err := net.ParseMAC(mac)
	if err != nil || len(hwAddr) != 6 {
		return [6]byte{}, fmt.Errorf("%s is not a valid Ethernet MAC", mac)
	}
	return [6]byte(hwAddr), nil
}

// Parse BR port specification with all addressing layers
func parseLogicalPort(topo_port topology.LogicalPort) (LogicalPort, error) {
	var err error
	var port = LogicalPort{
		Vlan: Vlan{Tag: topo_port.VLAN.Tag, Tagged: topo_port.VLAN.Tagged},
	}

	// HW address
	port.Mac, err = parseMac(topo_port.MAC)
	if err != nil {
		return port, err
	}

	// SCION underlay address
	ip, err := parseIpAddr(topo_port.IP, topo_port.IsIP6)
	if err != nil {
		return port, nil
	}
	port.Underlay = netip.AddrPortFrom(ip, uint16(topo_port.Port))

	// Physical port
	port.Physical, err = parsePhysicalPort(topo_port.PhysicalPort, ip)
	if err != nil {
		return port, err
	}

	return port, nil
}

// Parse remote station address on a point-to-point link
func parseRemotePort(topo_port topology.RemotePort) (RemotePort, error) {
	var err error
	var port = RemotePort{
		Vlan: Vlan{Tag: topo_port.VLAN.Tag, Tagged: topo_port.VLAN.Tagged},
	}

	// HW address
	port.Mac, err = parseMac(topo_port.MAC)
	if err != nil {
		return port, err
	}

	// SCION underlay address
	ip, err := parseIpAddr(topo_port.IP, topo_port.IsIP6)
	if err != nil {
		return port, nil
	}
	port.Underlay = netip.AddrPortFrom(ip, uint16(topo_port.Port))

	return port, nil
}

// Parse a physical port specification trying to find the correct port index if not given
func parsePhysicalPort(topo_port topology.PhysicalPort, underlay netip.Addr) (PhysicalPort, error) {
	port := PhysicalPort{
		Index: topo_port.Index,
		Name:  topo_port.Name,
	}

	// Determine interface index if not given explicitly
	if port.Index <= 0 {
		var iface *net.Interface
		var err error
		if port.Name != "" {
			iface, err = net.InterfaceByName(port.Name)
		} else {
			iface, err = interfaceByIp(underlay)
		}
		if err != nil {
			return port, err
		}
		port.Index = iface.Index
	}

	return port, nil
}

// Get a network interface by IP address
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

// Parse BFD configuration
func parseBfdConfig(bfd topology.BFD) (BfdConfig, error) {
	return BfdConfig{
		Disabled: bfd.Disable,
	}, nil
}
