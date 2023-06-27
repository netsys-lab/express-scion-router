package topology

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Topology struct {
	IA                string                     `yaml:"isd_as"`
	DispatcherPort    int                        `yaml:"dispatcher_port"`
	DiscoveryServices map[string]*ServiceAddress `yaml:"discovery_services"`
	ControlServices   map[string]*ServiceAddress `yaml:"control_services"`
	BorderRouters     map[string]*BorderRouter   `yaml:"border_routers"`
}

type BorderRouter struct {
	Internal      Internal              `yaml:"internal"`
	ExtInterfaces map[int]*ExtInterface `yaml:"external"`
}

type Internal struct {
	Address      ServiceAddress        `yaml:"address"`
	Interfaces   map[int]*IntInterface `yaml:"interfaces"`
	IPRouting    string                `yaml:"ip_routing"` // static or kernel
	StaticRoutes []Route               `yaml:"routes"`
	NextHops     []NextHop             `yaml:"next_hops"`
}

// Inter-AS interface
// Must be a point-to-point link, routing is not supported.
type ExtInterface struct {
	IfId   int         `yaml:"ifid"`
	IA     string      `yaml:"isd_as"`
	LinkTo string      `yaml:"link_to"`
	Local  LogicalPort `yaml:"local"`
	Remote RemotePort  `yaml:"remote"`
	Bfd    BFD         `yaml:"bfd,omitempty"`
}

// AS-internal interface
type IntInterface struct {
	Address LogicalPort `yaml:"address"`
	Bfd     BFD         `yaml:"bfd,omitempty"`
}

// A logical port of the border router. A physical port can have many logical
// ports with different VLANs, MACs, IPs, and UDP ports.
type LogicalPort struct {
	PhysicalPort PhysicalPort `yaml:"physical"`
	VLAN         VLAN         `yaml:"vlan"`
	MAC          string       `yaml:"mac"`
	IsIP6        bool         `yaml:"is_ip6"`
	IP           string       `yaml:"ip"`
	Port         int          `yaml:"port"`
}

type RemotePort struct {
	VLAN  VLAN   `yaml:"vlan"`
	MAC   string `yaml:"mac"`
	IsIP6 bool   `yaml:"is_ip6"`
	IP    string `yaml:"ip"`
	Port  int    `yaml:"port"`
}

// A physical port of the border router identified by its index and or name.
// At least one of Index and Name must be set.
type PhysicalPort struct {
	Index int    `yaml:"index"`
	Name  string `yaml:"name"`
}

// VLAN tag
type VLAN struct {
	Tag    int  `yaml:"tag"`
	Tagged bool `yaml:"tagged"`
}

// Routing table entry
type Route struct {
	IsIP6   bool   `yaml:"is_ip6"`
	Prefix  string `yaml:"prefix"`
	NextHop int    `yaml:"next_hop"` // Index into next hop table
}

// Next hop address for IP routing
type NextHop struct {
	IsIP6     bool   `yaml:"is_ip6"`
	IP        string `yaml:"ip"`
	MAC       string `yaml:"mac"`
	Interface int    `yaml:"interface"` // Index of an internal interface
}

// SCION service address
type ServiceAddress struct {
	IsIP6 bool   `yaml:"is_ip6"`
	IP    string `yaml:"ip"`
	Port  int    `yaml:"port"`
}

// BFD configuration
type BFD struct {
	Disable bool `yaml:"disable,omitempty"`
}

func LoadTopology(path string) (*Topology, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	topo := &Topology{}
	if err = yaml.Unmarshal(b, topo); err != nil {
		return nil, err
	}
	return topo, nil
}
