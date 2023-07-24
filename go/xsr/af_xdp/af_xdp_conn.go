package af_xdp

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"
)

var LenBufDesc = 2048

// Minimal data plane interface that has to be implemented for interaction with
// XSR
type ScionSocket interface {
	// Read a message from the SCION socket. Creates message object.
	Read() ([]XdpMessage, error)
	// Write a message to the SCION socket. Takes message objec.
	Write(msgs []XdpMessage) error
	// Get the local address to which the SCION socket is bound
	LocalAddr() net.Addr
	// Close the SCION socket
	Close() error
}

// AF_XDP socket that implements following interface
type XskObject struct {
	xsk       *xdp.Socket
	program   *xdp.Program
	descs     []xdp.Desc
	descRead  int16
	descWrite int16
	link      netlink.Link
	local     net.Addr
}

// Create XSK socket for reading and sending
func CreateXskConn(ifname string) (*XskObject, error) {
	// Create XskObject
	x := new(XskObject)

	// Get link to which the XDP program should be attached
	var err error
	x.link, err = netlink.LinkByName(ifname)
	if err != nil {
		return x, err
	}

	// Create socket
	x.xsk, err = xdp.NewSocket(x.link.Attrs().Index, 0, nil)
	if err != nil {
		return x, fmt.Errorf("Failed to create XDP socket: %s", err)
	}

	// Initialize ring for unused descriptors
	x.descs = make([]xdp.Desc, 0, 2048)
	x.descRead = 0
	x.descWrite = 0

	return x, nil
}

// Get a new descriptor, either from the ring of unused descs or from the
// Completion ring.
func (x *XskObject) GetDesc() (xdp.Desc, error) {
	// Check if there are descs in control plane that are currently not in use
	if x.descRead != x.descWrite {
		desc := x.descs[x.descRead]
		if x.descRead++; x.descRead == 2048 {
			x.descRead = 0
		}
		return desc, nil
	}
	// Else get a new desc from Completion ring
	desc := x.xsk.GetDescs(1)
	if len(desc) == 0 {
		return desc[0], fmt.Errorf("Received descriptor with length 0!")
	}
	return desc[0], nil
}

// Read bytes from XSK socket into message type
func (x *XskObject) Read() ([]XdpMessage, error) {
	// Check if Fill ring has free descriptor slots and submit new descriptor
	if n := x.xsk.NumFreeFillSlots(); n > 0 {
		desc, err := x.GetDesc()
		if err != nil {
			return nil, fmt.Errorf("XDP submit to decriptor to Fill ring failed: %S", err)
		}
		descs := []xdp.Desc{desc}
		x.xsk.Fill(descs)
	}
	// Poll the received message from the Rx queue
	numRx, _, err := x.xsk.Poll(-1)
	if err != nil {
		return nil, fmt.Errorf("XDP socket poll failed: %S", err)
	}
	// Create a XdpMessage to store the descriptor
	if numRx > 0 {
		var rxDesc []xdp.Desc
		var msg = make([]XdpMessage, 1)
		rxDesc = x.xsk.Receive(1)
		msg[0].descriptor = rxDesc[0]
		fmt.Printf(fmt.Sprint("Slow path got packet:\n", hex.Dump(msg[0].Get(x))))
		return msg, nil
	}
	return nil, nil
}

// Write bytes to XSK socket
func (x *XskObject) Write(msgs []XdpMessage) (int, error) {
	// Check whether Tx ring has space for a descriptor
	if n := x.xsk.NumFreeTxSlots(); n <= 0 {
		return 0, fmt.Errorf("Send ring is full.")
	}
	// Submit descriptor to Tx ring
	k := 0
	for _, msg := range msgs {
		var txDesc = []xdp.Desc{msg.GetDescriptor()}
		n := x.xsk.Transmit(txDesc)
		if n == 0 {
			k++
		}
		fmt.Printf("Sent transmitted a packet of %d bytes.", n)
	}
	return len(msgs) - k, nil
}

// Push a descriptor that is currently unused into the control plane ring
func (x *XskObject) FreeDesc(desc xdp.Desc) {
	x.descs[x.descWrite] = desc
	x.descWrite++
}

// Detach XDP prog and close connection
func (x *XskObject) Close() error {
	x.xsk.Close()
	return nil
}

func (x *XskObject) LocalAddr() net.Addr {
	return x.local
}
