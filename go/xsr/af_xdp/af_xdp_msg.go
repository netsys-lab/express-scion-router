package af_xdp

import (
	"fmt"

	"github.com/asavie/xdp"
)

// Interface for the message type (introduced to wrap XDP descriptors into byte
// slices without copying data)
type Message interface {
	// Get the byte slice of an already existing message
	Get(s ScionSocket) []byte
	// Delete the message after it was processed entirely (Sending a message
	// will do this automatically)
	Free(s ScionSocket)
}

// The XDP implementation of the Message interface only stores the descriptor
type XdpMessage struct {
	descriptor xdp.Desc
}

// Get a new, unused descriptor from the XSK object
func CreateXdpMsg(x *XskObject) (*XdpMessage, error) {
	var err error
	var m *XdpMessage
	m.descriptor, err = x.GetDesc()
	if err != nil {
		return nil, fmt.Errorf("Unable to get descriptor from XDP: %s", err)
	}
	return m, nil
}

// Getter for the descriptor stored in the message
func (m *XdpMessage) GetDescriptor() xdp.Desc {
	return m.descriptor
}

// Get the frame as []byte from the message
func (m *XdpMessage) Get(x *XskObject) []byte {
	return x.xsk.GetFrame(m.descriptor)
}

// Move the descriptor from the message to the ring of unused control plane
// descriptors
func (m *XdpMessage) Free(x *XskObject) {
	x.FreeDesc(m.descriptor)
}
