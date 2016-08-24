package matching

import "net"

// Match encapsulates packet matching information for a certain use case
// - InMsgType: matchable incoming OF message type
// - OutMsgType: matchable outgoing OF message type
// - InMatch: function to extract pattern from matchable incoming msgs
// - OutMatch: function to extract pattern from matchable outgoing msgs
type Match struct {
	InMsgType  uint8
	OutMsgType uint8
	InMatch    func([]byte, net.IP, uint16) []byte
	OutMatch   func([]byte, net.IP, uint16) []byte
}
