package matching

import "net"

// Matcher defines a set of methods that must be implemented for any
// traffic scenario where we want Latte to match requests and replies
// and compute latencies.
//
// These methods are:
// - InMsg: get matchable incoming OF message type
// - OutMsg: get matchable outgoing OF message type
// - CheckIn: extract pattern from matchable incoming msgs
// - CheckOut: extract pattern from matchable outgoing msgs
type Matcher interface {
	InMsg() uint8
	OutMsg() uint8
	CheckIn([]byte, net.IP, uint16) []byte
	CheckOut([]byte, net.IP, uint16) []byte
}
