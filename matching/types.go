package matching

import "net"

type Match struct {
	InMsg    uint8
	OutMsg   uint8
	InMatch  func([]byte, net.IP, uint16) []byte
	OutMatch func([]byte, net.IP, uint16) []byte
}
