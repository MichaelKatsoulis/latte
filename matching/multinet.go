package matching

import (
	"encoding/binary"
	"github.com/anastop/latte/ofp14"
	"net"
)

// MultinetTraffic collects methods for matching requests and
// replies in traffic generated using Multinet's generation logic
type MultinetTraffic struct {
}

// InMsg returns the OF message type that each incoming message
// should be checked against in
func (m MultinetTraffic) InMsg() uint8 {
	return ofp14.OFPT_PACKET_IN
}

// InMsg returns the OF message type that each outgoing message
// should be checked against
func (m MultinetTraffic) OutMsg() uint8 {
	return ofp14.OFPT_FLOW_MOD
}

// CheckIn attempts to extract the pattern from an InMsg() message,
// that will be used to match it against a subsequent OutMsg() message
//
// Conditions for the packet to be eligible for check-in:
// - InMsg() message type (PACKET_IN)
// - containing an Ethernet frame with ARP payload
//
// The extracted pattern is a concatenation of:
// - Ethernet frame dst mac
// - Ethernet frame src mac
// - Sender (OF switch) IP (given as argument)
// - Sender (OF switch) port (given as argument)
//
// If the pattern is found it is returned. Otherwise nil is returned.
func (m MultinetTraffic) CheckIn(ofPkt []byte, ip net.IP, port uint16) []byte {
	var pattern, r []byte
	var i, j int

	i = ofp14.PKTIN_OFPMATCH_OFFSET + ofp14.OFPMATCH_LENGTH_OFFSET
	j = i + ofp14.OFPMATCH_LENGTH_BYTES
	matchlen := int(binary.BigEndian.Uint16(ofPkt[i:j]))
	// "ofp_match is padded as needed, to make its overall size a multiple of 8"
	matchlen = roundUp(matchlen, 3)
	// compute data index
	di := ofp14.PKTIN_OFPMATCH_OFFSET + matchlen + ofp14.PKTIN_PAD_BYTES
	data := ofPkt[di:]
	// extract data ethertype
	i = ofp14.ETHER_ETHERTYPE_OFFSET
	j = ofp14.ETHER_DATA_OFFSET
	etherType := int(binary.BigEndian.Uint16(data[i:j]))
	// ARP
	if etherType == 0x0806 {
		//dstMac: data[0:6], srcMac: data[6:12]
		i = ofp14.ETHER_DSTMAC_OFFSET
		j = ofp14.ETHER_ETHERTYPE_OFFSET
		pattern = data[i:j]
	}
	if pattern == nil {
		r = nil
	} else {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, port)
		r = append(pattern, ip...)
		r = append(r, b...)
	}

	return r
}

// CheckOut attempts to extract a pattern from an OutMsg() message,
// in order to match it against checked-in InMsg() messages
//
// Conditions for the packet to be eligible for checking against a checked-in
// message:
// - OutMsg() message type (FLOW_MOD)
// - First OXM should have a class equal to OFPXMC_OPENFLOW_BASIC
// - The match fields of the two OXMs should be equal to OFPXMT_OFB_ETH_DST,
//   OFPXMT_OFB_ETH_SRC
//
// The extracted pattern is a concatenation of:
// - Value of match field OFPXMT_OFB_ETH_DST
// - Value of match field OFPXMT_OFB_ETH_SRC
// - Receiver (OF switch) IP (given as argument)
// - Receiver (OF switch) port (given as argument)
func (m MultinetTraffic) CheckOut(ofPkt []byte, ip net.IP, port uint16) []byte {
	var matchDstMac, matchSrcMac []byte
	var i, j int
	i = ofp14.FLOWMOD_MATCH_OXM0_OFFSET
	j = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_FIELD_OFFSET
	oxm0Class := int(binary.BigEndian.Uint16(ofPkt[i:j]))

	if oxm0Class == ofp14.OFPXMC_OPENFLOW_BASIC {
		i = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_FIELD_OFFSET
		oxm0Field := uint8(ofPkt[i])
		i = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_LENGTH_OFFSET
		oxm0ValLength := uint8(ofPkt[i])
		oxm0ValFrom := ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_VALUE_OFFSET
		oxm0ValTo := oxm0ValFrom + int(oxm0ValLength)

		oxm1Offset := ofp14.FLOWMOD_MATCH_OXM0_OFFSET +
			ofp14.OXM_VALUE_OFFSET +
			oxm0ValLength
		oxm1LenOff := oxm1Offset + ofp14.OXM_LENGTH_OFFSET
		oxm1ValLength := uint8(ofPkt[oxm1LenOff])
		oxm1ValFrom := oxm1Offset + ofp14.OXM_VALUE_OFFSET
		oxm1ValTo := oxm1ValFrom + oxm1ValLength

		switch oxm0Field {
		case ofp14.OFPXMT_OFB_ETH_DST:
			matchDstMac = ofPkt[oxm0ValFrom:oxm0ValTo]
			matchSrcMac = ofPkt[oxm1ValFrom:oxm1ValTo]
		case ofp14.OFPXMT_OFB_ETH_SRC:
			matchSrcMac = ofPkt[oxm0ValFrom:oxm0ValTo]
			matchDstMac = ofPkt[oxm1ValFrom:oxm1ValTo]

		}
		if matchSrcMac != nil && matchDstMac != nil {
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, port)
			pattern := append(matchDstMac, matchSrcMac...)
			pattern = append(pattern, ip...)
			pattern = append(pattern, b...)
			return pattern
		}
	}
	return nil
}
