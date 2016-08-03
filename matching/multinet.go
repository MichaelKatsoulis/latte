package matching

import (
	"encoding/binary"
	"github.com/anastop/latte/ofp14"
	"net"
)

var MultinetMatch = Match{
	ofp14.OFPT_PACKET_IN,
	ofp14.OFPT_FLOW_MOD,
	MultinetPktInCheck,
	MultinetFlowModCheck}

// MultinetCheckIn attempts to extract the pattern from a PACKET_IN message that
// will be used to match it with a subsequent FLOW_MOD. The pattern in
// our case is the concatenation of <dstMac><srcMac> fields, which is returned
// if it is found within the PACKET_IN data, otherwise nil is returned.
func MultinetPktInCheck(ofPkt []byte, ip net.IP, port uint16) []byte {
	var pattern, r []byte
	var from, to int

	from = ofp14.PKTIN_OFPMATCH_OFFSET + ofp14.OFPMATCH_LENGTH_OFFSET
	to = from + ofp14.OFPMATCH_LENGTH_BYTES
	matchlen := int(binary.BigEndian.Uint16(ofPkt[from:to]))
	// "ofp_match is padded as needed, to make its overall size a multiple of 8"
	matchlen = roundUp(matchlen, 3)
	// compute data index
	di := ofp14.PKTIN_OFPMATCH_OFFSET + matchlen + ofp14.PKTIN_PAD_BYTES
	data := ofPkt[di:]
	from = ofp14.ETHER_ETHERTYPE_OFFSET
	to = ofp14.ETHER_DATA_OFFSET
	etherType := int(binary.BigEndian.Uint16(data[from:to]))
	// ARP
	if etherType == 0x0806 {
		//dstMac: data[0:6], srcMac: data[6:12]
		from = ofp14.ETHER_DSTMAC_OFFSET
		to = ofp14.ETHER_ETHERTYPE_OFFSET
		pattern = data[from:to]
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

// MultinetCheckOut attempts to extract the pattern from a FLOW_MOD message that will
// be used to match it with a previous PACKET_IN. The pattern in our case is
// the concatenation of <OFPXMT_OFB_ETH_DST><OFPXMT_OFB_ETH_SRC> value fields
// in OXM segments, which is returned if it is found within the PACKET_IN data,
// otherwise nil is returned.
func MultinetFlowModCheck(ofPkt []byte, ip net.IP, port uint16) []byte {
	var matchDstMac, matchSrcMac []byte
	var from, to int
	from = ofp14.FLOWMOD_MATCH_OXM0_OFFSET
	to = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_FIELD_OFFSET
	oxm0Class := int(binary.BigEndian.Uint16(ofPkt[from:to]))

	if oxm0Class == ofp14.OFPXMC_OPENFLOW_BASIC {
		from = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_FIELD_OFFSET
		oxm0Field := uint8(ofPkt[from])
		from = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_LENGTH_OFFSET
		oxm0ValLength := uint8(ofPkt[from])
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
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, port)
		pattern := append(matchDstMac, matchSrcMac...)
		pattern = append(pattern, ip...)
		pattern = append(pattern, b...)
		return pattern
	}
	return nil
}
