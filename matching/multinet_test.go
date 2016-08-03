package matching

import (
	"bytes"
	"log"
	"net"
	"testing"
)

func TestMultinetMatching(t *testing.T) {
	ip := net.IP{192, 168, 1, 10}
	port := uint16(6789)

	// etherType=0x0806, src:00:00:00:00:00:0a -> dst:00:00:00:00:00:0b
	pat1 := MultinetPktInCheck(mPktIn, ip, port)
	log.Printf("[1] Matchable PACKET_IN pattern: % x", pat1)

	// etherType!=0x0806
	pat2 := MultinetPktInCheck(uPktIn, ip, port)
	log.Printf("[2] Unmatchable PACKET_IN pattern: % x", pat2)

	// src:00:00:00:00:00:0a -> dst:00:00:00:00:00:0b
	pat3 := MultinetFlowModCheck(mFlowMod, ip, port)
	log.Printf("[3] Matching FLOW_MOD pattern: % x", pat3)

	// src:00:00:00:00:00:0b -> dst:00:00:00:00:00:0a
	pat4 := MultinetFlowModCheck(mFlowModU, ip, port)
	log.Printf("[4] Unmatching FLOW_MOD pattern: % x", pat4)

	// src:00:00:00:00:00:42 -> dst:00:00:00:00:00:43
	pat5 := MultinetFlowModCheck(uFlowMod, ip, port)
	log.Printf("[5] Unmatching FLOW_MOD 2 pattern: % x", pat5)

	if !bytes.Equal(pat1, pat3) {
		t.Error("Patterns 1 and 3 of matchable packets 3 found not same")
	}
	if bytes.Equal(pat1, pat4) {
		t.Error("Patterns 1 and 4 of unmatchable packets found same")
	}
	if bytes.Equal(pat1, pat5) {
		t.Error("Patterns 1 and 5 of unmatchable packets found same")
	}
	if pat2 != nil {
		t.Error("Non-nil pattern found in unmatchable PACKET_IN")
	}
}
