package matching

import (
	"log"
	"testing"
)

func TestMatching(t *testing.T) {
	// etherType=0x0806, src:00:00:00:00:00:0a -> dst:00:00:00:00:00:0b
	pattern := MultinetPktInCheck(mPktIn)
	log.Printf("Matchable PACKET_IN pattern: % x", pattern)

	// etherType!=0x0806
	pattern = MultinetPktInCheck(uPktIn)
	log.Printf("Unmatchable PACKET_IN pattern: % x", pattern)

	// src:00:00:00:00:00:0a -> dst:00:00:00:00:00:0b
	pattern = MultinetFlowModCheck(mFlowMod)
	log.Printf("Matching FLOW_MOD pattern: % x", pattern)

	// src:00:00:00:00:00:0b -> dst:00:00:00:00:00:0a
	pattern = MultinetFlowModCheck(mFlowModU)
	log.Printf("Unmatching FLOW_MOD pattern: % x", pattern)

	// src:00:00:00:00:00:42 -> dst:00:00:00:00:00:43
	pattern = MultinetFlowModCheck(uFlowMod)
	log.Printf("Unmatching FLOW_MOD 2 pattern: % x", pattern)
}
