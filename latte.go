package main

import (
	"flag"
	"fmt"
	"github.com/VividCortex/gohistogram"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"ofp14"
	//"github.com/google/gopacket/pfring"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"
)

var device = flag.String("device", "lo",
	"device to sniff packets from")
var cpuprofile = flag.String("cpuprofile", "",
	"enable CPU prof and write results to file")
var ofport = flag.String("ofport", "6653",
	"OpenFlow port number")
var sniffer = flag.String("sniffer", "pcap",
	"Library to use for packet sniffing: pcap or pfring")

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	packetsIn   map[uint32]int64
	lostPackets int64

	// OF packets with valid OF version and OF type fields
	packetIn, flowMod uint64
)

// roundUp rounds num up to the nearest multiple of 2^exp
func roundUp(num int, exp uint) int {
	tmp := num >> exp
	if tmp<<exp == num {
		return num
	} else {
		return (tmp + 1) << exp
	}
}

// checkIn attempts to extract the pattern from a PACKET_IN message that
// will be used to match it with a subsequent FLOW_MOD. The pattern in
// our case is the concatenation of <dstMac><srcMac> fields, which is returned
// if it is found within the PACKET_IN data, otherwise nil is returned.
func checkIn(ofPkt []byte) []byte {
	var pattern []byte
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
	if etherType == 0x0806 {
		//dstMac := data[0:6]
		//srcMac := data[6:12]
		from = ofp14.ETHER_DSTMAC_OFFSET
		to = ofp14.ETHER_ETHERTYPE_OFFSET
		pattern = data[from:to]
		log.Printf("PACKET_IN pattern: % x", pattern)
	}
	return pattern
}

// checkOut attempts to extract the pattern from a FLOW_MOD message that will
// be used to match it with a previous PACKET_IN. The pattern in our case is
// the concatenation of <OFPXMT_OFB_ETH_DST><OFPXMT_OFB_ETH_SRC> value fields
// in OXM segments, which is returned if it is found within the PACKET_IN data,
// otherwise nil is returned.
func checkOut(ofPkt []byte) []byte {
	var matchDstMac, matchSrcMac []byte
	var from, to int
	from = ofp14.FLOWMOD_MATCH_OXM0_OFFSET
	to = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_FIELD_OFFSET
	oxm0Class := int(binary.BigEndian.Uint16(ofPkt[from:to]))
	log.Printf("OXM class: % x", oxm0Class)

	if oxm0Class == ofp14.OFPXMC_OPENFLOW_BASIC {
		from = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_FIELD_OFFSET
		oxm0Field := uint8(ofPkt[from])
		log.Printf("OXM0 field: % x", oxm0Field)
		from = ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_LENGTH_OFFSET
		oxm0ValLength := uint8(ofPkt[from])
		log.Printf("OXM0 length: % x", oxm0Len)
		oxm0ValFrom := ofp14.FLOWMOD_MATCH_OXM0_OFFSET + ofp14.OXM_VALUE_OFFSET
		oxm0ValTo := oxm0ValFrom + oxm0ValLength

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
		log.Printf("FLOW_MOD (% x -> % x)", matchSrcMac, matchDstMac)
		return append(matchDstMac, matchSrcMac...)
	}
	return nil
}

func main() {
	flag.Parse()
	_, err := strconv.ParseUint(*ofport, 10, 32)

	fmt.Println("device: ", *device)
	fmt.Println("cpuprofile: ", *cpuprofile)
	fmt.Println("ofport: ", *ofport)
	fmt.Println("sniffer: ", *sniffer)

	var f *os.File
	if *cpuprofile != "" {
		f, err = os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
	}
	h := gohistogram.NewHistogram(20)

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Println(sig)
		fmt.Println(h)
		if *cpuprofile != "" {
			pprof.StopCPUProfile()
		}
		fmt.Println("PACKET_INs: ", packetIn)
		fmt.Println("FLOW_MODs: ", flowMod)
		os.Exit(0)
	}()

	packetsIn = make(map[uint32]int64)

	// Set filter
	filter := "tcp and port " + *ofport
	fmt.Printf("BPF filter: %s\n", filter)

	// Open device
	var packetSource *gopacket.PacketSource
	if *sniffer == "pcap" {
		handle, err = pcap.OpenLive(*device, snapshotLen, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	} else if *sniffer == "pfring" {
		//	ring, err := pfring.NewRing(*device, 65536, pfring.FlagPromisc)
		//	if err != nil {
		//		log.Fatal(err)
		//	}
		//	err = ring.SetBPFFilter(filter)
		//	err = ring.Enable()
		//	packetSource = gopacket.NewPacketSource(ring, layers.LayerTypeEthernet)
		//	ring.SetSocketMode(pfring.ReadOnly)

	}

	// Layers for decoding
	var (
		eth     layers.Ethernet
		ip      layers.IPv4
		tcp     layers.TCP
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ip, &tcp, &payload)
	decoded := []gopacket.LayerType{}

Sniffing:

	for packet := range packetSource.Packets() {

		err := parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			log.Println("Trouble decoding layers: ", err)
		}
		if len(decoded) == 0 {
			log.Println("Packet contained no valid layers")
			continue Sniffing
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeTCP:
				//src := uint32(tcp.SrcPort)
				//dst := uint32(tcp.DstPort)

				tcppaylen := len(tcp.Payload)

				// TCP segment with possible OF packets
				switch {

				// OF packets should at least contain a header (8 bytes)
				case tcppaylen >= 8:
					i := 0

					// Walk the TCP payload and extract possible OF packets (1 or more)
					for i < tcppaylen {
						ofplen := binary.BigEndian.Uint16(tcp.Payload[i+2 : i+4])
						ofpend := i + int(ofplen)
						if ofpend > int(tcppaylen) {
							log.Printf("OF packet ends beyond the TCP payload (%d, %d)."+
								"Ignoring packet...", ofpend, tcppaylen)
							continue Sniffing
						}

						ofpver := uint8(tcp.Payload[i])
						ofptype := uint8(tcp.Payload[i+1])

						// Consider only valid OF1.3 messages.
						// NOTE: valid OF1.3 messages that have been segmented but not
						// reassembled (i.e. do not have their OF header again)
						// will be ignored here
						if ofpver == 4 &&
							(ofptype >= 0 || ofptype <= ofp14.OFPT_MAX_TYPE) {

							ofPkt := tcp.Payload[i:ofpend]
							//ofpxid := binary.BigEndian.Uint32(ofPkt[4:8])

							switch ofptype {
							case ofp14.OFPT_PACKET_IN:
								packetIn += 1
								pattern := checkIn(ofPkt)
								if pattern != nil {
									// record it
								}
							case ofp14.OFPT_FLOW_MOD:
								flowMod += 1
								pattern := checkOut(ofPkt)
								if pattern != nil {
									// match it
								}

							} // end of switch ofptype
						} else {
							// stop walking the rest TCP segment
							log.Printf("Unknown OF version (%d) or OF type\n", ofpver)
							continue Sniffing
						}

						i = ofpend
					}

				}

				/*
					if dst == ofp {
						packetsIn[src] = time.Now().UnixNano()
					}

					if src == ofp {
						latency := time.Now().UnixNano() - packetsIn[dst]
						h.Add(float64(latency / 1000000.0))
					}*/
			}

		}
	}
}
