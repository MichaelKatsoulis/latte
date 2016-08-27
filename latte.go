package main

import (
	"flag"
	"fmt"
	"github.com/VividCortex/gohistogram"
	"github.com/anastop/latte/matching"
	"github.com/anastop/latte/ofp14"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
var match = flag.String("match", "multinet",
	"Traffic scenario to consider for matching")

var (
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	checkedIn   map[string]int64
	packetsLost int64
	orphanRes   int64
	m           matching.Match
)

func main() {
	flag.Parse()
	_, err := strconv.ParseUint(*ofport, 10, 32)

	fmt.Println("device: ", *device)
	fmt.Println("cpuprofile: ", *cpuprofile)
	fmt.Println("ofport: ", *ofport)
	fmt.Println("sniffer: ", *sniffer)
	fmt.Println("match: ", *match)

	if *cpuprofile != "" {
		var f *os.File
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
		fmt.Println("Mean: %d\n", h.Mean())
		fmt.Println("99th percentile: %d\n", h.Quantile(float64(0.99)))
		fmt.Printf("Lost packets: %d\n", packetsLost)
		fmt.Printf("Orphan responses: %d\n", orphanRes)
		if *cpuprofile != "" {
			pprof.StopCPUProfile()
		}
		os.Exit(0)
	}()

	checkedIn = make(map[string]int64)

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

	if *match == "multinet" {
		m = matching.MultinetMatch
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
				tcppaylen := len(tcp.Payload)

				// TCP segment with possible OF packets
				switch {

				// OF packets should at least contain a header (8 bytes)
				case tcppaylen >= 8:
					i := 0

					// Walk the TCP payload and extract possible OF packets (1 or more)
					for i < tcppaylen-8 {
						ofplen := binary.BigEndian.Uint16(tcp.Payload[i+2 : i+4])
						ofpend := i + int(ofplen)
						if ofpend > int(tcppaylen) {
							// OF packet ends beyond the TCP payload. Ignore it
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
							case m.InMsgType:
								pattern := m.InMatch(ofPkt, ip.SrcIP, uint16(tcp.SrcPort))
								if pattern != nil {
									s := string(pattern)
									log.Printf("C <- % x\n", pattern)
									_, exists := checkedIn[s]

									// The pattern already exists in checkedIn map,
									// this is a packet loss case
									if exists {
										packetsLost += 1
									}
									checkedIn[s] = time.Now().UnixNano()
								}
							case m.OutMsgType:
								pattern := m.OutMatch(ofPkt, ip.DstIP, uint16(tcp.DstPort))
								if pattern != nil {
									s := string(pattern)
									log.Printf("C -> % x\n", pattern)
									val, exists := checkedIn[s]
									if exists {
										log.Printf("MATCH!!\n")
										latency := time.Now().UnixNano() - val
										h.Add(float64(latency / 1000000.0))
										checkedIn[s] = 0
									} else {
										// unmatched replies... normal?
										orphanRes += 1
									}
								}
							} // end of switch ofptype
						} else {
							// Unknown OF version or type. Stop walking the rest TCP segment
							continue Sniffing
						}
						i = ofpend
					}
				}
			}
		}
	}
}
