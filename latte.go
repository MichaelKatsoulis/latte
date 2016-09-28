package main

import (
	"flag"
	"fmt"
	"github.com/anastop/latte/matching"
	"github.com/anastop/latte/ofp14"
	"github.com/codahale/hdrhistogram"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"github.com/google/gopacket/pfring"
	"encoding/binary"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"
)

// Stats collects statistics-related info about a run
type Stats struct {
	hist                     *hdrhistogram.Histogram
	ofcount                  int64
	incount, inreg           int64
	outcount, outreg, outmat int64
	lost, late, orphan       int64
}

// report prints statistic results when finished
func report(c chan os.Signal, reg map[string]int64, st *Stats, cpuprofile *string) {
	sig := <-c
	fmt.Println(sig)
	for _, v := range reg {
		if v > 0 {
			st.lost += 1
		}
	}
	scalef := 1000000.0

	fmt.Println()
	fmt.Println("Latency(ms)    Percentile    TotalCount")
	fmt.Println("---------------------------------------")
	for _, b := range st.hist.CumulativeDistribution() {
		pct := b.Quantile / 100.0
		fmt.Printf("%13.8f  %2.6f %15d\n",
			float64(b.ValueAt)/scalef, pct, b.Count)
	}
	fmt.Println()
	fmt.Printf("total_count: %d\n", st.hist.TotalCount())
	fmt.Printf("min: %f\n", float64(st.hist.Min())/scalef)
	fmt.Printf("max: %f\n", float64(st.hist.Max())/scalef)
	fmt.Printf("mean: %f\n", st.hist.Mean()/scalef)
	fmt.Printf("stddev: %f\n", st.hist.StdDev()/scalef)

	fmt.Println()
	fmt.Printf("Inmsg total: %d\n", st.incount)
	fmt.Printf("Inmsg registered: %d\n", st.inreg)
	fmt.Printf("Inmsg unreplied: %d (%.1f%%)\n",
		st.lost, float64(st.lost)*100.0/float64(st.inreg))
	fmt.Printf("Outmsg total: %d\n", st.outcount)
	fmt.Printf("Outmsg registered: %d\n", st.outreg)
	fmt.Printf("Outmsg matched: %d\n", st.outmat)
	fmt.Printf("Outmsg late: %d (%.1f%%)\n",
		st.late, float64(st.late)*100.0/float64(st.outmat))
	fmt.Printf("Outmsg orphan: %d\n", st.orphan)
	if *cpuprofile != "" {
		pprof.StopCPUProfile()
	}
	os.Exit(0)
}

func main() {
	var err error

	// cmd line options
	var (
		device = flag.String("device", "lo",
			"device to sniff packets from")
		cpuprofile = flag.String("cpuprofile", "",
			"enable CPU prof and write results to file")
		ofport  = flag.String("ofport", "6653", "OpenFlow port number")
		sniffer = flag.String("sniffer", "pcap",
			"Library to use for packet sniffing: pcap or pfring")
		matcher = flag.String("matcher", "multinet",
			"Traffic scenario to consider for matching")
		dolog = flag.Bool("log", false,
			"Enable logging")
		lateThres = flag.Float64("late-threshold", 2000.0,
			"Threshold (msec) above which a late response is considered lost")
		nanoLateThres = int64(*lateThres) * 1000000
	)

	// Packet matching
	var (
		reg             map[string]int64
		m               matching.Matcher
		intype, outtype uint8
	)

	flag.Parse()
	fmt.Println("device: ", *device)
	fmt.Println("cpuprofile: ", *cpuprofile)
	fmt.Println("ofport: ", *ofport)
	fmt.Println("sniffer: ", *sniffer)
	fmt.Println("matcher: ", *matcher)
	fmt.Println("log: ", *dolog)
	fmt.Println("late threshold (msec): ", *lateThres)

	_, err = strconv.ParseUint(*ofport, 10, 32)

	if !*dolog {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	if *cpuprofile != "" {
		var f *os.File
		f, err = os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
	}

	reg = make(map[string]int64)
	st := Stats{}
	st.hist = hdrhistogram.New(1, 20000000000, 2)

	// Set filter
	filter := "tcp and port " + *ofport
	fmt.Printf("BPF filter: %s\n", filter)

	// Open device
	var pktSrc *gopacket.PacketSource
	if *sniffer == "pcap" {
		var (
			snapshotLen int32         = 1024
			promiscuous bool          = false
			timeout     time.Duration = 30 * time.Second
			handle      *pcap.Handle
		)

		handle, err = pcap.OpenLive(*device, snapshotLen, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		pktSrc = gopacket.NewPacketSource(handle, handle.LinkType())
	} else if *sniffer == "pfring" {
		//	ring, err := pfring.NewRing(*device, 65536, pfring.FlagPromisc)
		//	if err != nil {
		//		log.Fatal(err)
		//	}
		//	err = ring.SetBPFFilter(filter)
		//	err = ring.Enable()
		//	pktSrc = gopacket.NewPacketSource(ring, layers.LayerTypeEthernet)
		//	ring.SetSocketMode(pfring.ReadOnly)

	}

	if *matcher == "multinet" {
		m = matching.MultinetTraffic{}
	}
	intype = m.InMsg()
	outtype = m.OutMsg()

	// Setup finalization
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go report(sigs, reg, &st, cpuprofile)

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

	for pkt := range pktSrc.Packets() {

		err := parser.DecodeLayers(pkt.Data(), &decoded)
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
							st.ofcount += 1

							switch ofptype {
							case intype:
								st.incount += 1
								pattern := m.CheckIn(ofPkt, ip.SrcIP, uint16(tcp.SrcPort))
								if pattern != nil {
									st.inreg += 1
									s := string(pattern)
									log.Printf("C <- % x\n", pattern)
									_, exists := reg[s]

									// The pattern already exists in reg map,
									// this is a packet loss case
									if exists {
										st.lost += 1
									}
									reg[s] = time.Now().UnixNano()
								}
							case outtype:
								st.outcount += 1
								pattern := m.CheckOut(ofPkt, ip.DstIP, uint16(tcp.DstPort))
								if pattern != nil {
									st.outreg += 1
									s := string(pattern)
									log.Printf("C -> % x\n", pattern)
									val, exists := reg[s]
									if exists {
										st.outmat += 1
										log.Printf("MATCH!!\n")
										latency := (time.Now().UnixNano() - val)
										if latency < 0 {
											panic("Negative latency?")
										}
										if latency > nanoLateThres {
											st.late += 1
										}
										st.hist.RecordValue(latency)
										reg[s] = 0
									} else {
										// unmatched repliest... normal?
										st.orphan += 1
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
