package main

import (
	"flag"
	"fmt"
	"github.com/VividCortex/gohistogram"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pfring"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"
)

var device = flag.String("device", "lo", "device to sniff packets from")
var cpuprofile = flag.String("cpuprofile", "",
	"enable CPU prof and write results to file")
var ofport = flag.String("ofport", "6653", "OpenFlow port number")
var sniflib = flag.String("sniflib", "pcap",
	"Library to use for packet sniffing: pcap or pfring")

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	packets_in   map[int32]int64
	lostPackets  int64
)

// TODO: use arrays instead of maps in Cbench tests
// TODO: further optimizations
func main() {
	flag.Parse()
	var ofp int64
	ofp, err = strconv.ParseInt(*ofport, 10, 64)

	fmt.Println("device: ", *device)
	fmt.Println("cpuprofile: ", *cpuprofile)
	fmt.Println("ofport: ", *ofport)
	fmt.Println("sniflib: ", *ofport)

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
		os.Exit(0)
	}()

	packets_in = make(map[int32]int64)

	// Set filter
	filter := "tcp and port " + *ofport
	fmt.Println(filter)

	// Open device
	var packetSource *gopacket.PacketSource
	if *sniflib == "pcap" {
		handle, err = pcap.OpenLive(*device, snapshot_len, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	} else if *sniflib == "pfring" {
		ring, err := pfring.NewRing(*device, 65536, pfring.FlagPromisc)
		if err != nil {
			log.Fatal(err)
		}
		err = ring.SetBPFFilter(filter)
		err = ring.Enable()
		packetSource = gopacket.NewPacketSource(ring, layers.LayerTypeEthernet)
		ring.SetSocketMode(pfring.ReadOnly)

	}

	var (
		ethLayer layers.Ethernet
		ipLayer layers.IPv4
		tcpLayer layers.TCP
	)

	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer, 
			&ipLayer, 
			&tcpLayer,
		)
		
		foundLayerTypes := []gopacket.LayerType{}
		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		//tcpLayer := packet.Layer(layers.LayerTypeTCP)
		//tcp, _ := tcpLayer.(*layers.TCP)
		src := int32(tcpLayer.SrcPort)
		dst := int32(tcpLayer.DstPort)
		if dst == int32(ofp) {
			packets_in[src] = time.Now().UnixNano()
		}

		if src == int32(ofp) {
			latency := time.Now().UnixNano() - packets_in[dst]
			h.Add(float64(latency / 1000000.0))
		}

	}
}
