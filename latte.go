package main

import (
	"fmt"
	"github.com/VividCortex/gohistogram"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	device       string
	ofport       int32
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
	device = os.Args[1]
	ofport = 6653
	h := gohistogram.NewHistogram(20)

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Println(sig)
		fmt.Println(h)
		os.Exit(0)
	}()

	packets_in = make(map[int32]int64)

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "tcp and port 6653"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		src := int32(tcp.SrcPort)
		dst := int32(tcp.DstPort)
		if dst == ofport {
			packets_in[src] = time.Now().UnixNano()
		}

		if src == ofport {
			latency := time.Now().UnixNano() - packets_in[dst]
			h.Add(float64(latency / 1000000.0))
		}

	}
}
