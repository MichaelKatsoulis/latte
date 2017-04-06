package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	//"os"
	//"os/signal"
	//"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// main
func main() {
	var err error

	// cmd line options
	var (
		device   = flag.String("device", "docker0", "device to sniff packets from")
		clientIP = flag.String("client-ip", "0.0.0.0", "The client container IP")
		gorbIP   = flag.String("gorb-ip", "0.0.0.0", "The IP gorb listens to")
		dolog    = flag.Bool("log", true, "Enable logging")
	)

	flag.Parse()
	fmt.Println("device: ", *device)

	if !*dolog {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	// clientIP := "172.17.0.4"
	// gorbIP := "10.0.2.15"

	requestFilter := fmt.Sprintf("src %s and dst %s and (tcp[0xd] & tcp-syn) != 0", *clientIP, *gorbIP)
	responseFilter := fmt.Sprintf("dst %s and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)", *clientIP)

	fmt.Printf("Request filter: %s\n", requestFilter)
	fmt.Printf("Response filter: %s\n", responseFilter)

	// Open device
	var requestPacketSource *gopacket.PacketSource
	var responsePacketSource *gopacket.PacketSource

	var (
		snapshotLen int32         = 1024
		promiscuous bool          = true
		timeout     time.Duration = 30 * time.Second
		handle_res  *pcap.Handle
		handle_req  *pcap.Handle
	)

	handle_req, err = pcap.OpenLive(*device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle_req.Close()

	if err := handle_req.SetBPFFilter(requestFilter); err != nil {
		log.Fatal(err)
	}

	requestPacketSource = gopacket.NewPacketSource(handle_req, handle_req.LinkType())

	handle_res, err = pcap.OpenLive(*device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle_res.Close()

	if err := handle_res.SetBPFFilter(responseFilter); err != nil {
		log.Fatal(err)
	}
	responsePacketSource = gopacket.NewPacketSource(handle_res, handle_res.LinkType())

	// Setup finalization

	/*
	sigs_res := make(chan os.Signal, 1)
	signal.Notify(sigs_res, syscall.SIGINT, syscall.SIGTERM)
	//go report(sigs, reg, &st, cpuprofile)
	sigs_req := make(chan os.Signal, 1)
	signal.Notify(sigs_req, syscall.SIGINT, syscall.SIGTERM)
        */
	requests := 0
	responses := 0

	for {
		select {
		case _ = <-requestPacketSource.Packets():
			requests += 1
			log.Print("Requests: %s", requests)
		case _ = <-responsePacketSource.Packets():
			responses += 1
			log.Print("Responses: %s", responses)
		}
	}
}

