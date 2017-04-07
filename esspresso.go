package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"log"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// main
func main() {
	var err error

	requests := 0
	responses := 0

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


	go func() {
		http.HandleFunc("/requests", func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte(fmt.Sprintf("%d\n", requests))); err != nil {
				log.Fatal("Can't write rate")
			}
		})
		http.HandleFunc("/responses", func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte(fmt.Sprintf("%d\n", responses))); err != nil {
				log.Fatal("Can't write rate")
			}
		})
		log.Fatal(http.ListenAndServe(":6666", nil))
	}()

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
		timeout     time.Duration = 1 * time.Second
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

	for {
		select {
		case request := <-requestPacketSource.Packets():
			log.Print(request)
			requests += 1
			log.Print("Requests: ", requests)
		case response := <-responsePacketSource.Packets():
			log.Print(response)
			responses += 1
			log.Print("Responses: ", responses)
		}
	}
}
