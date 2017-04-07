package main

import (
	"os/exec"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"log"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Metric struct {
	Rate         int
	CurrentValue int
	PrevValue    int
}

func getHandleFunc(metric *int, metricDescription string) func(w http.ResponseWriter, r *http.Request){
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(fmt.Sprintf("%d\n", *metric))); err != nil {
			log.Fatal("Can't write ", metricDescription)
		}
	}
}

func createPacketSource(device string, filter string) (*gopacket.PacketSource, *pcap.Handle) {
	var (
		snapshotLen int32 = 1024
		promiscuous bool = true
		timeout time.Duration = 100 * time.Millisecond
		err error
		handler *pcap.Handle
		packetSource *gopacket.PacketSource
	)

	handler, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	packetSource = gopacket.NewPacketSource(handler, handler.LinkType())

	return packetSource, handler
}

// main
func main() {
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

	requests := &Metric{
		Rate:         0,
		CurrentValue: 0,
		PrevValue:    0,
	}

	responses := &Metric{
		Rate:         0,
		CurrentValue: 0,
		PrevValue:    0,
	}

	ticker := time.NewTicker(1 * time.Second)

	//requests2 := 0
	go func() {
		command := exec.Command("/bin/sleep", "100")
		command.Start()
		for {
			std, err := command.Output()
			time.Sleep(2 * time.Second)
			if (err != nil) {
				log.Fatal(err)
			}
			fmt.Println(std)
			fmt.Println("foo")
		}
		//requests2 = os.Run("")
	}()

	// requestFilter := fmt.Sprintf("src %s and dst %s and (tcp[0xd] & tcp-syn) != 0", *clientIP, *gorbIP)
  requestFilter := fmt.Sprintf("tcp and dst %s and tcp[(tcp[0xc] >> 4) << 2 : 4] = 0x47455420", *gorbIP)
	fmt.Printf("Request filter: %s\n", requestFilter)

	requestPacketSource, requestHandler := createPacketSource(*device, requestFilter)
	defer requestHandler.Close()

	responseFilter := fmt.Sprintf("dst %s and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)", *clientIP)
	fmt.Printf("Response filter: %s\n", responseFilter)

	responsePacketSource, responseHandler := createPacketSource(*device, responseFilter)
	defer responseHandler.Close()

	go func() {
		http.HandleFunc("/request/count", getHandleFunc(&requests.CurrentValue, "request count"))
		http.HandleFunc("/response/count", getHandleFunc(&responses.CurrentValue, "response count"))
		http.HandleFunc("/request/rate", getHandleFunc(&requests.Rate, "request rate"))
		http.HandleFunc("/response/rate", getHandleFunc(&responses.Rate, "response rate"))

		log.Fatal(http.ListenAndServe(":6666", nil))
	}()

	for {
		select {
		case <-ticker.C:
			go func() {
					requests.Rate = requests.CurrentValue - requests.PrevValue
					requests.PrevValue = requests.CurrentValue
					responses.Rate = responses.CurrentValue - responses.PrevValue
					responses.PrevValue = responses.CurrentValue
		  }()
		case request := <-requestPacketSource.Packets():
			go func() {
				log.Print(request)
				requests.CurrentValue += 1
				log.Print("Requests: ", requests.CurrentValue)
			}()
		case response := <-responsePacketSource.Packets():
			go func() {
				log.Print(response)
				responses.CurrentValue += 1
				log.Print("Responses: ", responses.CurrentValue)
			}()
		}
	}
}
