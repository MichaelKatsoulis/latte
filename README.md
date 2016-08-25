[![Build Status](https://travis-ci.org/anastop/latte.svg?branch=master)](https://travis-ci.org/anastop/latte)
[![Go Report Card](https://goreportcard.com/badge/github.com/anastop/latte)](https://goreportcard.com/report/github.com/anastop/latte)

# latte
`latte` is a simple network probe written in Go that measures the response 
latency of an SDN controller for certain types of request/response message
pairs.

It runs on the controller side, sniffing the OpenFlow traffic coming in and 
going out of it. It filters predefined message types that form request/response 
pairs (e.g. `PACKET_IN`/`FLOW_MOD`), and deeply inspects each of them to extract 
patterns that uniquely match a request to a response. The time diff between requests
and responses is the response latency, which is finally reported in the form of a
histogram.

Currently, the following request/response pairs are supported:

- PACKET_IN requests and FLOW_MOD replies generated using [Multinet](https://github.com/intracom-telecom-sdn/multinet#generate-packet_in-events-with-arp-payload)

![latte](./resources/latte.jpg)


## Usage
  1. Install Go and init your `GOPATH` env variable, 
  e.g. 
  ```bash
  export GOPATH=$HOME/gocode/
  ```

  2. Fetch and build latte:
  
  ```bash
  go get github.com/anastop/latte
  go install github.com/anastop/latte
  ```
  
  3. Run latte to monitor OF traffic (port=6653) on the controller interface:
  
  ```bash
  sudo $GOPATH/bin/latte -device lo -ofport 6653 -sniffer pcap
  ```
  
  4. Generate some traffic. 
  
  For a quick test, replay the `multinet_1w_traffic` pcap file located under `resources` folder.  
  This is a capture from real traffic generated using Multinet (1 worker) and the OpenDaylight controller. 

  In another shell, invoke the `tcpreplay` utility as follows:
  ```bash
  sudo tcpreplay -i lo multinet_1w_traffic.pcap
  ```
  
  5. When you're done, stop latte and get latency histogram
  
  ```bash
  ^C
  
  Total: 919
0.2873239436619723 	 ..........................................................................................................................................................
5.8671875 	 ...........................
93 	 
99 	 
106 	 
125.2 	 .
138.83333333333334 	 .
144.75 	 
155.5 	 
186.5 	 
192.66666666666666 	 .
203 	 
209 	 
217.66666666666666 	 
515.4666666666667 	 ...
521 	 ..
691.8571428571429 	 .
922 	 
1005.5 	 
1013.4 	 .

Lost packets: 9
Orphan responses: 1
```

The above results are in milliseconds
