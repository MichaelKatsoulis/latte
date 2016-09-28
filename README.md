[![Build Status](https://travis-ci.org/anastop/latte.svg?branch=master)](https://travis-ci.org/anastop/latte)
[![Go Report Card](https://goreportcard.com/badge/github.com/anastop/latte)](https://goreportcard.com/report/github.com/anastop/latte)

# latte
`latte` is a simple network probe written in Go that measures the response 
latency of an SDN controller for certain types of request/response message
pairs. 

`latte` runs on the controller side, sniffing the OpenFlow traffic coming in and 
going out of it. The filtering of certain request/response pairs to measure the latency 
of (e.g. `PACKET_IN`/`FLOW_MOD`) is based on "matchers". Matchers are sets of 
functions (or, strictly speaking, golang interfaces) defining: 
- what types of incoming/outgoing OF messages form request/response pairs, and
  therefore should be selected for deeper inspection
- what patterns within each selected message should be inspected and extracted in 
  order to uniquely match a response with an existing, in-flight request

Matchers are provided as a command line option to `latte`. Currently the
following matchers are supported:
- `multinet`: matches `PACKET_IN` requests and `FLOW_MOD` replies generated 
  using [Multinet](https://github.com/intracom-telecom-sdn/multinet#generate-packet_in-events-with-arp-payload), based on the following patterns:
    - `PACKET_IN`s should contain Ethernet frames with ARP payload
    - `FLOW_MOD`s should contain two `OXM`s with `OFPXMC_OPENFLOW_BASIC` class and 
      `OFPXMT_OFB_ETH_DST`, `OFPXMT_OFB_ETH_SRC` match fields

![latte](./resources/latte.jpg)


## Usage
  1. Install Go 
  2. Install libpcap development library (`yum install libpcap-devel` or `apt-get install libpcap-dev`)
  3. Init your `GOPATH` env variable, 
  e.g. 
  ```bash
  export GOPATH=$HOME/gocode/
  ```

  4. Fetch and build latte:
  
  ```bash
  go get github.com/anastop/latte
  go install github.com/anastop/latte
  ```
  
  5. Run latte:
  
  ```bash
  sudo $GOPATH/bin/latte -device lo -ofport 6653 -sniffer pcap -matcher "multinet" -late-threshold 400
  ```
  
  This will start monitoring:
   * OpenFlow traffic (port=6653) 
   * on loopback interface on the controller side
   * using libpcap for capturing packets
   * using "multinet" matcher to detect packets generated through Multinet (see above)
   * and a latency threshold of 400.0 msec, to consider any response that exceeds this as late
  
  6. Generate some traffic. 
  
  For a quick test, replay the `multinet_1w_traffic` pcap file located under `resources` folder.  
  This is a capture from real traffic generated using Multinet (1 worker) and the OpenDaylight controller. 

  To do this, invoke in another shell the `tcpreplay` utility as follows:
  ```bash
  sudo tcpreplay -i lo multinet_1w_traffic.pcap
  ```
  
  7. When you're done, hit Ctrl+C to stop latte and get the results

  ```bash  
Latency(ms)    Percentile    TotalCount
---------------------------------------
   0.00447900  0.000000               1
   0.04121500  0.500000             461
   0.12134300  0.750000             690
   0.28671900  0.875000             806
 161.48070300  0.937500             864
 236.97817500  0.968750             916
 236.97817500  0.984375             916
 236.97817500  0.992188             916
 236.97817500  0.996094             916
 425.72185500  0.998047             919
 425.72185500  1.000000             919

total_count: 919
min: 0.004448
max: 425.721855
mean: 15.590453
stddev: 57.842297

Inmsg total: 1018
Inmsg registered: 928
Inmsg unreplied: 9 (1.0%)
Outmsg total: 920
Outmsg registered: 920
Outmsg matched: 919
Outmsg late: 0 (0.0%)
Outmsg orphan: 1
```

Statistics:
- `Inmsg total`: total incoming messages having the same OF type as the one
  defined in matcher
- `Inmsg registered`: messages from `Inmsg total` that were successfully 
  registered for subsequent comparisons, as they were found containing the 
  pattern defined in matcher
- `Inmsg unreplied`: messages from `Inmsg registered` for which no reply 
  was ever detected
- `Outmsg total`: total outgoing messages having the same OF type as the one
  defined in matcher 
- `Outmsg registered`: messages from `Outmsg total` that were successfully 
  registered for matching with registered incoming messages, as they were 
  found containing the pattern defined in matcher
- `Outmsg matched`: messages from `Outmsg registered` that were successfully 
  matched with an existing registered incoming message. Latencies are being
  computed for these ones.
- `Outmsg late`: messages from `Outmsg matched` considered late because they
  exceeded the latency threshold
- `Outmsg orphan`: messages from `Outmsg registered` for which no match was 
  found within the registered incoming messages. Normally these should be 
  controller initiated messages, just having the same pattern as the one 
  defined in matcher.

All results are reported in milliseconds.
