# latte
SDN controller latency measuring tool 

![latte](./resources/latte.jpg)

## Usage
  1. Install Go
  2. Install dependencies
  
  ```bash
  go get github.com/VividCortex/gohistogram
  go get github.com/google/gopacket
  ```
  3. Build latte
  
  ```bash
  # PCAP version
  go build latte_pcap.go
  ```
  or 
  ```bash
  # PF_RING version
  go build latte_pfring.go
  ```
  4. Run latte to monitor OF traffic (port=6653) on the controller interface
  
  ```bash
  sudo ./latte_pfring <ifname>
  ```
  
  5. Exit latte and get latency histogram
  
  ```bash
  ^C
  ```


## Sample latency histogram
- Results are in milliseconds
- Controller: ODL Beryllium RC2
- Generator: MT-Cbench (5 threads, 10 switches per thread)

```
Total: 216724
0.11667228145571665      .....................................................................................................
16.453421916272944       .........................................................
35.922695312499634       .......................
55.54585101367283        .......
72.84179189112582        ...
91.10193204530309        ..
113.50277998411435       .
129.6542056074765        
147.11814345991573       
162.93155893536104       
178.10569105691062       
192.67924528301893       
208.3571428571429        
220.390625       
239.98591549295776       
```
