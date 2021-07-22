# DNS-Attacker-and-Detector-using-GO
Developed an on-path DNS poisoning attack tool and a passive DNS poisoning attack detector.

Both tools should be developed
in Go using the GoPacket library, and should support just plain (UDP) DNS
traffic over port 53.
-----------------------------------------------------------------------------------------------------------------------------------
The DNS packet injector, named 'dnspoison', captures the traffic from a network interface in promiscuous mode, and injects forged
responses to selected DNS A requests with the goal of poisoning the cache of the victim's resolver.

**go run dnspoison.go [-i interface] [-f hostnames] [expression]**

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    dnspoison should select a default interface to listen on. The same
    interface should be used for packet injection.

-f  Read a list of IP address and hostname pairs specifying the hostnames to
    be hijacked. If '-f' is not specified, dnspoison should forge replies to
    all observed requests with the chosen interface's IP address as an answer.

The optional expression argument is a BPF filter that specifies a subset of
the traffic to be monitored. This option is useful for targeting a single
victim or a group of victims.

The <hostnames> file should contain one IP and hostname pair per line,
separated by whitespace, in the following format:
10.6.6.6      foo.example.com
10.6.6.6      bar.example.com
  
Development:
  
Kindly refer to the file dnspoison.go for the implementation of the DNS Spoofing attack using Golang.

Following are the key features regarding the implementation:

1. I have consolidated the main application information as part of a Go struct "poisonCommandDetails"
    Description of each field:
     - device : Name of the device for live reading of packets (Updated when "-i" is provided)
     - hostfile : Name of the file for reading the list of IP address and hostname pairs specifying the hostnames to
    be hijacked. 
     - websiteNames : Internal Usage. List of website names from hostfile 
     - redirectLocations : Internal Usage. List of corresponding spoofed IP addresses from hostfile
     - promiscous : promiscous mode. Default value: true (Set in "main" function)
     - snapshot_len : Snapshot Length. Default value: 65535 (Set in "main" function)
     - bpf_expression : BPF filter


2. By default, dnspoison will spoof all DNS requests with the attacker's IP address. Also it will ensure
    it does not spoof the attacker's DNS requests.
    Example: go run dnspoison.go

3. I have tried to keep the execution and error handlings similar to that of dnsspoof(dsniff).
    By default, if not bpf_expression is provided it will add a default value of "udp and port 53"

4. Implementation
    - DNS Poison will start by reading each packet on live captures
    - It will check for DNS Query Packets(QR code as false) and spoof them basis on the condition(hostfile)
    - The original DNS Query Packet is processed to extract the Source and Destination's IP address, 
        MAC address and ports. All the information is saved as part of another struct(originalPacketDetails)
    - The DNS layer is reused and the appropriate fields are updated to represent it as a DNS Response layer
    - The reused and processed DNS layer is then added as part of a new packet where the source and 
        destination addresses are reversed and sent back to the victim's machine. 


-------------------------------------------------------------------------------------------------------------------------------------
The DNS poisoning attack detector named 'dnsdetect',
captures the traffic from a network interface in promiscuous mode and detects
DNS poisoning attack attempts. Detection is based on
identifying duplicate responses within a short time interval towards the same
destination, which contain different answers for the same A request (i.e., the
observation of the attacker's spoofed response and the server's actual
response).

go run dnsdetect.go [-i interface] [-r tracefile] expression

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    the program should select a default interface to listen on.

-r  Read packets from <tracefile> (tcpdump format). Useful for detecting
    DNS poisoning attacks in existing network traces.

expression is a BPF filter that specifies a subset of the traffic to be
monitored.
  
  
  Development:
  
Kindly refer to the file dnsdetect.go for the implementation of the DNS Spoof detection using Golang.

Following are the key features regarding the implementation:

1. I have consolidated the main application information as part of a Go struct "detectCommandDetails"
    Description of each field:
     - device : Name of the device for live reading of packets (Updated when "-i" is provided)
     - pcapFile : Name of the pcap file for offline file reading (Updated when "-r" is provided)
     - livePacketCapture : Internal usage. Value initially 0 for not initialized, 1 for live reading,
                            2 for offline file reading. 
     - promiscous : promiscous mode. Default value: true (Set in "main" function)
     - snapshot_len : Snapshot Length. Default value: 65535 (Set in "main" function)
     - bpf_expression : BPF filter


2. By default, dnsdetect will perform live reading on "eth0"
    Example: go run dnsdetect.go

3. Implementation
    - DNS Detect will read for all DNS packets (Query and Response)
    - It will keep track of the Query IDs of DNS layers for each DNS packet.
    - In case of live packet reading, I have made use of "timers" in Golang. 
      For every DNS packet response, the Query ID will be recorded in the data for 5 seconds using Timer.
      Once the timer expires the corresponding entry of the DNS Packet will be removed from the memory.
    - In case of offile file reading, the timestamps of each packet is recorded and maintained 
      (maintainDNSRecords). For all the packets that exceed the interval of 5 seconds are removed from 
      memory and are no longer tracked.
    - DNS Detect basically tries to find multiple responses with same Query ID and prints them if found.
    - Load balancing DNS Requests are taken into consideration. This means that in a case where a 
      machine sends multiple DNS Requests with the same Query ID then the corresponding number of responses
      with the same Query ID will not be treated as a DNS Poisoning Attempt. 

---------------------------------------------------------------------------------------------------------------------------------------
  
