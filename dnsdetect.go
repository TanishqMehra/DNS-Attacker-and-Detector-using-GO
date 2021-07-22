package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type detectCommandDetails struct {
	device            string
	pcapFile          string
	livePacketCapture int //0 for not initialized, 1 for true, 2 for reading from file
	promiscuous       bool
	snapshot_len      int32
	bpf_expression    string
}

type maintainDNSRecords struct {
	txid      []uint16
	timestamp []time.Time
	website   [][]string
	answers   [][]string
}

var (
	txid_request_count_map = make(map[uint16]int)
)

func main() {
	cDetails := detectCommandDetails{livePacketCapture: 0, promiscuous: true, snapshot_len: 65535}

	bpf_expr := ""

	// Accessing all the commands received during the command line execution
	commandLineArgs := os.Args[1:]

	for j := 0; j < len(commandLineArgs); j++ {
		var value = commandLineArgs[j]
		switch value {
		case "-i":
			if cDetails.livePacketCapture == 0 {
				cDetails.device = commandLineArgs[j+1]
				j += 1
				cDetails.livePacketCapture = 1
			}

		case "-r":
			cDetails.pcapFile = commandLineArgs[j+1]
			j += 1
			cDetails.livePacketCapture = 2
		default:
			bpf_expr = bpf_expr + " " + value
		}
	}
	cDetails.bpf_expression = bpf_expr
	cDetails.readPackets()
}

func (cDetails detectCommandDetails) readPackets() {
	var deviceFound bool = false

	if cDetails.livePacketCapture == 0 {
		cDetails.livePacketCapture = 1 // default behaviour is live reading
	}

	if cDetails.livePacketCapture == 1 { // live reading
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
			log.Fatal("dnsdetect: ", cDetails.device, ": No such device exists")
		}

		handle, err := pcap.OpenLive(cDetails.device, 1600, true, pcap.BlockForever)
		fmt.Println("listening on ", cDetails.device, ",  snapshot length ", cDetails.snapshot_len)
		if err != nil {
			log.Fatal(err)
		}
		cDetails.processPacketData(*handle)
	} else { // offline reading
		handle, err := pcap.OpenOffline(cDetails.pcapFile)
		fmt.Println("reading from file ", cDetails.pcapFile, ",  snapshot length ", cDetails.snapshot_len)
		cDetails.processPacketData(*handle)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (cDetails detectCommandDetails) processPacketData(handle pcap.Handle) {

	dnsRecords := maintainDNSRecords{txid: make([]uint16, 0), website: make([][]string, 0), answers: make([][]string, 0)}

	// Add BPF filter
	handle.SetBPFFilter(cDetails.bpf_expression)

	packetSource := gopacket.NewPacketSource(&handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		dnsRecords.extractPacketInformation(packet, cDetails)
	}
}

func (dnsRecords *maintainDNSRecords) extractPacketInformation(packet gopacket.Packet, cDetails detectCommandDetails) {

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	var latestTimeStamp time.Time
	var oldestTimeStamp time.Time

	if dnsLayer != nil {

		dns, _ := dnsLayer.(*layers.DNS)

		if dns.QR == true && dns.ANCount > 0 {

			dnsQueryExists := contains(dnsRecords.txid, dns.ID)
			// fmt.Println(dns.ID.String)
			if dnsQueryExists == -1 {

				dnsRecords.txid = append([]uint16{dns.ID}, dnsRecords.txid...)
				latestTimeStamp = packet.Metadata().Timestamp
				dnsRecords.timestamp = append([]time.Time{latestTimeStamp}, dnsRecords.timestamp...)

				dnsRecords.website = append([][]string{fetchWebsites(dns)}, dnsRecords.website...)

				dnsRecords.answers = append([][]string{fetchAnswers(dns)}, dnsRecords.answers...)
				if cDetails.livePacketCapture == 1 {
					timer := time.NewTimer(5 * time.Second)
					go func() {
						<-timer.C
						if len(dnsRecords.txid) > 0 {
							dnsRecords.removeOldestRecord()
						}
					}()
				} else {
					if len(dnsRecords.txid) > 1 {
						oldestTimeStamp = dnsRecords.timestamp[0]
						sub := latestTimeStamp.Sub(oldestTimeStamp)
						for sub.Seconds() > 5 {
							dnsRecords.removeOldestRecord()
							oldestTimeStamp = dnsRecords.timestamp[0]
							sub = latestTimeStamp.Sub(oldestTimeStamp)
						}
					}
				}
			} else {
				if txid_request_count_map[dns.ID] > 1 {
					txid_request_count_map[dns.ID] -= 1
				} else {

					dnsRecords.generateAndPrintResponse(packet, dns, dnsQueryExists)
				}
			}
		} else if dns.QR == false {
			if _, ok := txid_request_count_map[dns.ID]; ok {
				txid_request_count_map[dns.ID] += 1
			} else {
				txid_request_count_map[dns.ID] = 1
			}
		}
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

}

func (dnsRecords *maintainDNSRecords) generateAndPrintResponse(packet gopacket.Packet, dns *layers.DNS, recordIndex int) {
	fmt.Println("------------------------------------------------------------------------------")
	finalDisplayString := ""
	finalDisplayString += packet.Metadata().Timestamp.Format("20060102-15:04:05.32536")
	finalDisplayString += "\t"
	finalDisplayString += "DNS Poisoning Attempt\n"
	finalDisplayString += "TXID " + strconv.Itoa(int(dnsRecords.txid[recordIndex]))
	finalDisplayString += "\t"
	finalDisplayString += "Request " + dnsRecords.website[recordIndex][0] + "\n"

	finalDisplayString += "Answer1 "

	for _, value := range dnsRecords.answers[recordIndex] {
		finalDisplayString += value + " "
	}
	finalDisplayString += "\n"

	finalDisplayString += "Answer2 "

	for _, value := range fetchAnswers(dns) {
		finalDisplayString += value + " "
	}
	finalDisplayString += "\n"

	fmt.Println(finalDisplayString)
}

func (dnsRecords *maintainDNSRecords) removeOldestRecord() {
	oldest_dns_txid := dnsRecords.txid[len(dnsRecords.txid)-1]
	dnsRecords.txid = dnsRecords.txid[:len(dnsRecords.txid)-1]
	dnsRecords.website = dnsRecords.website[:len(dnsRecords.website)-1]
	dnsRecords.answers = dnsRecords.answers[:len(dnsRecords.answers)-1]
	_, ok := txid_request_count_map[oldest_dns_txid]
	if ok {
		delete(txid_request_count_map, oldest_dns_txid)
	}
}

func fetchWebsites(dns *layers.DNS) []string {
	var websites_in_dns []string
	for _, dnsQuestion := range dns.Questions {
		websites_in_dns = append(websites_in_dns, string(dnsQuestion.Name))
	}
	return websites_in_dns
}

func fetchAnswers(dns *layers.DNS) []string {
	var answers_in_dns []string
	for _, dnsAnswer := range dns.Answers {
		answers_in_dns = append(answers_in_dns, dnsAnswer.IP.String())
	}
	return answers_in_dns
}

func contains(arr []uint16, element uint16) int {
	for index, v := range arr {
		if v == element {
			return index
		}
	}
	return -1
}
