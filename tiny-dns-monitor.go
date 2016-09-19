package main

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "fmt"
    "time"
)

//decoding layers
var (
	eth     layers.Ethernet
	ip      layers.IPv4
	ip6		layers.IPv6
	udp     layers.UDP
	dns     layers.DNS
	payload gopacket.Payload
)


func main() {
	//open the interface (en0) and only recieve UDP packets
	if handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp"); err != nil {  // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			decoded := []gopacket.LayerType{}

			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&eth,
				&ip,
				&ip6,
				&udp,
				&dns,
				&payload)

			err = parser.DecodeLayers(packet.Data(), &decoded)
			if err != nil {
				fmt.Printf("Error decoding packet: %v\n", err)
				continue
			}
			if len(decoded) == 0 {
				fmt.Printf("Packet contained no valid layers\n")
				continue
			}

			for _, layerType := range decoded {
			   switch layerType {
			        case layers.LayerTypeDNS:
						for _, q := range dns.Questions {
							s := string(q.Name)
							var string_type = ""
							switch q.Type {
								case layers.DNSTypeA:
									string_type = "A"
								case layers.DNSTypeNS:
									string_type = "NS"
								case layers.DNSTypeMD:
									string_type = "MD"
								case layers.DNSTypeMF:
									string_type = "MF"
								case layers.DNSTypeCNAME:
									string_type = "CNAME"
								case layers.DNSTypeSOA:
									string_type = "SOA"
								case layers.DNSTypeMB:
									string_type = "MB"
								case layers.DNSTypeMX:
									string_type = "MX"
								case layers.DNSTypeTXT:
									string_type = "TXT"
								case layers.DNSTypeAAAA:
									string_type = "AAAA"
								case layers.DNSTypeSRV:
									string_type = "SRV"
							}

							t := time.Now()
							fmt.Printf("%v, ", t)
						    fmt.Printf("%v, ", string_type)
						    fmt.Println(s)
						}
			   }
			}

	  	}
	}
}
