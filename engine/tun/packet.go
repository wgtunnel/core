package tun

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	ipVersion4     = 4
	ipHeaderMinLen = 20
	udpHeaderLen   = 8
)

// parsedPacket holds the bits we need for DNS hijacking
type parsedPacket struct {
	Raw          []byte
	IPVersion    int
	IPHeaderLen  int
	SrcIP        netip.Addr
	DstIP        netip.Addr
	Protocol     uint8 // 17 = UDP
	TotalLen     int
	SrcPort      uint16
	DstPort      uint16
	UDPHeaderOff int
	PayloadOff   int
	Payload      []byte
}

func parseIPPacket(packet []byte) (*parsedPacket, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short")
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		return parseIPv4UDP(packet)
	case 6:
		return parseIPv6UDP(packet)
	default:
		return nil, fmt.Errorf("unsupported IP version %d", version)
	}
}

func parseIPv6UDP(packet []byte) (*parsedPacket, error) {
	if len(packet) < 48 {
		return nil, fmt.Errorf("ipv6 packet too short")
	}
	if packet[6] != 17 {
		return nil, fmt.Errorf("not UDP")
	}
	udpLen := int(binary.BigEndian.Uint16(packet[44:46]))
	if udpLen < 8 || 40+udpLen > len(packet) {
		return nil, fmt.Errorf("invalid UDP length")
	}
	return &parsedPacket{
		Raw:          packet[:40+udpLen],
		IPVersion:    6,
		SrcIP:        netip.AddrFrom16([16]byte(packet[8:24])),
		DstIP:        netip.AddrFrom16([16]byte(packet[24:40])),
		Protocol:     17,
		TotalLen:     40 + udpLen,
		SrcPort:      binary.BigEndian.Uint16(packet[40:42]),
		DstPort:      binary.BigEndian.Uint16(packet[42:44]),
		UDPHeaderOff: 40,
		PayloadOff:   48,
		Payload:      packet[48 : 40+udpLen],
	}, nil
}

func parseIPv4UDP(packet []byte) (*parsedPacket, error) {
	if len(packet) < ipHeaderMinLen+udpHeaderLen {
		return nil, fmt.Errorf("packet too short")
	}
	version := int(packet[0] >> 4)
	if version != ipVersion4 {
		return nil, fmt.Errorf("not IPv4")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < ipHeaderMinLen || len(packet) < ihl+udpHeaderLen {
		return nil, fmt.Errorf("invalid IPv4 header length")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen > len(packet) {
		totalLen = len(packet)
	}
	protocol := packet[9]
	if protocol != 17 {
		return nil, fmt.Errorf("not UDP")
	}
	srcIP, _ := netip.AddrFromSlice(packet[12:16])
	dstIP, _ := netip.AddrFromSlice(packet[16:20])
	udpOff := ihl
	srcPort := binary.BigEndian.Uint16(packet[udpOff : udpOff+2])
	dstPort := binary.BigEndian.Uint16(packet[udpOff+2 : udpOff+4])
	payloadOff := udpOff + udpHeaderLen
	if payloadOff > totalLen {
		return nil, fmt.Errorf("udp payload out of bounds")
	}
	return &parsedPacket{
		Raw:          packet[:totalLen],
		IPVersion:    version,
		IPHeaderLen:  ihl,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		Protocol:     protocol,
		TotalLen:     totalLen,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		UDPHeaderOff: udpOff,
		PayloadOff:   payloadOff,
		Payload:      packet[payloadOff:totalLen],
	}, nil
}

func isDNSQueryTo(p *parsedPacket, fake netip.Addr) bool {
	if p.DstPort != 53 {
		return false
	}
	return p.DstIP == fake
}

// buildDNSResponse constructs a reply packet (IPv4 or IPv6) with the DNS response
func buildDNSResponse(orig *parsedPacket, dnsPayload []byte, mtu int) ([]byte, error) {
	switch orig.IPVersion {
	case 4:
		return buildIPv4DNSResponse(orig, dnsPayload, mtu)
	case 6:
		return buildIPv6DNSResponse(orig, dnsPayload, mtu)
	default:
		return nil, fmt.Errorf("unsupported IP version %d", orig.IPVersion)
	}
}

func buildIPv4DNSResponse(orig *parsedPacket, dnsPayload []byte, mtu int) ([]byte, error) {
	ihl := orig.IPHeaderLen
	if ihl < 20 {
		ihl = 20
	}
	udpLen := 8 + len(dnsPayload)
	totalLen := ihl + udpLen

	if mtu > 0 && totalLen > mtu {
		maxPayload := mtu - ihl - 8
		if maxPayload < 12 {
			return nil, fmt.Errorf("mtu too small")
		}
		dnsPayload = dnsPayload[:maxPayload]
		udpLen = 8 + len(dnsPayload)
		totalLen = ihl + udpLen
	}

	out := make([]byte, totalLen)

	// IPv4 header
	out[0] = 0x45
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	if len(orig.Raw) >= 6 {
		copy(out[4:6], orig.Raw[4:6])
	}
	out[8] = 64
	out[9] = 17

	// swap addresses
	src4 := orig.DstIP.As4()
	dst4 := orig.SrcIP.As4()
	copy(out[12:16], src4[:])
	copy(out[16:20], dst4[:])

	// UDP
	udpOff := 20
	binary.BigEndian.PutUint16(out[udpOff:udpOff+2], orig.DstPort)
	binary.BigEndian.PutUint16(out[udpOff+2:udpOff+4], orig.SrcPort)
	binary.BigEndian.PutUint16(out[udpOff+4:udpOff+6], uint16(udpLen))
	out[udpOff+6] = 0
	out[udpOff+7] = 0
	copy(out[udpOff+8:], dnsPayload)

	// IPv4 header checksum
	binary.BigEndian.PutUint16(out[10:12], ipChecksum(out[:20]))

	return out, nil
}

func buildIPv6DNSResponse(orig *parsedPacket, dnsPayload []byte, mtu int) ([]byte, error) {
	udpLen := 8 + len(dnsPayload)
	totalLen := 40 + udpLen

	if mtu > 0 && totalLen > mtu {
		maxPayload := mtu - 40 - 8
		if maxPayload < 12 {
			return nil, fmt.Errorf("mtu too small")
		}
		dnsPayload = dnsPayload[:maxPayload]
		udpLen = 8 + len(dnsPayload)
		totalLen = 40 + udpLen
	}

	out := make([]byte, totalLen)

	// IPv6 header
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(udpLen))
	out[6] = 17
	out[7] = 64

	// swap addresses
	copy(out[8:24], orig.DstIP.AsSlice())
	copy(out[24:40], orig.SrcIP.AsSlice())

	// UDP header
	udpOff := 40
	binary.BigEndian.PutUint16(out[udpOff:udpOff+2], orig.DstPort)
	binary.BigEndian.PutUint16(out[udpOff+2:udpOff+4], orig.SrcPort)
	binary.BigEndian.PutUint16(out[udpOff+4:udpOff+6], uint16(udpLen))
	binary.BigEndian.PutUint16(out[udpOff+6:udpOff+8], 0)
	copy(out[udpOff+8:], dnsPayload)

	csum := ipv6UDPChecksum(
		orig.DstIP, orig.SrcIP,
		uint32(udpLen), 17,
		out[udpOff:],
	)
	binary.BigEndian.PutUint16(out[udpOff+6:udpOff+8], csum)

	return out, nil
}

// ipv6UDPChecksum computes the checksum for an IPv6 UDP packet.
func ipv6UDPChecksum(src, dst netip.Addr, upperLayerLen uint32, nextHeader uint8, udpAndPayload []byte) uint16 {
	var sum uint32

	srcBytes := src.AsSlice()
	dstBytes := dst.AsSlice()

	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcBytes[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dstBytes[i : i+2]))
	}

	sum += upperLayerLen
	sum += uint32(nextHeader)

	for i := 0; i+1 < len(udpAndPayload); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpAndPayload[i : i+2]))
	}
	if len(udpAndPayload)%2 == 1 {
		sum += uint32(udpAndPayload[len(udpAndPayload)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
