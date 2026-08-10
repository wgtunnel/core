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
	switch packet[0] >> 4 {
	case 4:
		return parseIPv4(packet) // UDP or TCP
	case 6:
		return parseIPv6(packet)
	default:
		return nil, fmt.Errorf("unsupported IP version")
	}
}

func parseIPv4(packet []byte) (*parsedPacket, error) {
	if len(packet) < ipHeaderMinLen+4 { // ports at least
		return nil, fmt.Errorf("packet too short")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < ipHeaderMinLen || len(packet) < ihl+4 {
		return nil, fmt.Errorf("invalid IPv4 header length")
	}
	protocol := packet[9]
	if protocol != 6 && protocol != 17 {
		return nil, fmt.Errorf("not TCP/UDP")
	}
	totalLen := min(int(binary.BigEndian.Uint16(packet[2:4])), len(packet))
	srcIP, _ := netip.AddrFromSlice(packet[12:16])
	dstIP, _ := netip.AddrFromSlice(packet[16:20])
	l4 := ihl
	srcPort := binary.BigEndian.Uint16(packet[l4 : l4+2])
	dstPort := binary.BigEndian.Uint16(packet[l4+2 : l4+4])

	p := &parsedPacket{
		Raw:         packet[:totalLen],
		IPVersion:   4,
		IPHeaderLen: ihl,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		Protocol:    protocol,
		TotalLen:    totalLen,
		SrcPort:     srcPort,
		DstPort:     dstPort,
	}
	if protocol == 17 && totalLen >= ihl+udpHeaderLen {
		p.UDPHeaderOff = ihl
		p.PayloadOff = ihl + udpHeaderLen
		p.Payload = packet[p.PayloadOff:totalLen]
	}
	return p, nil
}

func parseIPv6(packet []byte) (*parsedPacket, error) {
	if len(packet) < 40+4 {
		return nil, fmt.Errorf("ipv6 packet too short")
	}
	next := packet[6]
	if next != 6 && next != 17 {
		// no extension-header walk — good enough for this
		return nil, fmt.Errorf("not TCP/UDP")
	}
	srcIP := netip.AddrFrom16([16]byte(packet[8:24]))
	dstIP := netip.AddrFrom16([16]byte(packet[24:40]))
	srcPort := binary.BigEndian.Uint16(packet[40:42])
	dstPort := binary.BigEndian.Uint16(packet[42:44])

	p := &parsedPacket{
		Raw:       packet,
		IPVersion: 6,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Protocol:  next,
		SrcPort:   srcPort,
		DstPort:   dstPort,
	}
	if next == 17 {
		udpLen := int(binary.BigEndian.Uint16(packet[44:46]))
		if udpLen >= 8 && 40+udpLen <= len(packet) {
			p.TotalLen = 40 + udpLen
			p.UDPHeaderOff = 40
			p.PayloadOff = 48
			p.Payload = packet[48 : 40+udpLen]
			p.Raw = packet[:p.TotalLen]
		}
	}
	return p, nil
}

func isDNSQueryToFake(p *parsedPacket, v4, v6 netip.Addr) bool {
	if p.DstPort != 53 || p.Protocol != 17 {
		return false
	}
	if v4.IsValid() && p.DstIP == v4 {
		return true
	}
	if v6.IsValid() && p.DstIP == v6 {
		return true
	}
	return false
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
	const ihl = 20
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

	out[0] = 0x45
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	if len(orig.Raw) >= 6 {
		copy(out[4:6], orig.Raw[4:6])
	}
	out[8] = 64
	out[9] = 17

	src4 := orig.DstIP.As4()
	dst4 := orig.SrcIP.As4()
	copy(out[12:16], src4[:])
	copy(out[16:20], dst4[:])

	udpOff := ihl
	binary.BigEndian.PutUint16(out[udpOff:udpOff+2], orig.DstPort)
	binary.BigEndian.PutUint16(out[udpOff+2:udpOff+4], orig.SrcPort)
	binary.BigEndian.PutUint16(out[udpOff+4:udpOff+6], uint16(udpLen))
	out[udpOff+6] = 0
	out[udpOff+7] = 0
	copy(out[udpOff+8:], dnsPayload)

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
