// gen_evpn_nlri generates EVPN NLRI wire bytes (Types 1-5, RFC 7432 / RFC 9136)
// using GoBGP's packet library, and prints them as Rust byte-array literals for
// use as test vectors in packet/src/evpn.rs.
//
// Usage:
//
//	go run .
//
// Regenerate whenever EVPN encoding is changed.
// Parameters match the GOBGP_TYPE* constants in evpn.rs exactly.
package main

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func rustBytes(buf []byte) string {
	parts := make([]string, len(buf))
	for i, b := range buf {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return "&[" + strings.Join(parts, ", ") + "]"
}

func mustSerialize(nlri *bgp.EVPNNLRI) []byte {
	buf, err := nlri.Serialize()
	if err != nil {
		panic(fmt.Sprintf("serialize failed: %v", err))
	}
	return buf
}

func mustSerializeErr(nlri *bgp.EVPNNLRI, err error) []byte {
	if err != nil {
		panic(fmt.Sprintf("create nlri failed: %v", err))
	}
	return mustSerialize(nlri)
}

func zeroESI() bgp.EthernetSegmentIdentifier {
	return bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}}
}

func rdTwoOctet(admin uint16, assigned uint32) bgp.RouteDistinguisherInterface {
	return bgp.NewRouteDistinguisherTwoOctetAS(admin, assigned)
}

func rdFourOctet(admin uint32, assigned uint16) bgp.RouteDistinguisherInterface {
	return bgp.NewRouteDistinguisherFourOctetAS(admin, assigned)
}

func main() {
	esi := zeroESI()

	// -----------------------------------------------------------------------
	// Type-1: Ethernet Auto-Discovery (RFC 7432 §7.1)
	// -----------------------------------------------------------------------

	// Type-1: RD=TwoOctetAS(100,100), ESI=zeros, ETag=0xFFFFFFFF (mass withdrawal), label=0
	{
		nlri := bgp.NewEVPNEthernetAutoDiscoveryRoute(rdTwoOctet(100, 100), esi, 0xFFFFFFFF, 0)
		buf := mustSerialize(nlri)
		fmt.Printf("// Type-1: RD=TwoOctetAS(100,100), ESI=zeros, ETag=0xFFFFFFFF (mass withdrawal), label=0\n")
		fmt.Printf("const GOBGP_TYPE1_MASS_WITHDRAW: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Type-1: RD=FourOctetAS(5,6), ESI=zeros, ETag=3, label=200
	{
		nlri := bgp.NewEVPNEthernetAutoDiscoveryRoute(rdFourOctet(5, 6), esi, 3, 200)
		buf := mustSerialize(nlri)
		fmt.Printf("// Type-1: RD=FourOctetAS(5,6), ESI=zeros, ETag=3, label=200\n")
		fmt.Printf("const GOBGP_TYPE1_WITH_LABEL: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// -----------------------------------------------------------------------
	// Type-2: MAC/IP Advertisement (RFC 7432 §7.2)
	// -----------------------------------------------------------------------

	// Type-2: RD=TwoOctetAS(100,100), ESI=zeros, ETag=42, MAC=aa:bb:cc:dd:ee:ff, no IP, label=200
	{
		nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(
			rdTwoOctet(100, 100), esi, 42,
			"aa:bb:cc:dd:ee:ff",
			netip.Addr{}, // no IP
			[]uint32{200},
		)
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-2: RD=TwoOctetAS(100,100), ESI=zeros, ETag=42, MAC=aa:bb:cc:dd:ee:ff, no IP, label=200\n")
		fmt.Printf("const GOBGP_TYPE2_MAC_ONLY: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Type-2: RD=FourOctetAS(5,6), ESI=zeros, ETag=3, MAC=01:23:45:67:89:ab, IP=192.2.1.2, label1=3, label2=4
	{
		nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(
			rdFourOctet(5, 6), esi, 3,
			"01:23:45:67:89:ab",
			netip.MustParseAddr("192.2.1.2"),
			[]uint32{3, 4},
		)
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-2: RD=FourOctetAS(5,6), ESI=zeros, ETag=3, MAC=01:23:45:67:89:ab, IP=192.2.1.2, label1=3, label2=4\n")
		fmt.Printf("const GOBGP_TYPE2_MAC_IPV4_TWO_LABELS: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// -----------------------------------------------------------------------
	// Type-3: Inclusive Multicast Ethernet Tag (RFC 7432 §7.3)
	// -----------------------------------------------------------------------

	// Type-3: RD=FourOctetAS(5,6), ETag=3, IP=192.2.1.2
	{
		nlri, err := bgp.NewEVPNMulticastEthernetTagRoute(rdFourOctet(5, 6), 3, netip.MustParseAddr("192.2.1.2"))
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-3: RD=FourOctetAS(5,6), ETag=3, IP=192.2.1.2\n")
		fmt.Printf("const GOBGP_TYPE3_IPV4: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Type-3: RD=FourOctetAS(5,6), ETag=3, IP=2001:db8::1
	{
		nlri, err := bgp.NewEVPNMulticastEthernetTagRoute(rdFourOctet(5, 6), 3, netip.MustParseAddr("2001:db8::1"))
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-3: RD=FourOctetAS(5,6), ETag=3, IP=2001:db8::1\n")
		fmt.Printf("const GOBGP_TYPE3_IPV6: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// -----------------------------------------------------------------------
	// Type-4: Ethernet Segment (RFC 7432 §7.4)
	// -----------------------------------------------------------------------

	// Type-4: RD=TwoOctetAS(100,100), ESI=zeros, IP=192.2.1.2
	{
		nlri, err := bgp.NewEVPNEthernetSegmentRoute(rdTwoOctet(100, 100), esi, netip.MustParseAddr("192.2.1.2"))
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-4: RD=TwoOctetAS(100,100), ESI=zeros, IP=192.2.1.2\n")
		fmt.Printf("const GOBGP_TYPE4_IPV4: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Type-4: RD=FourOctetAS(5,6), ESI=zeros, IP=2001:db8::1
	{
		nlri, err := bgp.NewEVPNEthernetSegmentRoute(rdFourOctet(5, 6), esi, netip.MustParseAddr("2001:db8::1"))
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-4: RD=FourOctetAS(5,6), ESI=zeros, IP=2001:db8::1\n")
		fmt.Printf("const GOBGP_TYPE4_IPV6: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// -----------------------------------------------------------------------
	// Type-5: IP Prefix (RFC 9136 §5)
	// -----------------------------------------------------------------------

	// Type-5: RD=TwoOctetAS(100,100), ESI=zeros, ETag=0, prefix=10.10.10.0/24, GW=10.10.10.1, label=200
	{
		nlri, err := bgp.NewEVPNIPPrefixRoute(
			rdTwoOctet(100, 100), esi, 0,
			24,
			netip.MustParseAddr("10.10.10.0"),
			netip.MustParseAddr("10.10.10.1"),
			200,
		)
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-5: RD=TwoOctetAS(100,100), ESI=zeros, ETag=0, prefix=10.10.10.0/24, GW=10.10.10.1, label=200\n")
		fmt.Printf("const GOBGP_TYPE5_IPV4: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Type-5: RD=FourOctetAS(5,6), ESI=zeros, ETag=3, prefix=2001:db8::/64, GW=::, label=3
	{
		nlri, err := bgp.NewEVPNIPPrefixRoute(
			rdFourOctet(5, 6), esi, 3,
			64,
			netip.MustParseAddr("2001:db8::"),
			netip.MustParseAddr("::"),
			3,
		)
		buf := mustSerializeErr(nlri, err)
		fmt.Printf("// Type-5: RD=FourOctetAS(5,6), ESI=zeros, ETag=3, prefix=2001:db8::/64, GW=::, label=3\n")
		fmt.Printf("const GOBGP_TYPE5_IPV6: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
