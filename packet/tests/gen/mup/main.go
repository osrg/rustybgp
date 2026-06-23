// gen_mup generates BGP-MUP NLRI and Extended Community wire bytes using
// GoBGP's packet library, and prints them as Rust byte-array literals for
// use as test vectors in mup.rs.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to MUP NLRI or Extended Community encoding.
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

func mupBytes(nlri *bgp.MUPNLRI) []byte {
	buf, err := nlri.Serialize()
	if err != nil {
		panic(fmt.Sprintf("serialize failed: %v", err))
	}
	return buf
}

func rd() bgp.RouteDistinguisherInterface {
	return bgp.NewRouteDistinguisherTwoOctetAS(100, 200)
}

func main() {
	// --- ISD IPv4: RD=100:200, Prefix=10.0.0.0/24 ---
	{
		buf := mupBytes(bgp.NewMUPInterworkSegmentDiscoveryRoute(
			rd(),
			netip.MustParsePrefix("10.0.0.0/24"),
		))
		fmt.Printf("// ISD IPv4: RD=100:200, Prefix=10.0.0.0/24\n")
		fmt.Printf("const GOBGP_ISD_IPV4: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- ISD IPv6: RD=100:200, Prefix=2001:db8::/32 ---
	{
		buf := mupBytes(bgp.NewMUPInterworkSegmentDiscoveryRoute(
			rd(),
			netip.MustParsePrefix("2001:db8::/32"),
		))
		fmt.Printf("// ISD IPv6: RD=100:200, Prefix=2001:db8::/32\n")
		fmt.Printf("const GOBGP_ISD_IPV6: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- DSD IPv4: RD=100:200, Address=192.0.2.1 ---
	{
		buf := mupBytes(bgp.NewMUPDirectSegmentDiscoveryRoute(
			rd(),
			netip.MustParseAddr("192.0.2.1"),
		))
		fmt.Printf("// DSD IPv4: RD=100:200, Address=192.0.2.1\n")
		fmt.Printf("const GOBGP_DSD_IPV4: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- DSD IPv6: RD=100:200, Address=2001:db8::1 ---
	{
		buf := mupBytes(bgp.NewMUPDirectSegmentDiscoveryRoute(
			rd(),
			netip.MustParseAddr("2001:db8::1"),
		))
		fmt.Printf("// DSD IPv6: RD=100:200, Address=2001:db8::1\n")
		fmt.Printf("const GOBGP_DSD_IPV6: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- T1ST IPv4 (no source): RD=100:200, Prefix=192.168.0.0/24, TEID=0x12345678, QFI=9, EA=10.0.0.1 ---
	// TEID is passed as a netip.Addr (4-byte IPv4 representation of the 32-bit value).
	{
		buf := mupBytes(bgp.NewMUPType1SessionTransformedRoute(
			rd(),
			netip.MustParsePrefix("192.168.0.0/24"),
			netip.MustParseAddr("18.52.86.120"), // 0x12345678
			9,
			netip.MustParseAddr("10.0.0.1"),
			nil,
		))
		fmt.Printf("// T1ST IPv4 (no source): RD=100:200, Prefix=192.168.0.0/24, TEID=0x12345678, QFI=9, EA=10.0.0.1\n")
		fmt.Printf("const GOBGP_T1ST_IPV4_NO_SRC: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- T1ST IPv4 (with source): same + Source=10.0.0.2 ---
	{
		src := netip.MustParseAddr("10.0.0.2")
		buf := mupBytes(bgp.NewMUPType1SessionTransformedRoute(
			rd(),
			netip.MustParsePrefix("192.168.0.0/24"),
			netip.MustParseAddr("18.52.86.120"), // 0x12345678
			9,
			netip.MustParseAddr("10.0.0.1"),
			&src,
		))
		fmt.Printf("// T1ST IPv4 (with source): RD=100:200, Prefix=192.168.0.0/24, TEID=0x12345678, QFI=9, EA=10.0.0.1, Src=10.0.0.2\n")
		fmt.Printf("const GOBGP_T1ST_IPV4_WITH_SRC: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- T1ST IPv6: RD=100:200, Prefix=2001:db8::/32, TEID=0x12345678, QFI=9, EA=2001:db8::1 ---
	// TEID is always 4 bytes (IPv4 addr) regardless of prefix address family.
	{
		buf := mupBytes(bgp.NewMUPType1SessionTransformedRoute(
			rd(),
			netip.MustParsePrefix("2001:db8::/32"),
			netip.MustParseAddr("18.52.86.120"), // 0x12345678
			9,
			netip.MustParseAddr("2001:db8::1"),
			nil,
		))
		fmt.Printf("// T1ST IPv6: RD=100:200, Prefix=2001:db8::/32, TEID=0x12345678, QFI=9, EA=2001:db8::1\n")
		fmt.Printf("const GOBGP_T1ST_IPV6: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- T2ST IPv4 full TEID (ea_len=64): EA=10.0.0.1, TEID=0xDEADBEEF ---
	// ea_len = IP bits (32) + TEID bits (32) = 64
	{
		buf := mupBytes(bgp.NewMUPType2SessionTransformedRoute(
			rd(),
			64,
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("222.173.190.239"), // 0xDEADBEEF
		))
		fmt.Printf("// T2ST IPv4 full TEID (ea_len=64): RD=100:200, EA=10.0.0.1, TEID=0xDEADBEEF\n")
		fmt.Printf("const GOBGP_T2ST_IPV4_FULL_TEID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- T2ST IPv4 truncated TEID (ea_len=48): EA=10.0.0.1, TEID upper 16 bits = 0xDEAD ---
	// ea_len = IP bits (32) + TEID bits (16) = 48; only first 2 bytes of TEID are serialized.
	{
		buf := mupBytes(bgp.NewMUPType2SessionTransformedRoute(
			rd(),
			48,
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("222.173.0.0"), // first 2 bytes = 0xDEAD
		))
		fmt.Printf("// T2ST IPv4 truncated TEID (ea_len=48): RD=100:200, EA=10.0.0.1, TEID upper 16 bits=0xDEAD\n")
		fmt.Printf("const GOBGP_T2ST_IPV4_TRUNC_TEID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- T2ST IPv4 no TEID (ea_len=32): EA=10.0.0.1 ---
	// ea_len = IP bits (32) + TEID bits (0) = 32; no TEID bytes appended.
	{
		buf := mupBytes(bgp.NewMUPType2SessionTransformedRoute(
			rd(),
			32,
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("0.0.0.0"),
		))
		fmt.Printf("// T2ST IPv4 no TEID (ea_len=32): RD=100:200, EA=10.0.0.1\n")
		fmt.Printf("const GOBGP_T2ST_IPV4_NO_TEID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- MUP Extended Community: sid2=100, sid4=10000 ---
	{
		ec := bgp.NewMUPExtended(100, 10000)
		buf, err := ec.Serialize()
		if err != nil {
			panic(fmt.Sprintf("mup ext comm serialize failed: %v", err))
		}
		fmt.Printf("// MUP Extended Community: type=0x0c, sub_type=0x00, sid2=100, sid4=10000\n")
		fmt.Printf("const GOBGP_MUP_EXTENDED: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
