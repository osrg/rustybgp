// gen_labeled_nlri generates BGP Labeled Unicast NLRI wire bytes using
// GoBGP's packet library, and prints them as Rust byte-array literals for
// use as test vectors in labeled.rs.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to Labeled Unicast NLRI encoding.
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

func labeledBytes(prefix netip.Prefix, labels ...uint32) []byte {
	nlri, err := bgp.NewLabeledIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(labels...))
	if err != nil {
		panic(fmt.Sprintf("NewLabeledIPAddrPrefix failed: %v", err))
	}
	buf, err := nlri.Serialize()
	if err != nil {
		panic(fmt.Sprintf("Serialize failed: %v", err))
	}
	return buf
}

func main() {
	// --- IPv4 single label: label=100, 10.0.1.0/24 ---
	{
		buf := labeledBytes(netip.MustParsePrefix("10.0.1.0/24"), 100)
		fmt.Printf("// IPv4 single label: label=100, prefix=10.0.1.0/24\n")
		fmt.Printf("const GOBGP_V4_SINGLE_LABEL: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- IPv4 label stack: labels=[100, 200], 10.0.1.0/24 ---
	{
		buf := labeledBytes(netip.MustParsePrefix("10.0.1.0/24"), 100, 200)
		fmt.Printf("// IPv4 label stack [100, 200]: prefix=10.0.1.0/24\n")
		fmt.Printf("const GOBGP_V4_LABEL_STACK: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- IPv4 host route: label=500, 192.168.1.1/32 ---
	{
		buf := labeledBytes(netip.MustParsePrefix("192.168.1.1/32"), 500)
		fmt.Printf("// IPv4 host route: label=500, prefix=192.168.1.1/32\n")
		fmt.Printf("const GOBGP_V4_HOST: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- IPv4 unreach (withdraw label 0x800000): 10.0.1.0/24 ---
	{
		buf := labeledBytes(netip.MustParsePrefix("10.0.1.0/24"), bgp.WITHDRAW_LABEL)
		fmt.Printf("// IPv4 unreach (withdraw label 0x800000): prefix=10.0.1.0/24\n")
		fmt.Printf("const GOBGP_V4_UNREACH: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- IPv6 single label: label=300, 2001:db8::/32 ---
	{
		buf := labeledBytes(netip.MustParsePrefix("2001:db8::/32"), 300)
		fmt.Printf("// IPv6 single label: label=300, prefix=2001:db8::/32\n")
		fmt.Printf("const GOBGP_V6_SINGLE_LABEL: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- IPv6 label stack: labels=[100, 200], 2001:db8::/48 ---
	{
		buf := labeledBytes(netip.MustParsePrefix("2001:db8::/48"), 100, 200)
		fmt.Printf("// IPv6 label stack [100, 200]: prefix=2001:db8::/48\n")
		fmt.Printf("const GOBGP_V6_LABEL_STACK: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
