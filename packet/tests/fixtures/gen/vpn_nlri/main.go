// gen_vpn_nlri generates VPNv4/VPNv6 NLRI wire bytes using GoBGP's packet
// library, and prints them as Rust byte-array literals for use as test vectors.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to VPN NLRI encoding.
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

func vpnNlri(prefixStr string, labels *bgp.MPLSLabelStack, rd bgp.RouteDistinguisherInterface) []byte {
	prefix := netip.MustParsePrefix(prefixStr)
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, *labels, rd)
	if err != nil {
		panic(err)
	}
	buf, err := nlri.Serialize()
	if err != nil {
		panic(err)
	}
	return buf
}

func main() {
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)

	// --- VPNv4 single label ---
	{
		buf := vpnNlri("10.0.1.0/24", bgp.NewMPLSLabelStack(100), rd)
		fmt.Printf("// VPNv4: label=100, RD=65000:100, 10.0.1.0/24\n")
		fmt.Printf("pub const VPNV4_SINGLE_LABEL: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- VPNv4 label stack [100, 200] ---
	{
		buf := vpnNlri("10.0.1.0/24", bgp.NewMPLSLabelStack(100, 200), rd)
		fmt.Printf("// VPNv4: labels=[100, 200], RD=65000:100, 10.0.1.0/24\n")
		fmt.Printf("pub const VPNV4_LABEL_STACK: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- VPNv4 default route ---
	{
		buf := vpnNlri("0.0.0.0/0", bgp.NewMPLSLabelStack(0), rd)
		fmt.Printf("// VPNv4: label=0, RD=65000:100, 0.0.0.0/0\n")
		fmt.Printf("pub const VPNV4_DEFAULT: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- VPNv6 single label ---
	{
		buf := vpnNlri("2001:db8::/32", bgp.NewMPLSLabelStack(300), rd)
		fmt.Printf("// VPNv6: label=300, RD=65000:100, 2001:db8::/32\n")
		fmt.Printf("pub const VPNV6_SINGLE_LABEL: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- VPNv6 label stack [100, 200] ---
	{
		buf := vpnNlri("2001:db8::/32", bgp.NewMPLSLabelStack(100, 200), rd)
		fmt.Printf("// VPNv6: labels=[100, 200], RD=65000:100, 2001:db8::/32\n")
		fmt.Printf("pub const VPNV6_LABEL_STACK: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
