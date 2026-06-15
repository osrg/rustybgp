// gen_flowspec_nlri generates Flowspec NLRI wire bytes using GoBGP's packet
// library, and prints them as Rust byte-array literals for use as test vectors.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to Flowspec NLRI encoding.
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

func ipPrefix(s string) *bgp.IPAddrPrefix {
	p, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(s))
	if err != nil {
		panic(err)
	}
	return p
}

func flowspecV4(components []bgp.FlowSpecComponentInterface) []byte {
	nlri, err := bgp.NewFlowSpecUnicast(bgp.RF_FS_IPv4_UC, components)
	if err != nil {
		panic(err)
	}
	buf, err := nlri.Serialize()
	if err != nil {
		panic(err)
	}
	return buf
}

func flowspecV6(components []bgp.FlowSpecComponentInterface) []byte {
	nlri, err := bgp.NewFlowSpecUnicast(bgp.RF_FS_IPv6_UC, components)
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
	// --- V4: DstPrefix only ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecDestinationPrefix(ipPrefix("10.0.1.0/24")),
		})
		fmt.Printf("// IPv4 Flowspec: DstPrefix=10.0.1.0/24\n")
		fmt.Printf("pub const V4_DST_PREFIX: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: DstPrefix + Protocol=TCP(6) + DstPort=80 ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecDestinationPrefix(ipPrefix("10.0.1.0/24")),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 6),
			}),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 80),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: DstPrefix=10.0.1.0/24, Protocol=TCP(6), DstPort=80\n")
		fmt.Printf("pub const V4_DST_PREFIX_PROTO_TCP_PORT_80: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: DstPort >= 1024 AND <= 65535 ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DST_PORT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_GT_EQ, 1024),
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_LT_EQ|bgp.DEC_NUM_OP_END|bgp.DEC_NUM_OP_AND, 65535),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: DstPort >= 1024 AND <= 65535\n")
		fmt.Printf("pub const V4_DST_PORT_RANGE: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: DstPrefix, offset=0 ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecDestinationPrefix6(ipPrefix("2001:db8::/32"), 0),
		})
		fmt.Printf("// IPv6 Flowspec: DstPrefix=2001:db8::/32, offset=0\n")
		fmt.Printf("pub const V6_DST_PREFIX_NO_OFFSET: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: DstPrefix with offset=16 (tunnel encap) ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecDestinationPrefix6(ipPrefix("2001:db8::/32"), 16),
		})
		fmt.Printf("// IPv6 Flowspec: DstPrefix=2001:db8::/32, offset=16\n")
		fmt.Printf("pub const V6_DST_PREFIX_WITH_OFFSET: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: NextHeader=TCP(6) + FlowLabel=100 ---
	// FLOW_SPEC_TYPE_IP_PROTO (type 3) is used for Next Header in IPv6.
	// FLOW_SPEC_TYPE_LABEL (type 13) is the IPv6 Flow Label.
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 6),
			}),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_LABEL, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 100),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: NextHeader=TCP(6), FlowLabel=100\n")
		fmt.Printf("pub const V6_NEXT_HEADER_TCP_FLOW_LABEL_100: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
