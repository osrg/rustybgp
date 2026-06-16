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

func flowspecVpnV4(rd bgp.RouteDistinguisherInterface, components []bgp.FlowSpecComponentInterface) []byte {
	nlri, err := bgp.NewFlowSpecVPN(bgp.RF_FS_IPv4_VPN, rd, components)
	if err != nil {
		panic(err)
	}
	buf, err := nlri.Serialize()
	if err != nil {
		panic(err)
	}
	return buf
}

func flowspecVpnV6(rd bgp.RouteDistinguisherInterface, components []bgp.FlowSpecComponentInterface) []byte {
	nlri, err := bgp.NewFlowSpecVPN(bgp.RF_FS_IPv6_VPN, rd, components)
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

	// --- V4: SrcPrefix=192.168.1.0/24 ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecSourcePrefix(ipPrefix("192.168.1.0/24")),
		})
		fmt.Printf("// IPv4 Flowspec: SrcPrefix=192.168.1.0/24\n")
		fmt.Printf("pub const V4_SRC_PREFIX: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: Port=8080 (combined src+dst) ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_PORT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 8080),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: Port=8080 (src+dst)\n")
		fmt.Printf("pub const V4_PORT: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: SrcPort=443 ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_SRC_PORT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 443),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: SrcPort=443\n")
		fmt.Printf("pub const V4_SRC_PORT: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: IcmpType=8 (echo request) + IcmpCode=0 ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_ICMP_TYPE, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 8),
			}),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_ICMP_CODE, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 0),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: IcmpType=8 (echo request), IcmpCode=0\n")
		fmt.Printf("pub const V4_ICMP_TYPE_CODE: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: TcpFlags MATCH SYN (0x02) ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_TCP_FLAG, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.BITMASK_FLAG_OP_MATCH|bgp.BITMASK_FLAG_OP_END, 0x02),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: TcpFlags MATCH SYN (0x02)\n")
		fmt.Printf("pub const V4_TCP_FLAGS: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: PacketLen <= 1500 ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_PKT_LEN, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_LT_EQ|bgp.DEC_NUM_OP_END, 1500),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: PacketLen <= 1500\n")
		fmt.Printf("pub const V4_PACKET_LEN: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: Dscp=46 (EF) ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DSCP, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 46),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: Dscp=46 (EF)\n")
		fmt.Printf("pub const V4_DSCP: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V4: Fragment MATCH IS-FRAGMENT (0x02) ---
	{
		buf := flowspecV4([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_FRAGMENT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.BITMASK_FLAG_OP_MATCH|bgp.BITMASK_FLAG_OP_END, 0x02),
			}),
		})
		fmt.Printf("// IPv4 Flowspec: Fragment MATCH IS-FRAGMENT (0x02)\n")
		fmt.Printf("pub const V4_FRAGMENT: &[u8] = %s;\n\n", rustBytes(buf))
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

	// --- V6: SrcPrefix=2001:db8:1::/48, offset=0 ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecSourcePrefix6(ipPrefix("2001:db8:1::/48"), 0),
		})
		fmt.Printf("// IPv6 Flowspec: SrcPrefix=2001:db8:1::/48, offset=0\n")
		fmt.Printf("pub const V6_SRC_PREFIX: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: Port=8080 ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_PORT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 8080),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: Port=8080 (src+dst)\n")
		fmt.Printf("pub const V6_PORT: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: SrcPort=443 ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_SRC_PORT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 443),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: SrcPort=443\n")
		fmt.Printf("pub const V6_SRC_PORT: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: IcmpType=128 (echo request) + IcmpCode=0 ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_ICMP_TYPE, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 128),
			}),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_ICMP_CODE, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 0),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: IcmpType=128 (echo request), IcmpCode=0\n")
		fmt.Printf("pub const V6_ICMP_TYPE_CODE: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: TcpFlags MATCH SYN (0x02) ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_TCP_FLAG, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.BITMASK_FLAG_OP_MATCH|bgp.BITMASK_FLAG_OP_END, 0x02),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: TcpFlags MATCH SYN (0x02)\n")
		fmt.Printf("pub const V6_TCP_FLAGS: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: PacketLen <= 1500 ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_PKT_LEN, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_LT_EQ|bgp.DEC_NUM_OP_END, 1500),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: PacketLen <= 1500\n")
		fmt.Printf("pub const V6_PACKET_LEN: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: Dscp=46 (EF) ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_DSCP, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 46),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: Dscp=46 (EF)\n")
		fmt.Printf("pub const V6_DSCP: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- V6: Fragment MATCH IS-FRAGMENT (0x02) ---
	{
		buf := flowspecV6([]bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_FRAGMENT, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.BITMASK_FLAG_OP_MATCH|bgp.BITMASK_FLAG_OP_END, 0x02),
			}),
		})
		fmt.Printf("// IPv6 Flowspec: Fragment MATCH IS-FRAGMENT (0x02)\n")
		fmt.Printf("pub const V6_FRAGMENT: &[u8] = %s;\n\n", rustBytes(buf))
	}

	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)

	// --- VPNv4 Flowspec: DstPrefix + Protocol=TCP + RD=65000:100 ---
	{
		buf := flowspecVpnV4(rd, []bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecDestinationPrefix(ipPrefix("10.0.1.0/24")),
			bgp.NewFlowSpecComponent(bgp.FLOW_SPEC_TYPE_IP_PROTO, []*bgp.FlowSpecComponentItem{
				bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, 6),
			}),
		})
		fmt.Printf("// VPNv4 Flowspec: RD=65000:100, DstPrefix=10.0.1.0/24, Protocol=TCP(6)\n")
		fmt.Printf("pub const VPN_V4_DST_PREFIX_PROTO_TCP: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- VPNv6 Flowspec: DstPrefix + RD=65000:100 ---
	{
		buf := flowspecVpnV6(rd, []bgp.FlowSpecComponentInterface{
			bgp.NewFlowSpecDestinationPrefix6(ipPrefix("2001:db8::/32"), 0),
		})
		fmt.Printf("// VPNv6 Flowspec: RD=65000:100, DstPrefix=2001:db8::/32, offset=0\n")
		fmt.Printf("pub const VPN_V6_DST_PREFIX: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
