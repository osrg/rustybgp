// gen_mrt_table_dump generates MRT TABLE_DUMP_V2 wire bytes using GoBGP's packet
// library, and prints them as Rust byte-array literals for use as test vectors.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to TABLE_DUMP_V2 encoding.
package main

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/mrt"
)

func rustBytes(buf []byte) string {
	parts := make([]string, len(buf))
	for i, b := range buf {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return "&[\n        " + strings.Join(parts, ", ") + ",\n    ]"
}

const fixedUnix = int64(1_000_000_000)

var fixedTime = time.Unix(fixedUnix, 0)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	// --- PEER_INDEX_TABLE ---
	// collector=1.1.1.1, one peer: AS65001, BGP-ID=10.0.0.1, addr=10.0.0.1
	{
		peer := mrt.NewPeer(
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("10.0.0.1"),
			65001,
			true, // 4-octet AS
		)
		pit := mrt.NewPeerIndexTable(
			netip.MustParseAddr("1.1.1.1"),
			"",
			[]*mrt.Peer{peer},
		)
		msg := must(mrt.NewMRTMessage(fixedTime, mrt.TABLE_DUMPv2, mrt.PEER_INDEX_TABLE, pit))
		buf := must(msg.Serialize())
		fmt.Printf("// PEER_INDEX_TABLE: collector=1.1.1.1, peer=[AS65001 10.0.0.1]\n")
		fmt.Printf("const GOBGP_PEER_INDEX_TABLE: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- RIB_IPV4_UNICAST ---
	// seq=0, prefix=10.0.0.0/24, peer_index=0, originated=fixedTS
	// attrs: ORIGIN=IGP, AS_PATH=[65001], NEXT_HOP=192.168.1.1
	{
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
			}),
			must(bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))),
		}
		prefix := must(bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24")))
		entries := []*mrt.RibEntry{
			mrt.NewRibEntry(0, uint32(fixedUnix), 0, attrs, false),
		}
		rib := mrt.NewRib(0, bgp.RF_IPv4_UC, prefix, entries)
		msg := must(mrt.NewMRTMessage(fixedTime, mrt.TABLE_DUMPv2, mrt.RIB_IPV4_UNICAST, rib))
		buf := must(msg.Serialize())
		fmt.Printf("// RIB_IPV4_UNICAST: seq=0, 10.0.0.0/24, ORIGIN=IGP AS_PATH=[65001] NEXTHOP=192.168.1.1\n")
		fmt.Printf("const GOBGP_RIB_IPV4_UNICAST: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- RIB_IPV6_UNICAST ---
	// seq=1, prefix=2001:db8::/32, peer_index=0, originated=fixedTS
	// attrs: ORIGIN=IGP, AS_PATH=[65001], MP_REACH_NLRI(nexthop=2001:db8::1)
	// RibEntry.Serialize() uses MarshallingOption{MRT:true}, which strips AFI/SAFI
	// and NLRI from MP_REACH_NLRI (RFC 6396 §4.3.2).
	{
		ipv6Prefix := must(bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/32")))
		mpReach := must(bgp.NewPathAttributeMpReachNLRI(
			bgp.RF_IPv6_UC,
			[]bgp.PathNLRI{{NLRI: ipv6Prefix}},
			netip.MustParseAddr("2001:db8::1"),
		))
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
			}),
			mpReach,
		}
		prefix := must(bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/32")))
		entries := []*mrt.RibEntry{
			mrt.NewRibEntry(0, uint32(fixedUnix), 0, attrs, false),
		}
		rib := mrt.NewRib(1, bgp.RF_IPv6_UC, prefix, entries)
		msg := must(mrt.NewMRTMessage(fixedTime, mrt.TABLE_DUMPv2, mrt.RIB_IPV6_UNICAST, rib))
		buf := must(msg.Serialize())
		fmt.Printf("// RIB_IPV6_UNICAST: seq=1, 2001:db8::/32, ORIGIN=IGP AS_PATH=[65001] nexthop=2001:db8::1\n")
		fmt.Printf("const GOBGP_RIB_IPV6_UNICAST: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
