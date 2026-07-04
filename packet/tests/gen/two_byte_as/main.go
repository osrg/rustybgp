// gen_two_byte_as generates AS_PATH (two-octet ASN), AS4_PATH, AGGREGATOR
// (two-octet ASN), and AS4_AGGREGATOR wire bytes using GoBGP's packet
// library, and prints them as Rust byte-array literals for use as RFC 6793
// interop test vectors in packet/src/bgp.rs.
//
// Usage:
//
//	go run .
//
// Regenerate whenever AS_PATH/AGGREGATOR/AS4_PATH/AS4_AGGREGATOR encoding is
// changed. Each constant holds only the attribute *value* bytes (the
// path-attribute header -- flags, type, length -- is stripped), matching how
// RustyBGP stores attributes as raw value bytes.
package main

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const asTrans = uint16(bgp.AS_TRANS)

func rustBytes(buf []byte) string {
	parts := make([]string, len(buf))
	for i, b := range buf {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return "&[" + strings.Join(parts, ", ") + "]"
}

// stripAttrHeader removes the path-attribute header (flags, type, and a
// 1- or 2-byte length) so only the value bytes remain.
func stripAttrHeader(buf []byte) []byte {
	if buf[0]&0x10 != 0 {
		return buf[4:]
	}
	return buf[3:]
}

func asPathValue(params ...bgp.AsPathParamInterface) []byte {
	attr := bgp.NewPathAttributeAsPath(params)
	buf, err := attr.Serialize()
	if err != nil {
		panic(err)
	}
	return stripAttrHeader(buf)
}

func as4PathValue(params ...*bgp.As4PathParam) []byte {
	attr := bgp.NewPathAttributeAs4Path(params)
	buf, err := attr.Serialize()
	if err != nil {
		panic(err)
	}
	return stripAttrHeader(buf)
}

func aggregatorValue(as any, addr string) []byte {
	attr, err := bgp.NewPathAttributeAggregator(as, netip.MustParseAddr(addr))
	if err != nil {
		panic(err)
	}
	buf, err := attr.Serialize()
	if err != nil {
		panic(err)
	}
	return stripAttrHeader(buf)
}

func as4AggregatorValue(as uint32, addr string) []byte {
	attr, err := bgp.NewPathAttributeAs4Aggregator(as, netip.MustParseAddr(addr))
	if err != nil {
		panic(err)
	}
	buf, err := attr.Serialize()
	if err != nil {
		panic(err)
	}
	return stripAttrHeader(buf)
}

func printConst(name, comment string, buf []byte) {
	fmt.Printf("// %s\n", comment)
	fmt.Printf("const %s: &[u8] = %s;\n\n", name, rustBytes(buf))
}

func main() {
	// -----------------------------------------------------------------------
	// Scenario 1: AS_PATH hop count (5) > AS4_PATH hop count (3); leading 2
	// hops of AS_PATH are taken and prepended to AS4_PATH (RFC 6793 SS4.2.3).
	// as-path (2-octet): 65000, 4000, AS_TRANS, AS_TRANS, 40001
	// as4-path:          400000, 300000, 40001
	// expected merged:   65000, 4000, 400000, 300000, 40001
	// -----------------------------------------------------------------------
	{
		buf := asPathValue(bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ,
			[]uint16{65000, 4000, asTrans, asTrans, 40001}))
		printConst("GOBGP_AS2_65000_4000_TRANS_TRANS_40001",
			"AS_PATH (2-octet) SEQ: 65000, 4000, AS_TRANS, AS_TRANS, 40001", buf)
	}
	{
		buf := as4PathValue(bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ,
			[]uint32{400000, 300000, 40001}))
		printConst("GOBGP_AS4_400000_300000_40001",
			"AS4_PATH SEQ: 400000, 300000, 40001", buf)
	}

	// -----------------------------------------------------------------------
	// Scenario 2: equal hop counts (2 == 2); AS4_PATH replaces AS_PATH as-is.
	// as-path (2-octet): 65000, AS_TRANS
	// as4-path:          65000, 400000
	// -----------------------------------------------------------------------
	{
		buf := asPathValue(bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ,
			[]uint16{65000, asTrans}))
		printConst("GOBGP_AS2_65000_TRANS",
			"AS_PATH (2-octet) SEQ: 65000, AS_TRANS", buf)
	}
	{
		buf := as4PathValue(bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ,
			[]uint32{65000, 400000}))
		printConst("GOBGP_AS4_65000_400000",
			"AS4_PATH SEQ: 65000, 400000", buf)
	}

	// -----------------------------------------------------------------------
	// Scenario 3: AS_PATH hop count (2) < AS4_PATH hop count (3); AS4_PATH is
	// ignored and AS_PATH is kept as received (AS_TRANS left unresolved).
	// as-path (2-octet): 65000, AS_TRANS   (reuses GOBGP_AS2_65000_TRANS)
	// as4-path:          65000, 400000, 300000
	// -----------------------------------------------------------------------
	{
		buf := as4PathValue(bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ,
			[]uint32{65000, 400000, 300000}))
		printConst("GOBGP_AS4_65000_400000_300000",
			"AS4_PATH SEQ: 65000, 400000, 300000", buf)
	}

	// -----------------------------------------------------------------------
	// Scenario 4: leading AS_SET counts as a single hop.
	// as-path (2-octet): SET{65010, 65020}, SEQ[AS_TRANS]   (2 hops)
	// as4-path:          SEQ[500000]                        (1 hop)
	// expected merged:   SET{65010, 65020}, SEQ[500000]
	// -----------------------------------------------------------------------
	{
		buf := asPathValue(
			bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65010, 65020}),
			bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{asTrans}),
		)
		printConst("GOBGP_AS2_SET_65010_65020_SEQ_TRANS",
			"AS_PATH (2-octet): SET{65010, 65020}, SEQ[AS_TRANS]", buf)
	}
	{
		buf := as4PathValue(bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{500000}))
		printConst("GOBGP_AS4_500000",
			"AS4_PATH SEQ: 500000", buf)
	}

	// -----------------------------------------------------------------------
	// Scenario 5: AS_CONFED_SEQUENCE is carried through in full while
	// accumulating hops; it never consumes the hop budget (RFC 5065).
	// as-path (2-octet): CONFED_SEQ[65001], SEQ[65000, AS_TRANS]  (0+2 hops)
	// as4-path:          SEQ[600000]                              (1 hop)
	// expected merged:   CONFED_SEQ[65001], SEQ[65000], SEQ[600000]
	// -----------------------------------------------------------------------
	{
		buf := asPathValue(
			bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65001}),
			bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65000, asTrans}),
		)
		printConst("GOBGP_AS2_CONFEDSEQ_65001_SEQ_65000_TRANS",
			"AS_PATH (2-octet): CONFED_SEQ[65001], SEQ[65000, AS_TRANS]", buf)
	}
	{
		buf := as4PathValue(bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{600000}))
		printConst("GOBGP_AS4_600000",
			"AS4_PATH SEQ: 600000", buf)
	}

	// -----------------------------------------------------------------------
	// AGGREGATOR / AS4_AGGREGATOR scenarios (RFC 6793 SS4.2.3).
	// -----------------------------------------------------------------------
	{
		buf := aggregatorValue(asTrans, "198.51.100.1")
		printConst("GOBGP_AGGREGATOR_TRANS_198_51_100_1",
			"AGGREGATOR (2-octet): AS_TRANS, 198.51.100.1", buf)
	}
	{
		// A genuine (non-AS_TRANS) two-octet aggregating AS: the aggregation
		// happened at an OLD router, so AS4_AGGREGATOR/AS4_PATH must be ignored.
		buf := aggregatorValue(uint16(65055), "198.51.100.1")
		printConst("GOBGP_AGGREGATOR_65055_198_51_100_1",
			"AGGREGATOR (2-octet): 65055, 198.51.100.1", buf)
	}
	{
		buf := as4AggregatorValue(400000, "198.51.100.1")
		printConst("GOBGP_AS4_AGGREGATOR_400000_198_51_100_1",
			"AS4_AGGREGATOR: 400000, 198.51.100.1", buf)
	}

	// -----------------------------------------------------------------------
	// Encode-direction cross-check: a wide (>65535) four-octet AS_PATH, used
	// to verify RustyBGP's own two-octet downgrade + AS4_PATH generation.
	// -----------------------------------------------------------------------
	{
		buf := as4PathValue(bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ,
			[]uint32{65000, 4000, 400000, 300000, 40001}))
		printConst("GOBGP_AS4_65000_4000_400000_300000_40001",
			"four-octet AS_PATH SEQ: 65000, 4000, 400000, 300000, 40001 (as AS4_PATH-shaped value bytes)", buf)
	}
}
