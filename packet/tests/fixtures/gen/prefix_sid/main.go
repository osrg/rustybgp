// gen_prefix_sid generates Prefix SID attribute wire bytes using GoBGP's
// packet library, and prints them as Rust byte-array literals for use as
// test vectors.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to Prefix SID encoding.
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

func prefixSidAttr(tlvs ...bgp.PrefixSIDTLVInterface) []byte {
	attr := bgp.NewPathAttributePrefixSID(tlvs...)
	buf, err := attr.Serialize()
	if err != nil {
		panic(err)
	}
	// Strip the path-attribute header (flags=1, type=1, length=1 or 2 bytes)
	// so the test vector covers only the TLV payload, matching how RustyBGP
	// stores PrefixSid as the raw attribute value bytes.
	flags := buf[0]
	if flags&0x10 != 0 {
		return buf[4:] // extended-length: 4-byte header
	}
	return buf[3:] // normal: 3-byte header
}

func main() {
	sid := netip.MustParseAddr("2001:0:5:3::")
	structure := bgp.NewSRv6SIDStructureSubSubTLV(40, 24, 16, 0, 16, 64)

	// --- SRv6 L3 Service (type 5): SID 2001:0:5:3::, End.DT4 (19), structure 40/24/16/0/16/64 ---
	{
		buf := prefixSidAttr(
			bgp.NewSRv6ServiceTLV(
				bgp.TLVTypeSRv6L3Service,
				bgp.NewSRv6InformationSubTLV(sid, bgp.END_DT4, structure),
			),
		)
		fmt.Printf("// SRv6 L3 Service TLV: SID 2001:0:5:3::, End.DT4 (19), structure 40/24/16/0/16/64\n")
		fmt.Printf("pub const SRV6_L3_SERVICE: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- SRv6 L2 Service (type 6): SID 2001:0:5:3::, End.DT2U (23), structure 40/24/16/0/16/64 ---
	{
		buf := prefixSidAttr(
			bgp.NewSRv6ServiceTLV(
				bgp.TLVTypeSRv6L2Service,
				bgp.NewSRv6InformationSubTLV(sid, bgp.END_DT2U, structure),
			),
		)
		fmt.Printf("// SRv6 L2 Service TLV: SID 2001:0:5:3::, End.DT2U (23), structure 40/24/16/0/16/64\n")
		fmt.Printf("pub const SRV6_L2_SERVICE: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
