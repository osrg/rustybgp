// gen_sr_policy_nlri generates SR Policy NLRI and Tunnel Encapsulation
// attribute wire bytes using GoBGP's packet library, and prints them as
// Rust byte-array literals for use as test vectors.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to SR Policy NLRI or TunnelEncap encoding.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
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

func srPolicyNlri(family bgp.Family, lengthBits uint32, distinguisher, color uint32, endpoint []byte) []byte {
	nlri, err := bgp.NewSRPolicy(family, lengthBits, distinguisher, color, endpoint)
	if err != nil {
		panic(err)
	}
	buf, err := nlri.Serialize()
	if err != nil {
		panic(err)
	}
	return buf
}

func tunnelEncapAttr(tlvs []*bgp.TunnelEncapTLV) []byte {
	attr := &bgp.PathAttributeTunnelEncap{
		Value: tlvs,
	}
	buf, err := attr.Serialize()
	if err != nil {
		panic(err)
	}
	// Strip the 3-byte path attribute header (flags, type, length) so the
	// test vector covers only the TLV payload, matching how RustyBGP stores
	// Attribute::TUNNEL_ENCAP as AttributeData::Bin (the raw value bytes).
	if len(buf) < 4 {
		panic("tunnel encap attr too short")
	}
	// 2-byte length if extended-length flag set (0x10), 1-byte otherwise.
	flags := buf[0]
	if flags&0x10 != 0 {
		return buf[4:]
	}
	return buf[3:]
}

func main() {
	// --- IPv4 SR Policy NLRI: distinguisher=1, color=100, endpoint=10.0.0.1 ---
	{
		buf := srPolicyNlri(bgp.RF_SR_POLICY_IPv4, bgp.SRPolicyIPv4NLRILen, 1, 100, net.ParseIP("10.0.0.1").To4())
		fmt.Printf("// IPv4 SR Policy NLRI: distinguisher=1, color=100, endpoint=10.0.0.1\n")
		fmt.Printf("pub const IPV4_NLRI_D1_C100_EP10: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- IPv4 SR Policy NLRI: distinguisher=0, color=200, endpoint=192.168.1.254 ---
	{
		buf := srPolicyNlri(bgp.RF_SR_POLICY_IPv4, bgp.SRPolicyIPv4NLRILen, 0, 200, net.ParseIP("192.168.1.254").To4())
		fmt.Printf("// IPv4 SR Policy NLRI: distinguisher=0, color=200, endpoint=192.168.1.254\n")
		fmt.Printf("pub const IPV4_NLRI_D0_C200_EP192: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- IPv6 SR Policy NLRI: distinguisher=2, color=300, endpoint=2001:db8::1 ---
	{
		buf := srPolicyNlri(bgp.RF_SR_POLICY_IPv6, bgp.SRPolicyIPv6NLRILen, 2, 300, net.ParseIP("2001:db8::1").To16())
		fmt.Printf("// IPv6 SR Policy NLRI: distinguisher=2, color=300, endpoint=2001:db8::1\n")
		fmt.Printf("pub const IPV6_NLRI_D2_C300_EP2001DB8: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- TunnelEncap: preference=100 only ---
	{
		tlv := bgp.NewTunnelEncapTLV(bgp.TUNNEL_TYPE_SR_POLICY, []bgp.TunnelEncapSubTLVInterface{
			bgp.NewTunnelEncapSubTLVSRPreference(0, 100),
		})
		buf := tunnelEncapAttr([]*bgp.TunnelEncapTLV{tlv})
		fmt.Printf("// TunnelEncap: type=15 (SR Policy), preference=100\n")
		fmt.Printf("pub const TUNNEL_ENCAP_PREF100: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- TunnelEncap: preference=200, MPLS binding SID=16001, segment list weight=1, TypeA label=16001 ---
	{
		bsidBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(bsidBytes, 16001)
		bsid, err := bgp.NewBSID(bsidBytes)
		if err != nil {
			panic(err)
		}
		tlv := bgp.NewTunnelEncapTLV(bgp.TUNNEL_TYPE_SR_POLICY, []bgp.TunnelEncapSubTLVInterface{
			bgp.NewTunnelEncapSubTLVSRPreference(0, 200),
			&bgp.TunnelEncapSubTLVSRBSID{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.ENCAP_SUBTLV_TYPE_SRBINDING_SID,
					Length: 6,
				},
				Flags: 0,
				BSID:  bsid,
			},
			&bgp.TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6,
				},
				Weight: &bgp.SegmentListWeight{
					TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
						Type:   bgp.SegmentListSubTLVWeight,
						Length: 6,
					},
					Flags:  0,
					Weight: 1,
				},
				Segments: []bgp.TunnelEncapSubTLVInterface{
					&bgp.SegmentTypeA{
						TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
							Type:   bgp.EncapSubTLVType(bgp.TypeA),
							Length: 6,
						},
						Flags: 0,
						Label: 16001 << 12,
					},
				},
			},
		})
		buf := tunnelEncapAttr([]*bgp.TunnelEncapTLV{tlv})
		fmt.Printf("// TunnelEncap: type=15, preference=200, MPLS BSID=16001, segment list weight=1, TypeA label=16001\n")
		fmt.Printf("pub const TUNNEL_ENCAP_PREF200_BSID_SEGLIST_TYPEA: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- TunnelEncap: ENLP type 1 + priority 100 ---
	{
		tlv := bgp.NewTunnelEncapTLV(bgp.TUNNEL_TYPE_SR_POLICY, []bgp.TunnelEncapSubTLVInterface{
			bgp.NewTunnelEncapSubTLVSRPreference(0, 10),
			bgp.NewTunnelEncapSubTLVSRENLP(0, bgp.ENLPType1),
			bgp.NewTunnelEncapSubTLVSRPriority(100),
		})
		buf := tunnelEncapAttr([]*bgp.TunnelEncapTLV{tlv})
		fmt.Printf("// TunnelEncap: type=15, preference=10, ENLP type 1, priority=100\n")
		fmt.Printf("pub const TUNNEL_ENCAP_ENLP_PRIORITY: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- TunnelEncap: SRv6 binding SID fd00::1 ---
	{
		bsidBytes := net.ParseIP("fd00::1").To16()
		bsid, err := bgp.NewBSID(bsidBytes)
		if err != nil {
			panic(err)
		}
		tlv := bgp.NewTunnelEncapTLV(bgp.TUNNEL_TYPE_SR_POLICY, []bgp.TunnelEncapSubTLVInterface{
			bgp.NewTunnelEncapSubTLVSRPreference(0, 200),
			&bgp.TunnelEncapSubTLVSRBSID{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.ENCAP_SUBTLV_TYPE_SRBINDING_SID,
					Length: 18,
				},
				Flags: 0,
				BSID:  bsid,
			},
		})
		buf := tunnelEncapAttr([]*bgp.TunnelEncapTLV{tlv})
		fmt.Printf("// TunnelEncap: type=15, preference=200, SRv6 binding SID fd00::1\n")
		fmt.Printf("pub const TUNNEL_ENCAP_SRV6_BSID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- TunnelEncap: TypeB segment with endpoint behavior structure ---
	{
		tlv := bgp.NewTunnelEncapTLV(bgp.TUNNEL_TYPE_SR_POLICY, []bgp.TunnelEncapSubTLVInterface{
			bgp.NewTunnelEncapSubTLVSRPreference(0, 100),
			&bgp.TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6,
				},
				Segments: []bgp.TunnelEncapSubTLVInterface{
					&bgp.SegmentTypeB{
						TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
							Type:   bgp.EncapSubTLVType(bgp.TypeB),
							Length: 26,
						},
						Flags: 0x40, // A-flag: endpoint behavior structure present
						SID:   net.ParseIP("2001:db8::1").To16(),
						SRv6EBS: &bgp.SRv6EndpointBehaviorStructure{
							Behavior: bgp.SRBehavior(1), // End
							BlockLen: 32,
							NodeLen:  16,
							FuncLen:  16,
							ArgLen:   0,
						},
					},
				},
			},
		})
		buf := tunnelEncapAttr([]*bgp.TunnelEncapTLV{tlv})
		fmt.Printf("// TunnelEncap: type=15, preference=100, TypeB SID=2001:db8::1 with EBS (End, 32/16/16/0)\n")
		fmt.Printf("pub const TUNNEL_ENCAP_TYPEB_EBS: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// --- TunnelEncap: preference=50, SRv6 segment TypeB (no EBS), candidate path name ---
	{
		tlv := bgp.NewTunnelEncapTLV(bgp.TUNNEL_TYPE_SR_POLICY, []bgp.TunnelEncapSubTLVInterface{
			bgp.NewTunnelEncapSubTLVSRPreference(0, 50),
			bgp.NewTunnelEncapSubTLVSRCandidatePathName("test-policy"),
			&bgp.TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6,
				},
				Weight: &bgp.SegmentListWeight{
					TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
						Type:   bgp.SegmentListSubTLVWeight,
						Length: 6,
					},
					Flags:  0,
					Weight: 1,
				},
				Segments: []bgp.TunnelEncapSubTLVInterface{
					&bgp.SegmentTypeB{
						TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
							Type:   bgp.EncapSubTLVType(bgp.TypeB),
							Length: 18,
						},
						Flags: 0,
						SID:   net.ParseIP("2001:db8::1").To16(),
					},
				},
			},
		})
		buf := tunnelEncapAttr([]*bgp.TunnelEncapTLV{tlv})
		fmt.Printf("// TunnelEncap: type=15, preference=50, candidate path name=\"test-policy\", TypeB SID=2001:db8::1\n")
		fmt.Printf("pub const TUNNEL_ENCAP_PREF50_CPNAME_TYPEB: &[u8] = %s;\n\n", rustBytes(buf))
	}
}
