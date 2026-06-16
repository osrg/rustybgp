// gen_bgp_ls generates BGP-LS NLRI and BGP-LS attribute TLV wire bytes using
// GoBGP's packet library, and prints them as Rust byte-array literals for use
// as test vectors.
//
// # Skipped TLVs (known RustyBGP vs GoBGP incompatibilities)
//
//   - SrCapabilities (1034): RustyBGP uses 1-byte sub-TLV header (type=1,
//     len=1), GoBGP uses 2-byte header (type=1161, len=2).
//   - SrLocalBlock (1036): same sub-TLV format mismatch.
//   - Srv6PeerNodeSid: RustyBGP uses type 1104 with 28-byte payload
//     (includes 16-byte SID); GoBGP uses type 1251 with 12-byte payload.
//   - SRv6 SID NLRI: RustyBGP embeds Multi-Topology-ID inside TLV 518
//     (mt_id(2)+reserved(2)+SID(16)); GoBGP uses separate TLV 263.
//
// # SID encoding note
//
// For Adj-SID and Peer-*-SID TLVs, this gen script uses 4-byte (index)
// encoding (V-flag=0, Length=8) to avoid a 3-byte label encoding discrepancy:
// GoBGP stores the label in the lower 3 bytes of a 4-byte big-endian integer
// whereas RustyBGP stores it in the upper 20 bits (shift-left-4) of 3 bytes.
//
// Usage:
//
//	go run .
//
// Regenerate after any change to BGP-LS encoding.
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

// tlvBytes serializes a BGP-LS attribute TLV to raw bytes (type+length+value).
func tlvBytes(tlv bgp.LsTLVInterface) []byte {
	buf, err := tlv.Serialize()
	if err != nil {
		panic(fmt.Sprintf("serialize failed: %v", err))
	}
	return buf
}

// nlriBytes serializes a BGP-LS NLRI to raw bytes (type+length+body).
func nlriBytes(nlriType bgp.LsNLRIType, nlri bgp.LsNLRIInterface) []byte {
	prefix := &bgp.LsAddrPrefix{
		Type: nlriType,
		NLRI: nlri,
	}
	buf, err := prefix.Serialize()
	if err != nil {
		panic(fmt.Sprintf("NLRI serialize failed: %v", err))
	}
	return buf
}

func localNode(asn uint32, igpRouterID string) bgp.LsTLVNodeDescriptor {
	return bgp.NewLsTLVNodeDescriptor(&bgp.LsNodeDescriptor{
		Asn:         asn,
		IGPRouterID: igpRouterID,
	}, bgp.LS_TLV_LOCAL_NODE_DESC)
}

func remoteNode(asn uint32, igpRouterID string) bgp.LsTLVNodeDescriptor {
	return bgp.NewLsTLVNodeDescriptor(&bgp.LsNodeDescriptor{
		Asn:         asn,
		IGPRouterID: igpRouterID,
	}, bgp.LS_TLV_REMOTE_NODE_DESC)
}

func main() {
	// -------------------------------------------------------------------------
	// NLRI types
	// -------------------------------------------------------------------------

	// Node NLRI: IS-IS L1, ASN=65001, IS-IS system ID "0102.0304.0506"
	{
		local := localNode(65001, "0102.0304.0506")
		nlri := &bgp.LsNodeNLRI{
			LsNLRI: bgp.LsNLRI{
				ProtocolID: bgp.LS_PROTOCOL_ISIS_L1,
				Identifier: 42,
			},
			LocalNodeDesc: &local,
		}
		buf := nlriBytes(bgp.LS_NLRI_TYPE_NODE, nlri)
		fmt.Printf("// Node NLRI: IS-IS L1, identifier=42, ASN=65001, IGP-Router-ID=0102.0304.0506\n")
		fmt.Printf("pub const NODE_NLRI: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Link NLRI: IS-IS L2, local ASN=65001 id="0102.0304.0506",
	//            remote ASN=65002 id="0102.0304.0507",
	//            link: IPv4 interface=10.0.1.1, IPv4 neighbor=10.0.1.2
	{
		local := localNode(65001, "0102.0304.0506")
		remote := remoteNode(65002, "0102.0304.0507")
		ifAddr, _ := netip.ParseAddr("10.0.1.1")
		nbAddr, _ := netip.ParseAddr("10.0.1.2")
		linkDesc := []bgp.LsTLVInterface{
			&bgp.LsTLVIPv4InterfaceAddr{
				LsTLV: bgp.LsTLV{Type: bgp.LS_TLV_IPV4_INTERFACE_ADDR, Length: 4},
				IP:    ifAddr,
			},
			&bgp.LsTLVIPv4NeighborAddr{
				LsTLV: bgp.LsTLV{Type: bgp.LS_TLV_IPV4_NEIGHBOR_ADDR, Length: 4},
				IP:    nbAddr,
			},
		}
		nlri := &bgp.LsLinkNLRI{
			LsNLRI: bgp.LsNLRI{
				ProtocolID: bgp.LS_PROTOCOL_ISIS_L2,
				Identifier: 0,
			},
			LocalNodeDesc:  &local,
			RemoteNodeDesc: &remote,
			LinkDesc:       linkDesc,
		}
		buf := nlriBytes(bgp.LS_NLRI_TYPE_LINK, nlri)
		fmt.Printf("// Link NLRI: IS-IS L2, local ASN=65001 0102.0304.0506, remote ASN=65002 0102.0304.0507,\n")
		fmt.Printf("//           link if=10.0.1.1 nb=10.0.1.2\n")
		fmt.Printf("pub const LINK_NLRI: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// PrefixV4 NLRI: OSPF v2, ASN=65001, OSPF router ID=10.0.0.1, prefix=192.168.1.0/24
	{
		local := bgp.NewLsTLVNodeDescriptor(&bgp.LsNodeDescriptor{
			Asn:         65001,
			IGPRouterID: "10.0.0.1", // OSPF 4-byte router ID
		}, bgp.LS_TLV_LOCAL_NODE_DESC)
		prefixDesc := []bgp.LsTLVInterface{
			&bgp.LsTLVIPReachability{
				LsTLV:        bgp.LsTLV{Type: bgp.LS_TLV_IP_REACH_INFO, Length: 4},
				PrefixLength: 24,
				Prefix:       []byte{192, 168, 1},
			},
		}
		nlri := &bgp.LsPrefixV4NLRI{
			LsNLRI: bgp.LsNLRI{
				ProtocolID: bgp.LS_PROTOCOL_OSPF_V2,
				Identifier: 0,
			},
			LocalNodeDesc: &local,
			PrefixDesc:    prefixDesc,
		}
		buf := nlriBytes(bgp.LS_NLRI_TYPE_PREFIX_IPV4, nlri)
		fmt.Printf("// PrefixV4 NLRI: OSPF v2, ASN=65001, OSPF router-ID=10.0.0.1, prefix=192.168.1.0/24\n")
		fmt.Printf("pub const PREFIX_V4_NLRI: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// PrefixV6 NLRI: IS-IS L2, ASN=65001, IS-IS router ID, prefix=2001:db8::/32
	{
		local := localNode(65001, "0102.0304.0506")
		prefixDesc := []bgp.LsTLVInterface{
			&bgp.LsTLVIPReachability{
				LsTLV:        bgp.LsTLV{Type: bgp.LS_TLV_IP_REACH_INFO, Length: 5},
				PrefixLength: 32,
				Prefix:       []byte{0x20, 0x01, 0x0d, 0xb8},
			},
		}
		nlri := &bgp.LsPrefixV6NLRI{
			LsNLRI: bgp.LsNLRI{
				ProtocolID: bgp.LS_PROTOCOL_ISIS_L2,
				Identifier: 0,
			},
			LocalNodeDesc: &local,
			PrefixDesc:    prefixDesc,
		}
		buf := nlriBytes(bgp.LS_NLRI_TYPE_PREFIX_IPV6, nlri)
		fmt.Printf("// PrefixV6 NLRI: IS-IS L2, ASN=65001, router-ID=0102.0304.0506, prefix=2001:db8::/32\n")
		fmt.Printf("pub const PREFIX_V6_NLRI: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// -------------------------------------------------------------------------
	// BGP-LS attribute TLVs (Node attributes)
	// -------------------------------------------------------------------------

	// NodeFlagBits: Overload+External+Router = 0xA0 | 0x08 = 0xA8
	{
		flags := &bgp.LsNodeFlags{Overload: true, External: true, Router: true}
		buf := tlvBytes(bgp.NewLsTLVNodeFlagbits(flags))
		fmt.Printf("// NodeFlagBits: Overload+External+Router\n")
		fmt.Printf("pub const TLV_NODE_FLAG_BITS: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// OpaqueNodeAttr: [0x01, 0x02, 0x03]
	{
		data := []byte{0x01, 0x02, 0x03}
		buf := tlvBytes(bgp.NewLsTLVOpaqueNodeAttr(&data))
		fmt.Printf("// OpaqueNodeAttr: [0x01, 0x02, 0x03]\n")
		fmt.Printf("pub const TLV_OPAQUE_NODE_ATTR: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// NodeName: "router1"
	{
		name := "router1"
		buf := tlvBytes(bgp.NewLsTLVNodeName(&name))
		fmt.Printf("// NodeName: \"router1\"\n")
		fmt.Printf("pub const TLV_NODE_NAME: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// IsisArea: [0x47, 0x00, 0x01]
	{
		area := []byte{0x47, 0x00, 0x01}
		buf := tlvBytes(bgp.NewLsTLVIsisArea(&area))
		fmt.Printf("// IsisArea: [0x47, 0x00, 0x01]\n")
		fmt.Printf("pub const TLV_ISIS_AREA: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Ipv4LocalRouterId: 10.0.0.1
	{
		addr := netip.MustParseAddr("10.0.0.1")
		buf := tlvBytes(bgp.NewLsTLVLocalIPv4RouterID(&addr))
		fmt.Printf("// Ipv4LocalRouterId: 10.0.0.1\n")
		fmt.Printf("pub const TLV_IPV4_LOCAL_ROUTER_ID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Ipv6LocalRouterId: 2001:db8::1
	// NewLsTLVLocalIPv6RouterID sets Length=0, so construct directly.
	{
		tlv := &bgp.LsTLVLocalIPv6RouterID{
			LsTLV: bgp.LsTLV{Type: bgp.LS_TLV_IPV6_LOCAL_ROUTER_ID, Length: 16},
			IP:    netip.MustParseAddr("2001:db8::1"),
		}
		buf := tlvBytes(tlv)
		fmt.Printf("// Ipv6LocalRouterId: 2001:db8::1\n")
		fmt.Printf("pub const TLV_IPV6_LOCAL_ROUTER_ID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Ipv4RemoteRouterId: 10.0.0.2
	{
		addr := netip.MustParseAddr("10.0.0.2")
		buf := tlvBytes(bgp.NewLsTLVRemoteIPv4RouterID(&addr))
		fmt.Printf("// Ipv4RemoteRouterId: 10.0.0.2\n")
		fmt.Printf("pub const TLV_IPV4_REMOTE_ROUTER_ID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Ipv6RemoteRouterId: 2001:db8::2
	// NewLsTLVRemoteIPv6RouterID sets Length=4, so construct directly.
	{
		tlv := &bgp.LsTLVRemoteIPv6RouterID{
			LsTLV: bgp.LsTLV{Type: bgp.LS_TLV_IPV6_REMOTE_ROUTER_ID, Length: 16},
			IP:    netip.MustParseAddr("2001:db8::2"),
		}
		buf := tlvBytes(tlv)
		fmt.Printf("// Ipv6RemoteRouterId: 2001:db8::2\n")
		fmt.Printf("pub const TLV_IPV6_REMOTE_ROUTER_ID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// SrAlgorithms: [0, 1] (SPF + Strict SPF)
	{
		algos := []byte{0, 1}
		buf := tlvBytes(bgp.NewLsTLVSrAlgorithm(&algos))
		fmt.Printf("// SrAlgorithms: [0, 1]\n")
		fmt.Printf("pub const TLV_SR_ALGORITHM: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// -------------------------------------------------------------------------
	// BGP-LS attribute TLVs (Link attributes)
	// -------------------------------------------------------------------------

	// AdminGroup: 0x000000FF
	{
		group := uint32(0xFF)
		buf := tlvBytes(bgp.NewLsTLVAdminGroup(&group))
		fmt.Printf("// AdminGroup: 0x000000FF\n")
		fmt.Printf("pub const TLV_ADMIN_GROUP: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// MaxLinkBandwidth: 1e9 bps (IEEE 754 float32)
	{
		bw := float32(1e9)
		buf := tlvBytes(bgp.NewLsTLVMaxLinkBw(&bw))
		fmt.Printf("// MaxLinkBandwidth: 1e9 bps\n")
		fmt.Printf("pub const TLV_MAX_LINK_BANDWIDTH: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// MaxReservableBandwidth: 1e9 bps
	{
		bw := float32(1e9)
		buf := tlvBytes(bgp.NewLsTLVMaxReservableLinkBw(&bw))
		fmt.Printf("// MaxReservableBandwidth: 1e9 bps\n")
		fmt.Printf("pub const TLV_MAX_RESERVABLE_BANDWIDTH: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// UnreservedBandwidth: 8x 1e9 bps
	{
		bw := [8]float32{1e9, 1e9, 1e9, 1e9, 1e9, 1e9, 1e9, 1e9}
		buf := tlvBytes(bgp.NewLsTLVUnreservedBw(&bw))
		fmt.Printf("// UnreservedBandwidth: 8x 1e9 bps\n")
		fmt.Printf("pub const TLV_UNRESERVED_BANDWIDTH: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// TeDefaultMetric: 100
	{
		metric := uint32(100)
		buf := tlvBytes(bgp.NewLsTLVTEDefaultMetric(&metric))
		fmt.Printf("// TeDefaultMetric: 100\n")
		fmt.Printf("pub const TLV_TE_DEFAULT_METRIC: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// IgpMetric: 100000 (3-byte IS-IS/OSPF metric that round-trips in 3-byte form)
	{
		metric := uint32(100000)
		buf := tlvBytes(bgp.NewLsTLVIGPMetric(&metric))
		fmt.Printf("// IgpMetric: 100000 (3-byte encoding)\n")
		fmt.Printf("pub const TLV_IGP_METRIC: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Srlg: [0x00001000, 0x00002000]
	{
		srlgs := []uint32{0x00001000, 0x00002000}
		buf := tlvBytes(bgp.NewLsTLVSrlg(&srlgs))
		fmt.Printf("// Srlg: [0x1000, 0x2000]\n")
		fmt.Printf("pub const TLV_SRLG: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// OpaqueLinkAttr: [0xAB, 0xCD]
	{
		data := []byte{0xAB, 0xCD}
		buf := tlvBytes(bgp.NewLsTLVOpaqueLinkAttr(&data))
		fmt.Printf("// OpaqueLinkAttr: [0xAB, 0xCD]\n")
		fmt.Printf("pub const TLV_OPAQUE_LINK_ATTR: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// LinkName: "eth0"
	{
		name := "eth0"
		buf := tlvBytes(bgp.NewLsTLVLinkName(&name))
		fmt.Printf("// LinkName: \"eth0\"\n")
		fmt.Printf("pub const TLV_LINK_NAME: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// AdjSid: 4-byte index (L-flag=1, V-flag=0), SID=100500
	// Note: NewLsTLVAdjacencySID hardcodes Length=7 (3-byte), so construct directly.
	{
		tlv := &bgp.LsTLVAdjacencySID{
			LsTLV: bgp.LsTLV{
				Type:   bgp.LS_TLV_ADJACENCY_SID,
				Length: 8, // 4-byte SID index
			},
			Flags:  0x40, // L-flag (Local SID), V-flag=0 (index)
			Weight: 0,
			SID:    100500,
		}
		buf := tlvBytes(tlv)
		fmt.Printf("// AdjSid: L-flag=1, V-flag=0 (4-byte index), SID=100500\n")
		fmt.Printf("pub const TLV_ADJ_SID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// PeerNodeSid: 4-byte index (V-flag=0), SID=100500
	{
		flags := bgp.LsAttributeBgpPeerSegmentSIDFlags{Value: false, Local: true}
		tlv := bgp.NewLsTLVPeerNodeSID(&bgp.LsBgpPeerSegmentSID{
			Flags:  flags,
			Weight: 0,
			SID:    100500,
		})
		buf := tlvBytes(tlv)
		fmt.Printf("// PeerNodeSid: L-flag=1, V-flag=0 (4-byte index), SID=100500\n")
		fmt.Printf("pub const TLV_PEER_NODE_SID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// PeerAdjSid: 4-byte index (V-flag=0), SID=100500
	// NewLsTLVPeerAdjacencySID uses wrong type LS_TLV_ADJACENCY_SID (1099),
	// so construct directly with the correct LS_TLV_PEER_ADJACENCY_SID (1102).
	{
		tlv := &bgp.LsTLVPeerAdjacencySID{
			LsTLV:  bgp.LsTLV{Type: bgp.LS_TLV_PEER_ADJACENCY_SID, Length: 8},
			Flags:  0x40, // L-flag=1, V-flag=0 (4-byte index)
			Weight: 0,
			SID:    100500,
		}
		buf := tlvBytes(tlv)
		fmt.Printf("// PeerAdjSid: L-flag=1, V-flag=0 (4-byte index), SID=100500\n")
		fmt.Printf("pub const TLV_PEER_ADJ_SID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// PeerSetSid: 4-byte index (V-flag=0), SID=100500
	{
		flags := bgp.LsAttributeBgpPeerSegmentSIDFlags{Value: false, Local: true}
		tlv := bgp.NewLsTLVPeerSetSID(&bgp.LsBgpPeerSegmentSID{
			Flags:  flags,
			Weight: 0,
			SID:    100500,
		})
		buf := tlvBytes(tlv)
		fmt.Printf("// PeerSetSid: L-flag=1, V-flag=0 (4-byte index), SID=100500\n")
		fmt.Printf("pub const TLV_PEER_SET_SID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// Srv6EndXSid: endpoint_behavior=57 (End.X), flags=0, alg=0, weight=100,
	//              SID=fd00::1, structure=32/16/16/0
	{
		sid := netip.MustParseAddr("fd00::1")
		tlv := bgp.NewLsTLVSrv6EndXSID(&bgp.LsSrv6EndXSID{
			EndpointBehavior: 57, // End.X
			Flags:            0,
			Algorithm:        0,
			Weight:           100,
			SIDs:             []netip.Addr{sid},
			Srv6SIDStructure: bgp.LsSrv6SIDStructure{
				LocalBlock: 32,
				LocalNode:  16,
				LocalFunc:  16,
				LocalArg:   0,
			},
		})
		buf := tlvBytes(tlv)
		fmt.Printf("// Srv6EndXSid: EP=57 (End.X), weight=100, SID=fd00::1, struct=32/16/16/0\n")
		fmt.Printf("pub const TLV_SRV6_END_X_SID: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// UnidirectionalLinkDelay: 1000 us, not anomalous
	{
		tlv := bgp.NewLsTLVUnidirectionalLinkDelay(&bgp.LsUnidirectionalLinkDelay{
			Flags: bgp.LsDelayMetricFlags{Anomalous: false},
			Delay: 1000,
		})
		buf := tlvBytes(tlv)
		fmt.Printf("// UnidirectionalLinkDelay: 1000 us, not anomalous\n")
		fmt.Printf("pub const TLV_UNIDIRECTIONAL_LINK_DELAY: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// MinMaxUnidirectionalLinkDelay: min=500us max=2000us, not anomalous
	{
		tlv := bgp.NewLsTLVMinMaxUnidirectionalLinkDelay(&bgp.LsMinMaxUnidirectionalLinkDelay{
			Flags:    bgp.LsDelayMetricFlags{Anomalous: false},
			MinDelay: 500,
			MaxDelay: 2000,
		})
		buf := tlvBytes(tlv)
		fmt.Printf("// MinMaxUnidirectionalLinkDelay: min=500us max=2000us, not anomalous\n")
		fmt.Printf("pub const TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// UnidirectionalDelayVariation: 100 us
	{
		variation := uint32(100)
		tlv := bgp.NewLsTLVUnidirectionalDelayVariation(&variation)
		buf := tlvBytes(tlv)
		fmt.Printf("// UnidirectionalDelayVariation: 100 us\n")
		fmt.Printf("pub const TLV_UNIDIRECTIONAL_DELAY_VARIATION: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// -------------------------------------------------------------------------
	// BGP-LS attribute TLVs (Prefix attributes)
	// -------------------------------------------------------------------------

	// IgpFlags: Down=true, NoUnicast=true
	{
		tlv := bgp.NewLsTLVIGPFlags(&bgp.LsIGPFlags{Down: true, NoUnicast: true})
		buf := tlvBytes(tlv)
		fmt.Printf("// IgpFlags: Down=true, NoUnicast=true\n")
		fmt.Printf("pub const TLV_IGP_FLAGS: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// OpaquePrefixAttr: [0xDE, 0xAD, 0xBE]
	// NewLsTLVOpaquePrefixAttr sets Length=0, so construct directly.
	{
		data := []byte{0xDE, 0xAD, 0xBE}
		tlv := &bgp.LsTLVOpaquePrefixAttr{
			LsTLV: bgp.LsTLV{
				Type:   bgp.LS_TLV_OPAQUE_PREFIX_ATTR,
				Length: uint16(len(data)),
			},
			Attr: data,
		}
		buf := tlvBytes(tlv)
		fmt.Printf("// OpaquePrefixAttr: [0xDE, 0xAD, 0xBE]\n")
		fmt.Printf("pub const TLV_OPAQUE_PREFIX_ATTR: &[u8] = %s;\n\n", rustBytes(buf))
	}

	// PrefixSid: 4-byte index (V-flag=0), algorithm=0, SID=100500
	// NewLsTLVPrefixSID sets Length=0, so construct directly.
	{
		tlv := &bgp.LsTLVPrefixSID{
			LsTLV: bgp.LsTLV{
				Type:   bgp.LS_TLV_PREFIX_SID,
				Length: 8, // 4-byte SID index
			},
			Flags:     0x00, // no V-flag → 4-byte index
			Algorithm: 0,
			SID:       100500,
		}
		buf := tlvBytes(tlv)
		fmt.Printf("// PrefixSid: V-flag=0 (4-byte index), algorithm=0, SID=100500\n")
		fmt.Printf("pub const TLV_PREFIX_SID: &[u8] = %s;\n\n", rustBytes(buf))
	}

}
