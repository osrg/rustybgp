// sr-inject: inject or withdraw an IPv4 SR Policy route via GoBGP gRPC API.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	host         := flag.String("host", "localhost:50051", "GoBGP gRPC endpoint")
	del          := flag.Bool("delete", false, "delete path instead of adding")
	distinguisher := flag.Uint("distinguisher", 0, "SR Policy distinguisher")
	color        := flag.Uint("color", 0, "SR Policy color")
	endpoint     := flag.String("endpoint", "", "IPv4 endpoint address (required)")
	nexthop      := flag.String("nexthop", "", "BGP next-hop IPv4 address (required)")
	preference   := flag.Uint("preference", 100, "candidate path preference")
	bsid         := flag.Uint("bsid", 0, "MPLS binding SID label value (0 = omit)")
	segment      := flag.Uint("segment", 0, "TypeA segment MPLS label value (0 = omit)")
	flag.Parse()

	if *endpoint == "" || *nexthop == "" {
		fmt.Fprintln(os.Stderr, "error: -endpoint and -nexthop are required")
		os.Exit(1)
	}

	epIP := net.ParseIP(*endpoint).To4()
	if epIP == nil {
		fmt.Fprintln(os.Stderr, "error: -endpoint must be an IPv4 address")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.Dial(*host, grpc.WithTransportCredentials(insecure.NewCredentials())) //nolint:staticcheck
	if err != nil {
		fmt.Fprintf(os.Stderr, "grpc.Dial %s: %v\n", *host, err)
		os.Exit(1)
	}
	defer conn.Close()

	client := api.NewGoBgpServiceClient(conn)

	nlri := &api.NLRI{
		Nlri: &api.NLRI_SrPolicy{
			SrPolicy: &api.SRPolicyNLRI{
				Length:        96, // IPv4: distinguisher(32) + color(32) + endpoint(32) bits
				Distinguisher: uint32(*distinguisher),
				Color:         uint32(*color),
				Endpoint:      epIP,
			},
		},
	}

	// Preference sub-TLV is always included.
	subTlvs := []*api.TunnelEncapTLV_TLV{
		{
			Tlv: &api.TunnelEncapTLV_TLV_SrPreference{
				SrPreference: &api.TunnelEncapSubTLVSRPreference{
					Preference: uint32(*preference),
				},
			},
		},
	}

	if *bsid > 0 {
		// NewBSID(v) shifts the raw label left 12 internally; pass the raw label.
		sidBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sidBytes, uint32(*bsid))
		subTlvs = append(subTlvs, &api.TunnelEncapTLV_TLV{
			Tlv: &api.TunnelEncapTLV_TLV_SrBindingSid{
				SrBindingSid: &api.TunnelEncapSubTLVSRBindingSID{
					Bsid: &api.TunnelEncapSubTLVSRBindingSID_SrBindingSid{
						SrBindingSid: &api.SRBindingSID{Sid: sidBytes},
					},
				},
			},
		})
	}

	if *segment > 0 {
		// SegmentTypeA.Label is the full 4-byte MPLS stack entry (label<<12); GoBGP
		// serializes it verbatim to wire, so pre-shift so the receiver can decode label
		// via entry>>12.
		subTlvs = append(subTlvs, &api.TunnelEncapTLV_TLV{
			Tlv: &api.TunnelEncapTLV_TLV_SrSegmentList{
				SrSegmentList: &api.TunnelEncapSubTLVSRSegmentList{
					Weight: &api.SRWeight{Weight: 1},
					Segments: []*api.TunnelEncapSubTLVSRSegmentList_Segment{
						{
							Segment: &api.TunnelEncapSubTLVSRSegmentList_Segment_A{
								A: &api.SegmentTypeA{Label: uint32(*segment) << 12},
							},
						},
					},
				},
			},
		})
	}

	path := &api.Path{
		Nlri: nlri,
		Pattrs: []*api.Attribute{
			{Attr: &api.Attribute_Origin{
				Origin: &api.OriginAttribute{Origin: 0},
			}},
			{Attr: &api.Attribute_NextHop{
				NextHop: &api.NextHopAttribute{NextHop: *nexthop},
			}},
			{Attr: &api.Attribute_TunnelEncap{
				TunnelEncap: &api.TunnelEncapAttribute{
					Tlvs: []*api.TunnelEncapTLV{
						{Type: 15, Tlvs: subTlvs},
					},
				},
			}},
		},
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_SR_POLICY,
		},
	}

	if *del {
		_, err = client.DeletePath(ctx, &api.DeletePathRequest{Path: path})
		if err != nil {
			fmt.Fprintf(os.Stderr, "DeletePath: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("deleted SR Policy route: d=%d c=%d ep=%s\n",
			*distinguisher, *color, *endpoint)
	} else {
		_, err = client.AddPath(ctx, &api.AddPathRequest{Path: path})
		if err != nil {
			fmt.Fprintf(os.Stderr, "AddPath: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("injected SR Policy route: d=%d c=%d ep=%s pref=%d\n",
			*distinguisher, *color, *endpoint, *preference)
	}
}
