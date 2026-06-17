// ls-inject: inject or withdraw a BGP-LS NLRI via GoBGP gRPC API.
//
// Supports three NLRI types (selected by -type):
//
//	node   - LsNodeNLRI   (local-router-id required)
//	link   - LsLinkNLRI   (local-router-id, remote-router-id, iface-addr, neighbor-addr required)
//	prefix - LsPrefixV4NLRI (local-router-id, prefix required)
//
// A BGP-LS attribute (type 29) is always attached. For node NLRIs the
// attribute carries the node name set via -node-name so the verify tool
// can confirm the attribute was forwarded end-to-end.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	host            := flag.String("host", "localhost:50051", "GoBGP gRPC endpoint")
	del             := flag.Bool("delete", false, "delete path instead of adding")
	nlriType        := flag.String("type", "node", "NLRI type: node, link, or prefix")
	nexthop         := flag.String("nexthop", "", "BGP next-hop IPv4 address (required)")
	asn             := flag.Uint("asn", 65002, "AS number for node descriptors")
	localRouterID   := flag.String("local-router-id", "", "local node IGP router ID (IPv4, required)")
	remoteRouterID  := flag.String("remote-router-id", "", "remote node IGP router ID (IPv4, required for link)")
	ifaceAddr       := flag.String("iface-addr", "", "link interface IPv4 address (required for link)")
	neighborAddr    := flag.String("neighbor-addr", "", "link neighbor IPv4 address (required for link)")
	prefix          := flag.String("prefix", "", "IPv4 prefix in CIDR notation (required for prefix)")
	nodeName        := flag.String("node-name", "", "node name in BGP-LS node attribute")
	flag.Parse()

	if *nexthop == "" {
		fmt.Fprintln(os.Stderr, "error: -nexthop is required")
		os.Exit(1)
	}
	if *localRouterID == "" {
		fmt.Fprintln(os.Stderr, "error: -local-router-id is required")
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

	localNode := &api.LsNodeDescriptor{
		Asn:         uint32(*asn),
		BgpLsId:     1,
		IgpRouterId: *localRouterID,
	}

	var lsNlri *api.LsAddrPrefix
	var lsAttr *api.LsAttribute

	switch *nlriType {
	case "node":
		lsNlri = &api.LsAddrPrefix{
			Type:       api.LsNLRIType_LS_NLRI_TYPE_NODE,
			ProtocolId: api.LsProtocolID_LS_PROTOCOL_ID_OSPF_V2,
			Identifier: 0,
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Node{
					Node: &api.LsNodeNLRI{LocalNode: localNode},
				},
			},
		}
		lsAttr = &api.LsAttribute{
			Node: &api.LsAttributeNode{Name: *nodeName},
		}

	case "link":
		if *remoteRouterID == "" || *ifaceAddr == "" || *neighborAddr == "" {
			fmt.Fprintln(os.Stderr, "error: link type requires -remote-router-id, -iface-addr, -neighbor-addr")
			os.Exit(1)
		}
		remoteNode := &api.LsNodeDescriptor{
			Asn:         uint32(*asn),
			BgpLsId:     1,
			IgpRouterId: *remoteRouterID,
		}
		lsNlri = &api.LsAddrPrefix{
			Type:       api.LsNLRIType_LS_NLRI_TYPE_LINK,
			ProtocolId: api.LsProtocolID_LS_PROTOCOL_ID_OSPF_V2,
			Identifier: 0,
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_Link{
					Link: &api.LsLinkNLRI{
						LocalNode:  localNode,
						RemoteNode: remoteNode,
						LinkDescriptor: &api.LsLinkDescriptor{
							InterfaceAddrIpv4: *ifaceAddr,
							NeighborAddrIpv4:  *neighborAddr,
						},
					},
				},
			},
		}
		lsAttr = &api.LsAttribute{
			Link: &api.LsAttributeLink{
				LocalRouterId:  *localRouterID,
				RemoteRouterId: *remoteRouterID,
			},
		}

	case "prefix":
		if *prefix == "" {
			fmt.Fprintln(os.Stderr, "error: prefix type requires -prefix")
			os.Exit(1)
		}
		lsNlri = &api.LsAddrPrefix{
			Type:       api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V4,
			ProtocolId: api.LsProtocolID_LS_PROTOCOL_ID_OSPF_V2,
			Identifier: 0,
			Nlri: &api.LsAddrPrefix_LsNLRI{
				Nlri: &api.LsAddrPrefix_LsNLRI_PrefixV4{
					PrefixV4: &api.LsPrefixV4NLRI{
						LocalNode: localNode,
						PrefixDescriptor: &api.LsPrefixDescriptor{
							IpReachability: []string{*prefix},
							OspfRouteType:  api.LsOspfRouteType_LS_OSPF_ROUTE_TYPE_INTRA_AREA,
						},
					},
				},
			},
		}
		lsAttr = &api.LsAttribute{
			Prefix: &api.LsAttributePrefix{},
		}

	default:
		fmt.Fprintf(os.Stderr, "error: unknown -type %q (want node, link, or prefix)\n", *nlriType)
		os.Exit(1)
	}

	path := &api.Path{
		Nlri: &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: lsNlri}},
		Pattrs: []*api.Attribute{
			{Attr: &api.Attribute_Origin{
				Origin: &api.OriginAttribute{Origin: 0},
			}},
			{Attr: &api.Attribute_NextHop{
				NextHop: &api.NextHopAttribute{NextHop: *nexthop},
			}},
			{Attr: &api.Attribute_Ls{Ls: lsAttr}},
		},
		Family: &api.Family{
			Afi:  api.Family_AFI_LS,
			Safi: api.Family_SAFI_LS,
		},
	}

	if *del {
		_, err = client.DeletePath(ctx, &api.DeletePathRequest{Path: path})
		if err != nil {
			fmt.Fprintf(os.Stderr, "DeletePath: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("deleted BGP-LS %s NLRI (local=%s)\n", *nlriType, *localRouterID)
	} else {
		_, err = client.AddPath(ctx, &api.AddPathRequest{Path: path})
		if err != nil {
			fmt.Fprintf(os.Stderr, "AddPath: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("injected BGP-LS %s NLRI (local=%s)\n", *nlriType, *localRouterID)
	}
}
