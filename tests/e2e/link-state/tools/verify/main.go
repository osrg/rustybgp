// ls-verify: verify that a BGP-LS NLRI is (or is not) present in a GoBGP RIB.
//
// Supported -type values: node, link, prefix
//
// For node NLRIs, -node-name checks that the BGP-LS attribute (type 29)
// was forwarded with the correct node name, verifying end-to-end attribute
// propagation through rustybgp.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	host           := flag.String("host", "localhost:50051", "GoBGP gRPC endpoint")
	nlriType       := flag.String("type", "node", "NLRI type: node, link, or prefix")
	localRouterID  := flag.String("local-router-id", "", "local node IGP router ID to match (required)")
	remoteRouterID := flag.String("remote-router-id", "", "remote node IGP router ID to match (required for link)")
	prefix         := flag.String("prefix", "", "IPv4 prefix to match (required for prefix)")
	nodeName       := flag.String("node-name", "", "expected node name in BGP-LS attribute (node type, empty = skip check)")
	absent         := flag.Bool("absent", false, "assert NLRI is NOT present")
	flag.Parse()

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

	stream, err := client.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_LS,
			Safi: api.Family_SAFI_LS,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListPath: %v\n", err)
		os.Exit(1)
	}

	found := false
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Recv: %v\n", err)
			os.Exit(1)
		}
		for _, path := range resp.Destination.Paths {
			if path.Nlri == nil {
				continue
			}
			lsPrefix, ok := path.Nlri.Nlri.(*api.NLRI_LsAddrPrefix)
			if !ok {
				continue
			}
			if !matchNLRI(lsPrefix.LsAddrPrefix, *nlriType, *localRouterID, *remoteRouterID, *prefix) {
				continue
			}
			if *nodeName != "" && !matchNodeName(path.Pattrs, *nodeName) {
				continue
			}
			found = true
		}
		if found {
			break
		}
	}

	desc := fmt.Sprintf("type=%s local=%s", *nlriType, *localRouterID)
	if *remoteRouterID != "" {
		desc += " remote=" + *remoteRouterID
	}
	if *prefix != "" {
		desc += " prefix=" + *prefix
	}
	if *nodeName != "" {
		desc += " node-name=" + *nodeName
	}

	if *absent {
		if found {
			fmt.Fprintf(os.Stderr, "FAIL: BGP-LS NLRI %s unexpectedly present in %s\n", desc, *host)
			os.Exit(1)
		}
		fmt.Printf("OK: BGP-LS NLRI %s absent in %s\n", desc, *host)
	} else {
		if !found {
			fmt.Fprintf(os.Stderr, "FAIL: BGP-LS NLRI %s not found in %s\n", desc, *host)
			os.Exit(1)
		}
		fmt.Printf("OK: BGP-LS NLRI %s found in %s\n", desc, *host)
	}
}

func matchNLRI(lp *api.LsAddrPrefix, nlriType, localID, remoteID, pfx string) bool {
	if lp == nil || lp.Nlri == nil {
		return false
	}
	switch nlriType {
	case "node":
		n := lp.Nlri.GetNode()
		return n != nil && n.LocalNode != nil && n.LocalNode.IgpRouterId == localID
	case "link":
		l := lp.Nlri.GetLink()
		return l != nil &&
			l.LocalNode != nil && l.LocalNode.IgpRouterId == localID &&
			l.RemoteNode != nil && l.RemoteNode.IgpRouterId == remoteID
	case "prefix":
		p := lp.Nlri.GetPrefixV4()
		if p == nil || p.LocalNode == nil || p.LocalNode.IgpRouterId != localID {
			return false
		}
		if p.PrefixDescriptor == nil {
			return false
		}
		for _, r := range p.PrefixDescriptor.IpReachability {
			if r == pfx {
				return true
			}
		}
		return false
	}
	return false
}

func matchNodeName(pattrs []*api.Attribute, wantName string) bool {
	for _, attr := range pattrs {
		ls, ok := attr.Attr.(*api.Attribute_Ls)
		if !ok {
			continue
		}
		if ls.Ls.GetNode().GetName() == wantName {
			return true
		}
	}
	return false
}
