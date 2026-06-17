// sr-verify: verify that an IPv4 SR Policy route is (or is not) present in a GoBGP RIB.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	host          := flag.String("host", "localhost:50051", "GoBGP gRPC endpoint")
	distinguisher := flag.Uint("distinguisher", 0, "SR Policy distinguisher")
	color         := flag.Uint("color", 0, "SR Policy color")
	endpoint      := flag.String("endpoint", "", "IPv4 endpoint address (required)")
	preference    := flag.Uint("preference", 0, "expected preference value (0 = skip check)")
	bsid          := flag.Uint("bsid", 0, "expected MPLS binding SID label (0 = skip check)")
	absent        := flag.Bool("absent", false, "assert route is NOT present")
	flag.Parse()

	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "error: -endpoint is required")
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

	stream, err := client.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_SR_POLICY,
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
			srp, ok := path.Nlri.Nlri.(*api.NLRI_SrPolicy)
			if !ok {
				continue
			}
			nlri := srp.SrPolicy
			if nlri.Distinguisher != uint32(*distinguisher) ||
				nlri.Color != uint32(*color) ||
				!net.IP(nlri.Endpoint).Equal(epIP) {
				continue
			}
			if *preference > 0 || *bsid > 0 {
				if !matchAttrs(path.Pattrs, uint32(*preference), uint32(*bsid)) {
					continue
				}
			}
			found = true
		}
		if found {
			break
		}
	}

	desc := fmt.Sprintf("d=%d c=%d ep=%s", *distinguisher, *color, *endpoint)

	if *absent {
		if found {
			fmt.Fprintf(os.Stderr, "FAIL: route %s unexpectedly present in %s\n", desc, *host)
			os.Exit(1)
		}
		fmt.Printf("OK: route %s absent in %s\n", desc, *host)
	} else {
		if !found {
			fmt.Fprintf(os.Stderr, "FAIL: route %s not found in %s\n", desc, *host)
			os.Exit(1)
		}
		fmt.Printf("OK: route %s found in %s\n", desc, *host)
	}
}

func matchAttrs(pattrs []*api.Attribute, wantPref, wantBsid uint32) bool {
	for _, attr := range pattrs {
		te, ok := attr.Attr.(*api.Attribute_TunnelEncap)
		if !ok {
			continue
		}
		for _, tlv := range te.TunnelEncap.GetTlvs() {
			if tlv.Type != 15 {
				continue
			}
			var gotPref, gotBsidLabel uint32
			for _, sub := range tlv.Tlvs {
				switch v := sub.Tlv.(type) {
				case *api.TunnelEncapTLV_TLV_SrPreference:
					gotPref = v.SrPreference.Preference
				case *api.TunnelEncapTLV_TLV_SrBindingSid:
					if sr, ok := v.SrBindingSid.Bsid.(*api.TunnelEncapSubTLVSRBindingSID_SrBindingSid); ok {
						sid := sr.SrBindingSid.Sid
						if len(sid) >= 4 {
							gotBsidLabel = binary.BigEndian.Uint32(sid[:4]) >> 12
						}
					}
				}
			}
			prefOK := wantPref == 0 || gotPref == wantPref
			bsidOK := wantBsid == 0 || gotBsidLabel == wantBsid
			if prefOK && bsidOK {
				return true
			}
		}
	}
	return false
}
