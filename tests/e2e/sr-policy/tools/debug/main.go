// debug: dump ListPath response for SR Policy RIB
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	host := "localhost:50051"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.Dial(host, grpc.WithTransportCredentials(insecure.NewCredentials())) //nolint:staticcheck
	if err != nil {
		fmt.Fprintf(os.Stderr, "grpc.Dial: %v\n", err)
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

	m := protojson.MarshalOptions{Multiline: true, Indent: "  "}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Recv: %v\n", err)
			os.Exit(1)
		}
		j, _ := m.Marshal(resp)
		fmt.Println(string(j))
	}
}
