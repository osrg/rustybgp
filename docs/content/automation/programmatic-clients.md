# Programmatic clients

Any language with a gRPC implementation can control RustyBGP. Generate client
stubs from the protobuf files in
[`api/proto/`](https://github.com/osrg/rustybgp/tree/master/api/proto)
(`gobgp.proto` and the files it imports), or reuse GoBGP's published Go
package.

## Go

The GoBGP v4 module ships ready-made client stubs. The end-to-end tests use
`github.com/osrg/gobgp/v4` v4.7.0 to inject SR Policy and BGP-LS routes into
RustyBGP and verify them.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.NewClient("127.0.0.1:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := api.NewGoBgpServiceClient(conn)
	stream, err := client.ListPeer(context.Background(), &api.ListPeerRequest{})
	if err != nil {
		log.Fatal(err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		p := resp.GetPeer()
		fmt.Println(p.GetState().GetNeighborAddress(), p.GetState().GetSessionState())
	}
}
```

For complete, working examples see the tools used by the end-to-end tests:

| Tool | Location | What it does |
|---|---|---|
| `sr-inject` | `tests/e2e/sr-policy/tools/inject` | Builds an SR Policy NLRI with a Tunnel Encapsulation attribute and calls `AddPath` or `DeletePath`. |
| `sr-verify` | `tests/e2e/sr-policy/tools/verify` | Reads routes with `ListPath` and checks preference and binding SID. |
| `ls-inject` | `tests/e2e/link-state/tools/inject` | Injects BGP-LS node, link and prefix NLRI. |
| `bmp-receiver` | `tests/e2e/shared/bmp-receiver` | A minimal BMP collector used by the BMP tests. |

## Python

Generate stubs with `grpcio-tools`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install grpcio grpcio-tools
python -m grpc_tools.protoc -I api/proto \
  --python_out=. --grpc_python_out=. api/proto/*.proto
```

Then:

```python
import grpc
import gobgp_pb2
import gobgp_pb2_grpc

channel = grpc.insecure_channel("127.0.0.1:50051")
stub = gobgp_pb2_grpc.GoBgpServiceStub(channel)

bgp = stub.GetBgp(gobgp_pb2.GetBgpRequest())
print("AS", bgp.global_.asn, "router-id", bgp.global_.router_id)

for resp in stub.ListPeer(gobgp_pb2.ListPeerRequest()):
    print(resp.peer.state.neighbor_address, resp.peer.state.session_state)
```

!!! note

    `global` is a Python keyword, so the generated field is named `global_`.

## Rust

The workspace's `rustybgp-api` crate generates `tonic` bindings for the same
protobuf files with `tonic-prost-build`. To build an external Rust client,
generate client code from `api/proto/*.proto` with `tonic-prost-build` and
`build_client(true)`.

## Streaming RPCs

### Reading large tables

`ListPath` streams one response per destination. The server converts routes
lazily and respects gRPC flow control, so a client that reads slowly slows the
server down rather than growing its memory. Read the stream promptly, and
cancel the call if you only need the first part of the result.

`batch_size` on `ListPathRequest` is a cap on the **total** number of paths
returned. The stream ends once that many paths have been sent.

### Watching for changes

`WatchEvent` turns RustyBGP into an event source. A typical controller
subscribes to peer state and best-path changes:

```go
stream, err := client.WatchEvent(ctx, &api.WatchEventRequest{
	Peer: &api.WatchEventRequest_Peer{},
	Table: &api.WatchEventRequest_Table{
		Filters: []*api.WatchEventRequest_Table_Filter{
			{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST, Init: true},
		},
	},
})
```

With `Init: true` the stream starts with a snapshot of the current best paths,
then continues with live changes. Each event arrives in its own message;
`batch_size` is ignored. The stream ends when BGP is stopped.

### Bulk route injection

`AddPathStream` is client streaming and is the fastest way to load many routes.
Each request message is applied atomically: if any path in the message is
invalid, none of them is installed and the stream ends with an error. Set
`table_type` explicitly to `GLOBAL` or `VRF`.
