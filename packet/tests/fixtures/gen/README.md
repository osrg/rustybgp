# Test-vector generators

Go programs that produce wire-format byte sequences for BGP NLRI types,
using [GoBGP v4](https://github.com/osrg/gobgp) as an independent
reference implementation.  The output is pasted as constants into the
Rust unit tests in `packet/src/`, providing interoperability coverage
that internal roundtrip tests alone cannot give.

All generators share a single Go module (`go.mod`) so GoBGP is pinned
to one version across the board.

## Prerequisites

Go 1.22 or later.  Dependencies are downloaded automatically on first
run via the `go.sum` lockfile.

## Running a generator

```sh
cd packet/tests/fixtures/gen
go run ./vpn_nlri
```

The output is Rust source — copy the constants into the relevant test
module.

## Adding a new generator

1. Create a subdirectory (e.g. `flowspec_nlri/`).
2. Add `main.go` that imports `github.com/osrg/gobgp/v4/pkg/packet/bgp`
   and prints Rust byte-array literals.
3. Run `go mod tidy` from this directory.
4. Paste the output into the corresponding `packet/src/*.rs` test module.
