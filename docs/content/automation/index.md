# Automation

RustyBGP is built to be driven by software. Every operation an administrator
can perform, from adding a neighbor to injecting a FlowSpec rule, is exposed
through a gRPC API that is wire-compatible with the GoBGP v4 API. Existing
GoBGP tooling, including the `gobgp` command-line client and programs written
against the `github.com/osrg/gobgp/v4/api` package, works with `rustybgpd`
without modification.

<div class="grid cards" markdown>

-   :lucide-plug: **[gRPC API](grpc-api.md)**

    The `GoBgpService` interface, how to reach it, how to secure it, and the
    implementation status of all 55 RPCs.

-   :lucide-terminal: **[GoBGP CLI](gobgp-cli.md)**

    A cookbook of `gobgp` commands for day-to-day operation and scripting.

-   :lucide-code: **[Programmatic clients](programmatic-clients.md)**

    Writing Go and Python clients, streaming RPCs, and backpressure.

-   :lucide-workflow: **[CI and testing](ci-and-testing.md)**

    The GitHub Actions pipelines, release automation, and the Docker-based
    end-to-end test harness.

</div>

## Choosing an interface

| Use case | Recommended interface |
|---|---|
| Interactive troubleshooting | `gobgp` CLI |
| Shell scripts, cron jobs, Ansible `command` tasks | `gobgp` CLI with `-j` for JSON output |
| Controllers, route injectors, SDN applications | Native gRPC client (Go, Python, Rust, ...) |
| Continuous route or peer-state monitoring | `WatchEvent` streaming RPC, or [BMP](../user-guide/monitoring.md) |
| Static, version-controlled configuration | Configuration file with [SIGHUP reload](../administration/configuration-reload.md) |

The configuration file and the API are complementary. A common pattern is to
keep neighbors and policies in a version-controlled configuration file and use
the API for dynamic state such as injected routes, temporary peer shutdowns,
and soft resets.
