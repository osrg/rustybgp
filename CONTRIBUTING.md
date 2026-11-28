# Contributing to RustyBGP

## Development environment

You need a Rust toolchain and a protobuf compiler (`protobuf-compiler` and `libprotobuf-dev` on Debian/Ubuntu). For end-to-end tests, Docker with Compose v2 is also required.

## Pull requests

All pull requests must pass CI. Before submitting, verify locally — GitHub Actions does not expose detailed build logs, so debugging failures there is difficult:

```bash
cargo clippy --tests -- -D warnings
cargo test --all
cargo fmt -- --check
```

Fix all warnings and errors that these commands report.

The end-to-end tests in `tests/e2e/` each spin up a Docker Compose topology, run assertions against live BGP sessions, and tear everything down on exit. See [tests/e2e/README.md](tests/e2e/README.md) for prerequisites and usage.

## gRPC API

The files in `api/proto/` are copies of GoBGP's gRPC API definition. Do not add, remove, or change any fields. Every API extension must fit the existing schema.

## Commits

- Add a `Signed-off-by` trailer to every commit. By doing so you certify that you wrote the patch and have the right to submit it under the project license.
- Commit messages must be ASCII only. Explain *why* the change is made; the diff already shows what changed.

Example:

```
component: short description of the change

Explain the motivation here. Why is this change needed?
What problem does it solve?

Signed-off-by: Your Name <your@email.com>
```

## Using AI tools

You may use AI tools such as large language models. An AI tool is a tool, not an author. You are responsible for the result.

- You must understand the whole change and be able to explain it. If you cannot answer a review comment without going back to the tool, do not send the change. A pull request that its author cannot explain may be closed without a review.
- The same applies to an issue. Do not open one only because a tool read the code and said that it looks wrong. Reproduce the problem first, and send a fix if you can write one.
- An AI tool must not add a `Signed-off-by` trailer. Only you can certify that you have the right to submit the change, after you have reviewed it.
