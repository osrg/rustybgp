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

The end-to-end tests in `tests/e2e/` each spin up a Docker Compose topology, run assertions against live BGP sessions, and tear everything down on exit. See [tests/e2e/README.md](tests/e2e/README.md) for prerequisites and usage.

## Commits

- Add a `Signed-off-by` trailer to every commit. By doing so you certify that you wrote the patch and have the right to submit it under the project license.
- If you used an AI coding assistant, add an `Assisted-by` trailer identifying the tool. The `Signed-off-by` confirms that you have reviewed the generated code and take responsibility for its correctness — following the [Linux kernel coding assistants policy](https://docs.kernel.org/process/coding-assistants.html).
- Commit messages must be ASCII only. Explain *why* the change is made; the diff already shows what changed.

Example:

```
component: short description of the change

Explain the motivation here. Why is this change needed?
What problem does it solve?

Assisted-by: Claude Sonnet 4.6 <noreply@anthropic.com>
Signed-off-by: Your Name <your@email.com>
```
