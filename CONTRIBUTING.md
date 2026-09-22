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
- If you used an AI tool, add an `Assisted-by` trailer identifying the tool. See [Using AI tools](#using-ai-tools).
- Commit messages must be ASCII only. Explain *why* the change is made; the diff already shows what changed.

Example:

```
component: short description of the change

Explain the motivation here. Why is this change needed?
What problem does it solve?

Assisted-by: Claude Sonnet 4.6 <noreply@anthropic.com>
Signed-off-by: Your Name <your@email.com>
```

## Using AI tools

You may use AI tools such as large language models. These rules follow the [Linux kernel guidelines for tool-generated content](https://github.com/torvalds/linux/blob/master/Documentation/process/generated-content.rst).

- Say that you used one. Add an `Assisted-by: Claude Opus 5 <noreply@anthropic.com>` trailer to the commit message. Do not use `Co-Authored-By`. A tool is not an author.
- You are responsible for the result. Your `Signed-off-by` means that you reviewed the change. You must understand the whole change and be able to explain it. If you cannot answer a review comment without going back to the tool, do not send the change. A pull request that its author cannot explain may be closed without a review.
- The same applies to an issue. Do not open one only because a tool read the code and said that it looks wrong. Reproduce the problem first, and send a fix if you can write one.

Trivial help, such as completion or formatting, needs no disclosure.
