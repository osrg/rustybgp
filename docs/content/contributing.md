# Contributing

Contributions to RustyBGP are welcome: bug reports with a reproduction, fixes,
new features, tests and documentation. This page summarizes the workflow. The
authoritative rules are in
[`CONTRIBUTING.md`](https://github.com/osrg/rustybgp/blob/master/CONTRIBUTING.md)
at the root of the repository.

## Development environment

You need:

- A stable Rust toolchain (the workspace uses the 2024 edition).
- A protobuf compiler, used to generate the gRPC bindings. On Debian or Ubuntu
  install `protobuf-compiler` and `libprotobuf-dev`.
- Docker with Compose v2 for the end-to-end tests.
- Python 3 and [uv](https://docs.astral.sh/uv/) if you work on this
  documentation site.

## Workflow

Changes are submitted as pull requests against `master` of
[osrg/rustybgp](https://github.com/osrg/rustybgp):

1. Fork the repository on GitHub.
2. Create a topic branch from the latest `master`:

    ```bash
    git remote add upstream https://github.com/osrg/rustybgp.git
    git fetch upstream
    git switch -c fix-hold-timer-zero upstream/master
    ```

3. Commit your changes, push the branch to your fork, and open a pull request
   against `osrg/rustybgp` `master`.

Keep each pull request focused on one change; split unrelated fixes into
separate pull requests.

## Before opening a pull request

Every pull request must pass CI. GitHub Actions does not expose detailed build
logs, so run the same checks locally first:

```bash
cargo clippy --tests -- -D warnings
cargo test --all
cargo fmt -- --check
```

If your change affects protocol behavior, add or extend an end-to-end scenario
under `tests/e2e/`. See [CI and testing](automation/ci-and-testing.md) for how
the scenarios are structured and run.

## Commit messages

- Prefix the subject with the component, for example `packet:`, `table:`,
  `daemon:`, `fsm:` or `grpc:`.
- Explain *why* the change is made. The diff already shows what changed.
- Use ASCII only.
- Add a `Signed-off-by` trailer to every commit. By doing so you certify that
  you wrote the patch and have the right to submit it under the project
  license.

```text
table: compare MED in best-path selection

RFC 4271 9.1.2.2 (c) requires comparing MULTI_EXIT_DISC between
routes learned from the same neighboring AS. Without this step the
selection fell through to later tie-breakers.

Signed-off-by: Your Name <you@example.com>
```

## Using AI tools

AI tools are allowed, under rules modeled on the
[Linux kernel guidelines for tool-generated content](https://github.com/torvalds/linux/blob/master/Documentation/process/generated-content.rst):

- Disclose it with an `Assisted-by:` trailer naming the tool. Do not use
  `Co-Authored-By`; a tool is not an author.
- You are responsible for the result and must be able to explain every line
  of it in review.
- Reproduce a problem yourself before filing an issue about it.

Trivial help such as completion or formatting needs no disclosure.

## Working on the documentation

The site lives in `docs/`. Pages are Markdown files under `docs/content/`, and
the navigation is defined in `docs/zensical.toml`.

```bash
cd docs
uvx zensical serve
```

The preview runs at <http://localhost:8000> and reloads as you edit. Before
pushing, check that the site builds without warnings:

```bash
cd docs
uvx zensical build --strict
```

When you change protocol behavior, update the
[RFC support](reference/rfc-support.md) page in the same pull request so the
matrix stays accurate.
