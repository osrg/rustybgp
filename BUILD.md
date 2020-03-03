# Development Guide

## Building the development environment

You need a working Docker and [Rust with MUSL](https://doc.rust-lang.org/edition-guide/rust-2018/platform-and-target-support/musl-support-for-fully-static-binaries.html) environment to run the CI locally. If you work on macOS, [Homebrew's musl-cross package](https://github.com/FiloSottile/homebrew-musl-cross) should work.

## Running CI locally

Once you open a pull request for RustyBGP, [the CI](https://github.com/osrg/rustybgp/blob/master/.github/workflows/ci.yml) will be executed on Github Actions. It's better to run the CI locally in the following way before opening a pull request.

```bash
$ ./tests/integration/functional/local-ci.sh start
=== RUN   TestEbgp
rusty image name  rustybgp-ci
gobgp image name  tomo/gobgp
--- PASS: TestEbgp (17.73s)
PASS
ok  	github.com/osrg/rustybgp/tests/integration/functional/pkg	17.758s
=== RUN   TestIbgp
rusty image name  rustybgp-ci
gobgp image name  tomo/gobgp
--- PASS: TestIbgp (32.15s)
PASS
ok  	github.com/osrg/rustybgp/tests/integration/functional/pkg	32.179s
```
