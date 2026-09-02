# Contributing to SolDB

## Setup

```bash
git clone https://github.com/walnuthq/soldb.git
cd soldb
cargo build --workspace --all-targets
```

See [README.md](./README.md#development) for the full development setup, including running the lit-based end-to-end tests.

## Submitting changes

1. Fork the repo and create a branch off `main`
2. Make your changes
3. Run `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings`
4. Run `cargo test --workspace --all-targets`
5. Open a pull request — describe what you changed and why

## Releasing

Every crate in the workspace shares one version, and publishing a GitHub Release
publishes all of them to crates.io via
[`.github/workflows/release.yml`](./.github/workflows/release.yml).

1. Bump the version. `cargo set-version --workspace 0.2.0` (from `cargo-edit`)
   rewrites `[workspace.package]` and the `[workspace.dependencies]`
   requirements together; pass `--dry-run` first to see the edits.
2. Run `cargo check --workspace` so `Cargo.lock` picks up the new version, then
   open a pull request with both files and merge it.
3. Create a GitHub Release on `main` tagged `v0.2.0`. The tag must match the
   workspace version — the workflow refuses to publish otherwise.
4. Approve the `release` environment gate. All eleven crates publish together.

Versions on crates.io are permanent: yanking hides a release from resolution but
does not free the number.

## Reporting bugs

Open an issue at https://github.com/walnuthq/soldb/issues.

## Questions

Email: hi@walnut.dev
