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

1. Pick the version. A release that adds no new crate to the workspace is a patch
   bump (`0.4.0` to `0.4.1`). A release that adds a new crate is a minor bump
   (`0.4.x` to `0.5.0`).
2. Bump the version. `cargo set-version --workspace 0.4.1` (from `cargo-edit`)
   rewrites `[workspace.package]` and the `[workspace.dependencies]`
   requirements together; pass `--dry-run` first to see the edits.
3. Run `cargo check --workspace` so `Cargo.lock` picks up the new version, then
   open a pull request with both files and merge it.
4. Create a GitHub Release on `main` tagged `v0.4.1`. The tag must match the
   workspace version — the workflow refuses to publish otherwise.
5. Approve the `release` environment gate. All twelve crates publish together.

Versions on crates.io are permanent: yanking hides a release from resolution but
does not free the number. A crate dropped from the workspace keeps whatever it
already published and simply stops getting new versions.

### When a release stops partway

The workflow publishes only the crates whose version is not on crates.io yet.
If it fails partway — crates.io was unavailable, or a crate is missing its
trusted-publisher configuration (`403 The provided access token is not valid for
crate`) — fix the cause and re-run the failed job: it skips what was already
published and uploads the rest. A run that finds every crate already published
uploads nothing and succeeds.

### When the release adds a crate

A trusted-publishing token cannot create a crate, so the workflow cannot publish
one for the first time. It uploads the crates that come before the new one in
dependency order, then fails on it with `403 Trusted Publishing tokens do not
support creating new crates`, which leaves that crate and everything downstream
of it unpublished. Publishing the new crate ahead of the release does not avoid
this: it requires its siblings at the version being released, and they are not on
crates.io yet.

Finish that release once the workflow has failed:

1. From the release commit, `cargo publish -p <new crate>` with an API token
   carrying the `publish-new` scope.
2. Give the new crate the owners its siblings have; `cargo owner --list soldb-core`
   says who they are.
3. Add its trusted-publisher configuration on crates.io: this repository, the
   `release.yml` filename, and the `release` environment. Without it, the
   crate's next release stops on it again: `soldb-tui` missed this step in
   0.4.0, so 0.4.1 had to be finished by hand.
4. Re-run the failed job. It publishes the crates left over, and every later
   release publishes the new crate from CI like the rest.

`soldb-evm` was new in 0.3.0 and `soldb-tui` in 0.4.0, and both went this way.

## Reporting bugs

Open an issue at https://github.com/walnuthq/soldb/issues.

## Questions

Email: hi@walnut.dev
