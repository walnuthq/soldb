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

## Reporting bugs

Open an issue at https://github.com/walnuthq/soldb/issues.

## Questions

Telegram: [@walnut_soldb](https://t.me/walnut_soldb) · Email: hi@walnut.dev
