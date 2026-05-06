use std::io::{stdin, stdout};

fn main() {
    if let Err(error) = soldb_dap::run_stdio_server(stdin().lock(), stdout().lock()) {
        eprintln!("soldb-dap-server: {error}");
        std::process::exit(1);
    }
}
