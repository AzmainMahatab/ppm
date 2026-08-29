//! Win32 virtualization verification probe.
//!
//! Each module in `suites/` verifies one isolation boundary contract live, under
//! full redirector injection. Exit codes 1-5 identify the failing suite.

mod suites;
mod support;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--child") {
        println!("[CHILD] Running inside spawned child process!");
        // Verify child also has virtualized environment
        if let Err(e) = suites::shell::run() {
            eprintln!("[CHILD ERROR] {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if args.iter().any(|a| a == "--echo-args") {
        println!("[ARGS_ECHO] {:?}", &args[1..]);
        std::process::exit(0);
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("[PROBE_HELP] Custom test probe help output");
        std::process::exit(0);
    }

    println!("=== PPM Virtualization Test Probe ===");
    if let Err(e) = suites::registry::run() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(1);
    }
    if let Err(e) = suites::shell::run() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(2);
    }
    if let Err(e) = suites::credentials::run() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(3);
    }
    if let Err(e) = suites::injection::run() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(4);
    }
    if let Err(e) = suites::identity::run() {
        eprintln!("[FAIL] {}", e);
        std::process::exit(5);
    }

    println!("=== ALL 5 BOUNDARY SUITES PASSED SUCCESSFULLY! ===");
    std::process::exit(0);
}
