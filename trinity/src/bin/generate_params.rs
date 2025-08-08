use std::env;
use std::fs::File;
use std::io::Write;
use trinity::TrinityWasmSetup;

// cargo run --release --bin generate_params -- Halo2
fn main() {
    let args: Vec<String> = env::args().collect();

    // Check for the correct number of arguments and validate the mode.
    if args.len() != 2 || (args[1] != "Plain" && args[1] != "Halo2") {
        eprintln!("Usage: cargo run --release --bin generate_params -- <Plain|Halo2>");
        std::process::exit(1);
    }

    let mode = &args[1];
    println!("[1/5] Starting parameter generation for '{}' mode...", mode);

    println!("[2/5] Creating new TrinityWasmSetup for '{}' mode...", mode);
    let setup = TrinityWasmSetup::new(mode);
    println!("[3/5] Setup created successfully.");

    let params = setup.to_full_params_bytes();
    println!("[4/5] Parameters serialized to bytes.");

    // Determine the output filename based on the mode.
    let filename = if mode == "Halo2" {
        "halo2params.bin"
    } else {
        "plainparams.bin"
    };

    // Write the file to the current directory (workspace root).
    let path = format!("./{}", filename);
    let mut file = File::create(&path).expect("Unable to create file");
    file.write_all(&params).expect("Unable to write data");
    println!("[5/5] Success! {} written to {}", filename, path);
}
