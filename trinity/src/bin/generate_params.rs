use std::fs::File;
use std::io::Write;
use trinity::TrinityWasmSetup;

fn main() {
    println!("[1/5] Starting parameter generation...");

    // Choose mode: "Plain" or "Halo2"
    println!("[2/5] Creating new TrinityWasmSetup for 'Halo2' mode...");
    let setup = TrinityWasmSetup::new("Halo2");
    println!("[3/5] Setup created successfully.");

    let params = setup.to_sender_setup();
    println!("[4/5] Parameters serialized to bytes.");

    let path = "/Users/yanismeziane/trinity/trinity/halo2params.bin";
    let mut file = File::create(path).expect("Unable to create file");
    file.write_all(&params).expect("Unable to write data");
    println!("[5/5] Success! halo2params.bin written to {}", path);
}
