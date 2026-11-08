use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_core::MlKemKeyPair;
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    let kp = match MlKemKeyPair::new() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };
    let (dk_seed, ek) = kp.export_keys();
    let ek_b64 = general_purpose::STANDARD.encode(&ek);
    let dk_seed_b64 = general_purpose::STANDARD.encode(&dk_seed);

    if args.len() == 3 && args[1] == "--out" {
        let dir = &args[2];
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("error: cannot create output dir: {e}");
            process::exit(1);
        }
        if let Err(e) = fs::write(format!("{dir}/ek.b64"), &ek_b64) {
            eprintln!("error: cannot write ek.b64: {e}");
            process::exit(1);
        }
        if let Err(e) = fs::write(format!("{dir}/dk_seed.b64"), &dk_seed_b64) {
            eprintln!("error: cannot write dk_seed.b64: {e}");
            process::exit(1);
        }
        println!("wrote {dir}/ek.b64 and {dir}/dk_seed.b64");
        process::exit(0);
    }

    if args.len() != 1 {
        eprintln!("Usage: {} [--out <dir>]", args[0]);
        process::exit(1);
    }

    println!("EK={ek_b64}");
    println!("DK_SEED={dk_seed_b64}");
}
