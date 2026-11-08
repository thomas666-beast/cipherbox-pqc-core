use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_core::MlKemKeyPair;
use cipherbox_pqc_core::file::FileDecryptor;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <dk_seed_b64> <input_file> <output_file>",
            args[0]
        );
        process::exit(1);
    }

    let seed_bytes = general_purpose::STANDARD
        .decode(&args[1])
        .unwrap_or_else(|e| fail(format!("invalid dk_seed b64: {e}")));

    let kp = MlKemKeyPair::from_seed(&seed_bytes).unwrap_or_else(|e| fail(e));

    let mut input = File::open(&args[2]).unwrap_or_else(|e| fail(format!("open input: {e}")));
    let mut output = File::create(&args[3]).unwrap_or_else(|e| fail(format!("create output: {e}")));

    let mut dec = FileDecryptor::new(kp.decapsulation_key());

    let mut buf = vec![0u8; 65536];
    let mut out_buf = Vec::with_capacity(buf.len());
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => fail(format!("read: {e}")),
        };
        out_buf.clear();
        dec.update(&buf[..n], &mut out_buf)
            .unwrap_or_else(|e| fail(e));
        if !out_buf.is_empty() {
            output
                .write_all(&out_buf)
                .unwrap_or_else(|e| fail(format!("write: {e}")));
        }
    }
    out_buf.clear();
    dec.finish(&mut out_buf).unwrap_or_else(|e| fail(e));
    output
        .write_all(&out_buf)
        .unwrap_or_else(|e| fail(format!("write: {e}")));
    process::exit(0);
}
