use base64::{Engine as _, engine::general_purpose};
use cipherbox_pqc_core::file::{CHUNK_SIZE_DEFAULT, FileEncryptor};
use cipherbox_pqc_core::kem;
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
    if !(4..=5).contains(&args.len()) {
        eprintln!(
            "Usage: {} <recipient_pk_b64> <input_file> <output_file> [chunk_size]",
            args[0]
        );
        process::exit(1);
    }

    let pk_bytes = general_purpose::STANDARD
        .decode(&args[1])
        .unwrap_or_else(|e| fail(format!("invalid pk b64: {e}")));
    if pk_bytes.len() != kem::EK_BYTES {
        fail(format!(
            "public key must be {} bytes, got {}",
            kem::EK_BYTES,
            pk_bytes.len()
        ));
    }
    let mut ek = [0u8; kem::EK_BYTES];
    ek.copy_from_slice(&pk_bytes);

    let chunk_size = if args.len() == 5 {
        args[4]
            .parse::<usize>()
            .unwrap_or_else(|e| fail(format!("invalid chunk_size: {e}")))
    } else {
        CHUNK_SIZE_DEFAULT
    };

    let mut input = File::open(&args[2]).unwrap_or_else(|e| fail(format!("open input: {e}")));
    let mut output = File::create(&args[3]).unwrap_or_else(|e| fail(format!("create output: {e}")));

    let mut enc = FileEncryptor::new(&ek, chunk_size).unwrap_or_else(|e| fail(e));

    let mut buf = vec![0u8; chunk_size];
    let mut out_buf = Vec::with_capacity(chunk_size + 32);
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => fail(format!("read: {e}")),
        };
        out_buf.clear();
        enc.update(&buf[..n], &mut out_buf)
            .unwrap_or_else(|e| fail(e));
        if !out_buf.is_empty() {
            output
                .write_all(&out_buf)
                .unwrap_or_else(|e| fail(format!("write: {e}")));
        }
    }
    out_buf.clear();
    enc.finish(&mut out_buf).unwrap_or_else(|e| fail(e));
    output
        .write_all(&out_buf)
        .unwrap_or_else(|e| fail(format!("write: {e}")));
    process::exit(0);
}
