extern crate protoc_grpcio;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let target: HashMap<&str, u8> = vec![
        "empty.rs",
        "attribute.rs",
        "gobgp.rs",
        "gobgp_grpc.rs",
        "capability.rs",
    ]
    .iter()
    .map(|k| (*k, 0))
    .collect();

    let mut found = 0;
    for entry in fs::read_dir(Path::new("./src")).unwrap() {
        let name: &str = &(entry.unwrap().file_name().into_string().unwrap());
        if target.contains_key(name) {
            found += 1;
        }
    }

    if found == target.len() {
        return;
    }

    let proto_path = env::var("PROTOBUF").unwrap() + "/ptypes";
    let gobgp_path = env::var("GOBGP").unwrap() + "/api";
    let includes = [&proto_path, &gobgp_path];

    let files = fs::read_dir(&Path::new(&gobgp_path)).unwrap();
    let proto: Vec<_> = files
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                if e.path().extension().unwrap() == "proto" {
                    e.path().to_str().map(|s| String::from(s))
                } else {
                    None
                }
            })
        })
        .collect();

    // generate gobgp files
    protoc_grpcio::compile_grpc_protos(&proto, &includes, "./src", None).expect("protoc failed");

    // generate empty.rs
    protoc_grpcio::compile_grpc_protos(
        &[format!("{}/empty/empty.proto", proto_path)],
        &includes,
        "./src",
        None,
    )
    .expect("protoc failed")
}
