use contentstore::{descriptor_id, materialize, publish, ContentId, Store};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(name);
    std::fs::remove_dir_all(&dir).ok();
    dir
}

#[test]
fn put_get_roundtrip_and_id_stability() {
    let root = temp_dir("p2pc-store-basic");
    let store = Store::open(&root).unwrap();

    let data = b"hello deterministic world";
    let id = store.put(data).unwrap();
    let id2 = store.put(data).unwrap(); // idempotent
    assert_eq!(id, id2);

    assert_eq!(store.get(&id).unwrap(), data);
    assert!(store.has(&id).unwrap());
    assert!(!store.get(&ContentId::from_data(b"absent")).is_ok());
}

#[test]
fn tampered_blob_fails_read_and_verify() {
    let root = temp_dir("p2pc-store-tamper");
    let store = Store::open(&root).unwrap();
    let id = store.put(b"integrity matters").unwrap();

    // Corrupt the stored file in place.
    let hex = id.to_hex();
    let path = root.join("blobs").join(&hex[..2]).join(&hex);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    // get() refuses silently-corrupted content...
    assert!(store.get(&id).is_err());
    // ...and a full sweep names the offender.
    assert!(store.verify_all().is_err());
}

#[test]
fn verify_all_passes_on_clean_store() {
    let root = temp_dir("p2pc-store-verify");
    let store = Store::open(&root).unwrap();
    store.put(b"one").unwrap();
    store.put(b"two").unwrap();
    store.put(b"three").unwrap();
    assert_eq!(store.verify_all().unwrap(), 3);
}

#[test]
fn publish_materialize_roundtrip_preserves_job_bytes() {
    let root = temp_dir("p2pc-store-publish");
    let job_dir = root.join("original");
    let store = Store::open(root.join("store")).unwrap();

    // A synthetic job: manifest + elf + input as plain files.
    let manifest = r#"{
        "schema": 1,
        "id": "store-test-0001",
        "name": "store-test",
        "isa": "rv64imc",
        "toolchain": "synthetic",
        "chunk_size": 1024,
        "max_instructions": 1000,
        "verification_class": "quorum3",
        "elf": "program.elf",
        "input": "input.bin"
    }"#;
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("job.json"), manifest).unwrap();
    std::fs::write(job_dir.join("program.elf"), b"FAKE-ELF-BYTES").unwrap();
    std::fs::write(job_dir.join("input.bin"), b"FAKE-INPUT-BYTES").unwrap();

    // Publish → descriptor; materialize → identical job directory.
    let desc = publish(&job_dir, &store).unwrap();
    assert_eq!(desc.job_id, "store-test-0001");
    let desc_id = descriptor_id(&desc).unwrap();

    let out_dir = root.join("materialized");
    materialize(&desc, &store, &out_dir).unwrap();

    let loaded = jobfmt::load_dir(&out_dir).unwrap();
    assert_eq!(loaded.manifest.id, "store-test-0001");
    assert_eq!(loaded.elf, b"FAKE-ELF-BYTES");
    assert_eq!(loaded.input, b"FAKE-INPUT-BYTES");

    // The descriptor identity is stable across republishing the same job.
    let desc2 = publish(&out_dir, &store).unwrap();
    assert_eq!(descriptor_id(&desc2).unwrap(), desc_id);

    // A mutated descriptor fails at materialize (hash mismatch).
    let mut bad = desc.clone();
    bad.elf = bad.elf[..62].to_string() + if bad.elf.ends_with('0') { "1" } else { "0" };
    assert!(materialize(&bad, &store, &root.join("bad")).is_err());
}
