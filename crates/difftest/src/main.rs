use clap::Parser;
use jobfmt::WorkerResult;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The differential determinism harness.
///
/// The claim it tests: the emulator is a pure function of (job, input),
/// independent of build profile, host OS, libc, allocator, and CPU.
/// It runs the same job through the worker built at two optimization
/// levels on this machine, and optionally inside a Linux container,
/// then asserts byte-identical chunk hash chains. CI extends this to
/// a second CPU architecture (macOS ARM64).
#[derive(Parser)]
struct Args {
    job_dir: PathBuf,
    /// Also run the job inside this Docker image (e.g. rust:1) and
    /// compare hashes against the local run.
    #[arg(long)]
    docker: Option<String>,
    /// Prefix for the result JSONs (target/<prefix>-debug.json and
    /// target/<prefix>-release.json). Distinct jobs need distinct
    /// prefixes or a later run overwrites the earlier artifacts.
    #[arg(long, default_value = "difftest")]
    out_prefix: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn run_worker(worker: &Path, job_dir: &Path, id: &str, out: &Path) -> WorkerResult {
    let st = Command::new(worker)
        .arg("run")
        .arg(job_dir)
        .arg("--out")
        .arg(out)
        .args(["--id", id])
        .status()
        .expect("spawn worker");
    assert!(st.success(), "worker {id} exited {st}");
    let json = std::fs::read(out).expect("read result");
    serde_json::from_slice(&json).expect("parse result")
}

fn ensure_job_built(root: &Path, job_dir: &Path) {
    let _ = root; // unused for now; will hold the cargo workspace lock later
    let elf = job_dir.join("program.elf");
    if elf.exists() {
        return;
    }
    let crate_dir = job_dir.join("job");
    let st = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(&crate_dir)
        .status()
        .expect("cargo build for job");
    assert!(st.success(), "job build failed");
    let src = crate_dir.join("target/riscv64imac-unknown-none-elf/release/demo-hash");
    std::fs::copy(&src, &elf).expect("copy job elf");
}

fn compare(a: &WorkerResult, b: &WorkerResult, what: &str) -> bool {
    let ok = a.status == b.status
        && a.instructions == b.instructions
        && a.result_hash == b.result_hash
        && a.chunk_hashes == b.chunk_hashes
        && a.output_hex == b.output_hex;
    if !ok {
        eprintln!(
            "MISMATCH ({what}):\n  A: {} insts, hash {}\n  B: {} insts, hash {}",
            a.instructions,
            a.result_hash,
            b.instructions,
            b.result_hash
        );
        if a.chunk_hashes.len() != b.chunk_hashes.len() {
            eprintln!(
                "  chain lengths differ: {} vs {}",
                a.chunk_hashes.len(),
                b.chunk_hashes.len()
            );
        } else {
            for (i, (x, y)) in a.chunk_hashes.iter().zip(&b.chunk_hashes).enumerate() {
                if x != y {
                    eprintln!("  first divergent chunk: #{i}\n    A: {x}\n    B: {y}");
                    break;
                }
            }
        }
    }
    ok
}

fn main() {
    let args = Args::parse();
    let root = workspace_root();
    let job_dir = if args.job_dir.is_absolute() {
        args.job_dir.clone()
    } else {
        root.join(&args.job_dir)
    };
    ensure_job_built(&root, &job_dir);

    let target = root.join("target");
    let worker_debug = target.join(format!("debug/worker{}", std::env::consts::EXE_SUFFIX));
    let worker_release = target.join(format!("release/worker{}", std::env::consts::EXE_SUFFIX));

    for profile in ["debug", "release"] {
        let st = Command::new("cargo")
            .args(["build", "-p", "worker"])
            .args(if profile == "release" { vec!["--release".to_string()] } else { vec![] })
            .current_dir(&root)
            .status()
            .expect("cargo build worker");
        assert!(st.success(), "worker build failed ({profile})");
    }

    let out_a = target.join(format!("{}-debug.json", args.out_prefix));
    let out_b = target.join(format!("{}-release.json", args.out_prefix));
    let a = run_worker(&worker_debug, &job_dir, "debug", &out_a);
    let b = run_worker(&worker_release, &job_dir, "release", &out_b);

    println!(
        "local differential (debug vs release): {} chunks, result {}",
        a.chunk_hashes.len(),
        a.result_hash
    );
    let mut all_ok = compare(&a, &b, "debug vs release");

    if let Some(image) = &args.docker {
        let root_str = root.to_string_lossy().replace('\\', "/");
        let job_rel = args
            .job_dir
            .to_string_lossy()
            .replace('\\', "/");
        // Own target dir: host artifacts must not mix with container ones.
        // The job ELF is prebuilt, so the container needs no RISC-V target.
        let script = format!(
            "CARGO_TARGET_DIR=target-docker cargo run --release -p worker -- {job_rel} --out target-docker/difftest-docker.json --id docker-linux"
        );
        let st = Command::new("docker")
            .args(["run", "--rm", "-v", &format!("{root_str}:/ws"), "-w", "/ws", image, "bash", "-c", &script])
            .status()
            .expect("docker run");
        assert!(st.success(), "docker run failed");
        let out_c = root.join("target-docker/difftest-docker.json");
        let docker_result: WorkerResult = serde_json::from_slice(
            &std::fs::read(&out_c).expect("read docker result"),
        )
        .expect("parse docker result");
        println!(
            "docker differential ({image}, linux x64): result {}",
            docker_result.result_hash
        );
        all_ok &= compare(&b, &docker_result, "host vs linux container");
    }

    if all_ok {
        println!("DIFFERENTIAL PASS: chunk hash chains are byte-identical across all environments");
    } else {
        eprintln!("DIFFERENTIAL FAIL: determinism contract violated");
        std::process::exit(1);
    }
}
