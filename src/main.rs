use chrono::{DateTime, Local, TimeZone, Utc};
use roughenough::{merkle::MerkleTree, RtMessage, Tag};
use std::{
    convert::TryInto,
    env,
    error::Error,
    net::UdpSocket,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

// ---------------------------------------------------------------------------
// Convenient alias: every error is guaranteed Send + Sync → thread-safe
type GenResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

// Helper: convert any Debug-printable error (e.g. roughenough::Error) into a
// boxed I/O error that *does* implement Error + Send + Sync.
fn wrap_err<E: std::fmt::Debug>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))
}

/// Everything we want to print later for a single probe.
#[derive(Debug)]
struct ProbeResult {
    host: String,
    rtt: Duration,
    midpoint_us: u64,
    radius_us: u32,
    merkle_ok: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
fn main() -> GenResult<()> {
    // -------- CLI -----------------------------------------------------------
    //  <64-char hex nonce> [host1] [host2]
    let mut nonce = hex::decode(
        env::args()
            .nth(1)
            .expect("usage: cargo run -- <64-char nonce> [host1] [host2]"),
    )?;
    if nonce.len() != 32 {
        return Err("nonce must be 32 bytes (64 hex chars)".into());
    }
    nonce.resize(64, 0);
    let nonce = Arc::new(nonce);

    let host1 = env::args()
        .nth(2)
        .unwrap_or_else(|| "roughtime.int08h.com:2002".into());
    let host2 = env::args()
        .nth(3)
        .unwrap_or_else(|| "time.cloudflare.com:2003".into());

    // -------- Synchronise launch to minimise skew ---------------------------
    let gate = Arc::new(Barrier::new(3)); // 2 workers + main

    let h1 = spawn_probe(host1, nonce.clone(), gate.clone());
    let h2 = spawn_probe(host2, nonce.clone(), gate.clone());

    gate.wait(); // unleash both threads near-simultaneously

    // -------- Gather results ------------------------------------------------
    let r1 = h1.join().expect("thread-1 panic")?;
    let r2 = h2.join().expect("thread-2 panic")?;

    print_result(&r1);
    println!();
    print_result(&r2);

    // -------- Drift summary -------------------------------------------------
    let drift_us = if r1.midpoint_us >= r2.midpoint_us {
        r1.midpoint_us - r2.midpoint_us
    } else {
        r2.midpoint_us - r1.midpoint_us
    };
    println!("\n-----------------------------------------------------------");
    println!(
        "clock-drift  : {:>6} µs  (≈ {:+6.3} ms  {} ↔ {})",
        drift_us,
        drift_us as f64 / 1_000.0,
        r1.host,
        r2.host
    );
    println!("-----------------------------------------------------------");

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Thread launcher

fn spawn_probe(
    host: String,
    nonce: Arc<Vec<u8>>,
    gate: Arc<Barrier>,
) -> thread::JoinHandle<GenResult<ProbeResult>> {
    thread::spawn(move || {
        // Set everything up *before* we wait on the barrier
        let res = probe_once(&host, &nonce);
        gate.wait(); // tell main we’re ready
        res
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// One complete Roughtime round-trip for a given host.

fn probe_once(host: &str, nonce: &[u8]) -> GenResult<ProbeResult> {
    // 1 — craft the canonical 1 024-byte request
    let mut req = RtMessage::with_capacity(2);
    req.add_field(Tag::NONC, nonce).map_err(wrap_err)?;
    req.add_field(Tag::PAD, &[]).map_err(wrap_err)?; // dummy to compute padding
    let pad = vec![0u8; req.calculate_padding_length()];
    req.clear();
    req.add_field(Tag::NONC, nonce).map_err(wrap_err)?;
    req.add_field(Tag::PAD, &pad).map_err(wrap_err)?;

    let bytes = req.encode().map_err(wrap_err)?;

    // 2 — send / receive
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;

    let t0 = Instant::now();
    sock.send_to(&bytes, host)?;
    let mut buf = [0u8; 4096];
    let (len, _) = sock.recv_from(&mut buf)?;
    let rtt = t0.elapsed();

    // 3 — parse & verify
    let resp = RtMessage::from_bytes(&buf[..len]).map_err(wrap_err)?;
    let srep = RtMessage::from_bytes(resp.get_field(Tag::SREP).unwrap()).map_err(wrap_err)?;

    let radius_us = u32::from_le_bytes(srep.get_field(Tag::RADI).unwrap()[..4].try_into()?);
    let midpoint_us = u64::from_le_bytes(srep.get_field(Tag::MIDP).unwrap()[..8].try_into()?);

    // Merkle-proof
    let index = u32::from_le_bytes(resp.get_field(Tag::INDX).unwrap()[..4].try_into()?);
    let path = resp.get_field(Tag::PATH).unwrap();
    let root = MerkleTree::new_sha512_google().root_from_paths(index as usize, nonce, path);
    let merkle_ok = root == srep.get_field(Tag::ROOT).unwrap();

    Ok(ProbeResult {
        host: host.to_string(),
        rtt,
        midpoint_us,
        radius_us,
        merkle_ok,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Pretty-printer

fn print_result(r: &ProbeResult) {
    let ts_utc: DateTime<Utc> = Utc
        .timestamp_opt(
            (r.midpoint_us / 1_000_000) as i64,
            ((r.midpoint_us % 1_000_000) * 1_000) as u32,
        )
        .single()
        .unwrap();
    let ts_local = Local
        .timestamp_opt(ts_utc.timestamp(), ts_utc.timestamp_subsec_nanos())
        .unwrap();

    println!("server      : {}", r.host);
    println!("RTT         : {:>6.3} ms", r.rtt.as_secs_f64() * 1e3);
    println!("midpoint    : {}  (local {})", ts_utc, ts_local);
    println!(
        "radius      : {:>6} µs  (±{:6.3} ms)",
        r.radius_us,
        r.radius_us as f64 / 1_000.0
    );
    println!("merkle-ok   : {}", r.merkle_ok);
}