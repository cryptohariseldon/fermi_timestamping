use chrono::{DateTime, Local, TimeZone, Utc};
use roughenough::{merkle::MerkleTree, RtMessage, Tag};
use std::{
    convert::TryInto,
    env,
    error::Error,
    net::UdpSocket,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant, SystemTime},
};

// ---------- polymorphic, thread-safe error -------------------------------
type GenResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
fn wrap<E: std::fmt::Debug>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))
}

// ---------- result bundle ------------------------------------------------
struct Probe {
    host: String,
    rtt: Duration,
    offset: i128,          // µs   (server – client)
    uncert: i128,          // µs   ½RTT + radius
    midpoint_us: u64,      // for pretty-print only
}

fn main() -> GenResult<()> {
    // ---------- CLI -------------------------------------------------------
    let mut nonce = hex::decode(
        env::args()
            .nth(1)
            .expect("usage: cargo run -- <64-char nonce> [host1] [host2]"),
    )?;
    if nonce.len() != 32 {
        return Err("nonce must be 32 bytes".into());
    }
    nonce.resize(64, 0);
    let nonce = Arc::new(nonce);

    let h1 = env::args()
        .nth(2)
        //.unwrap_or_else(|| "roughtime.int08h.com:2002".into());
        .unwrap_or_else(|| "time.cloudflare.com:2003".into());
    let h2 = env::args()
        .nth(3)
        .unwrap_or_else(|| "time.cloudflare.com:2003".into());

    // ---------- barrier: launch together ---------------------------------
    let gate = Arc::new(Barrier::new(3));
    let t1 = spawn(h1, nonce.clone(), gate.clone());
    let t2 = spawn(h2, nonce.clone(), gate.clone());
    gate.wait();

    let p1 = t1.join().unwrap()?;
    let p2 = t2.join().unwrap()?;

    print_probe(&p1);
    println!();
    print_probe(&p2);

    // ---------- drift after latency comp ---------------------------------
    let drift = (p1.offset - p2.offset).abs();
    println!("\n---------------------------------------------------");
    println!(
        "clock drift (lat-adj) : {:>7.3} ms\nuncertainty bound     : ±{:>5.3} ms (max of both)",
        drift as f64 / 1e3,
        (p1.uncert.max(p2.uncert)) as f64 / 1e3
    );
    println!("---------------------------------------------------");
    Ok(())
}

fn spawn(
    host: String,
    nonce: Arc<Vec<u8>>,
    gate: Arc<Barrier>,
) -> thread::JoinHandle<GenResult<Probe>> {
    thread::spawn(move || {
        // fully prepare packet first
        let packet = build_packet(&nonce)?;
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_read_timeout(Some(Duration::from_secs(3)))?;

        gate.wait(); // align send-time

        let send_wall = SystemTime::now();
        let send_instant = Instant::now();
        sock.send_to(&packet, &host)?;
        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf)?;
        let rtt = send_instant.elapsed();

        parse_reply(&host, &nonce, &buf[..len], send_wall, rtt)
    })
}

// ---------- packet helpers ----------------------------------------------
fn build_packet(nonce: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut req = RtMessage::with_capacity(2);
    req.add_field(Tag::NONC, nonce).map_err(wrap)?;
    req.add_field(Tag::PAD, &[]).map_err(wrap)?;
    let pad = vec![0u8; req.calculate_padding_length()];
    req.clear();
    req.add_field(Tag::NONC, nonce).map_err(wrap)?;
    req.add_field(Tag::PAD, &pad).map_err(wrap)?;
    Ok(req.encode().map_err(wrap)?)
}

fn parse_reply(
    host: &str,
    nonce: &[u8],
    buf: &[u8],
    t_send_wall: SystemTime,
    rtt: Duration,
) -> GenResult<Probe> {
    let resp = RtMessage::from_bytes(buf).map_err(wrap)?;
    let srep = RtMessage::from_bytes(resp.get_field(Tag::SREP).unwrap()).map_err(wrap)?;

    let radius_us = u32::from_le_bytes(srep.get_field(Tag::RADI).unwrap()[..4].try_into()?);
    let mid_us = u64::from_le_bytes(srep.get_field(Tag::MIDP).unwrap()[..8].try_into()?);

    // verify Merkle (optional but nice)
    let index = u32::from_le_bytes(resp.get_field(Tag::INDX).unwrap()[..4].try_into()?);
    let path = resp.get_field(Tag::PATH).unwrap();
    let root = MerkleTree::new_sha512_google().root_from_paths(index as usize, nonce, path);
    assert_eq!(root, srep.get_field(Tag::ROOT).unwrap(), "bad Merkle proof");

    // convert mid-point to SystemTime
    let mid_wall = SystemTime::UNIX_EPOCH + Duration::from_micros(mid_us);
    let local_half_rtt = Duration::from_micros((rtt.as_micros() / 2) as u64);
    let local_mid_est = t_send_wall + local_half_rtt;

    let offset = mid_wall
        .duration_since(local_mid_est)
        .map(|d| d.as_micros() as i128)
        .unwrap_or_else(|e| -(e.duration().as_micros() as i128));

    Ok(Probe {
        host: host.into(),
        rtt,
        offset,
        uncert: radius_us as i128 + local_half_rtt.as_micros() as i128,
        midpoint_us: mid_us,
    })
}

// ---------- fancy print --------------------------------------------------
fn print_probe(p: &Probe) {
    let mid_utc: DateTime<Utc> = Utc
        .timestamp_opt(
            (p.midpoint_us / 1_000_000) as i64,
            ((p.midpoint_us % 1_000_000) * 1_000) as u32,
        )
        .unwrap();
    let mid_local = Local
        .timestamp_opt(mid_utc.timestamp(), mid_utc.timestamp_subsec_nanos())
        .unwrap();
    println!("server      : {}", p.host);
    println!("RTT         : {:>8.3} ms", p.rtt.as_secs_f64() * 1e3);
    println!("midpoint    : {}  (local {})", mid_utc, mid_local);
    println!(
        "offset      : {:+9.3} ms   (server – client)",
        p.offset as f64 / 1e3
    );
    println!(
        "uncertainty : ±{:>7.3} ms   (radius + RTT/2)",
        p.uncert as f64 / 1e3
    );
}