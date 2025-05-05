use chrono::{Local, TimeZone, Utc};
use roughenough::{merkle::MerkleTree, RtMessage, Tag};
use std::{
    convert::TryInto,
    env,
    error::Error,
    net::UdpSocket,
    time::{Duration, Instant},
};

type GenResult<T> = Result<T, Box<dyn Error>>;

/// Free anycast beacon
const DEFAULT_HOST: &str = "roughtime.int08h.com:2002";

fn main() -> GenResult<()> {
    // --- 1. parse <tx-hash> CLI arg -----------------------------------------
    let mut nonce = hex::decode(
        env::args()
            .nth(1)
            .expect("usage: cargo run -- <64-char tx-hash> [host:port]"),
    )?;
    if nonce.len() != 32 {
        return Err("hash must be 32 bytes (64 hex chars)".into());
    }
    nonce.resize(64, 0); // pad to 64-byte NONC

    // --- 2. craft 1 024-byte Roughtime request ------------------------------
    let mut req = RtMessage::with_capacity(2);
    req.add_field(Tag::NONC, &nonce)
        .map_err(|e| format!("{:?}", e))?;
    req.add_field(Tag::PAD, &[])
        .map_err(|e| format!("{:?}", e))?;
    let pad = vec![0u8; req.calculate_padding_length()];
    req.clear();
    req.add_field(Tag::NONC, &nonce)
        .map_err(|e| format!("{:?}", e))?;
    req.add_field(Tag::PAD, &pad)
        .map_err(|e| format!("{:?}", e))?;

    // --- 3. send & receive ---------------------------------------------------
    let target = env::args().nth(2).unwrap_or_else(|| DEFAULT_HOST.to_string());
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;

    let start = Instant::now();
    let bytes = req.encode().map_err(|e| format!("{:?}", e))?;
    sock.send_to(&bytes, target.as_str())?;            // <-- FIX (no parse)

    let mut buf = [0u8; 4096];
    let (len, _) = sock.recv_from(&mut buf)?;
    let rtt = start.elapsed();

    // --- 4. parse + verify ---------------------------------------------------
    let resp = RtMessage::from_bytes(&buf[..len]).map_err(|e| format!("{:?}", e))?;
    let srep = RtMessage::from_bytes(resp.get_field(Tag::SREP).unwrap())
        .map_err(|e| format!("{:?}", e))?;

    let radius = u32::from_le_bytes(srep.get_field(Tag::RADI).unwrap()[..4].try_into()?);
    let midp = u64::from_le_bytes(srep.get_field(Tag::MIDP).unwrap()[..8].try_into()?);

    // Merkle inclusion proof
    let index = u32::from_le_bytes(resp.get_field(Tag::INDX).unwrap()[..4].try_into()?);
    let path = resp.get_field(Tag::PATH).unwrap();
    let root = MerkleTree::new_sha512_google().root_from_paths(index as usize, &nonce, path);
    let ok = root == srep.get_field(Tag::ROOT).unwrap();

    // --- 5. pretty-print -----------------------------------------------------
    let ts_utc = Utc
        .timestamp_opt((midp / 1_000_000) as i64, ((midp % 1_000_000) * 1_000) as u32)
        .single()
        .unwrap();
    let ts_local =
        Local.timestamp_opt(ts_utc.timestamp(), ts_utc.timestamp_subsec_nanos()).unwrap();

    println!("server      : {}", target);
    println!("RTT         : {:.3} ms", rtt.as_secs_f64() * 1e3);
    println!("midpoint    : {}  (local {})", ts_utc, ts_local);
    println!(
        "radius      : {} µs  (±{:.3} ms)",
        radius,
        radius as f64 / 1_000.0
    );
    println!("merkle-ok   : {}", ok);

    Ok(())
}