//! rt_timestamp 0.2 – latency-adjusted Roughtime querier.

use chrono::{DateTime, Local, Utc};
use roughenough::{merkle::MerkleTree, RtMessage, Tag};
use std::{
    convert::TryInto,
    net::UdpSocket,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant, SystemTime},
};

// -------------------------------------------------------------------------
// Public structs

#[derive(Debug, serde::Serialize)]
pub struct TimestampResponse {
    pub input_hash: String,
    pub timestamp: u64,        // median true-time (µs since epoch)
    pub metadata: Metadata,
}

#[derive(Debug, serde::Serialize)]
pub struct Metadata {
    pub beacons: [BeaconMeta; 2],
    pub drift_us: u64,
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct BeaconMeta {
    pub host: String,
    pub rtt_ms: f64,
    pub true_time: SystemTime,
    pub offset_us: i128,
    pub uncert_us: i128,
    pub radius_us: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum TimestampError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Thread panic")]
    Join,
    #[error("All probes failed")]
    NoProbes,
}

// -------------------------------------------------------------------------
// Constants & helpers

const DEFAULT_HOSTS: [&str; 2] = [
    "roughtime.cloudflare.com:2003",
    "time.cloudflare.com:2003",
];

#[inline]
fn pad_nonce(hash: [u8; 32]) -> Vec<u8> {
    let mut v = hash.to_vec();
    v.resize(64, 0);
    v
}

#[inline]
fn rt_to_io(e: roughenough::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))
}

#[inline]
fn sys_to_us(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

// -------------------------------------------------------------------------
// Public API

pub fn get_timestamp(hash: [u8; 32]) -> Result<TimestampResponse, TimestampError> {
    get_timestamp_custom(hash, &DEFAULT_HOSTS)
}

pub fn get_timestamp_custom(
    hash: [u8; 32],
    hosts: &[&str; 2],
) -> Result<TimestampResponse, TimestampError> {
    let nonce = Arc::new(pad_nonce(hash));
    let gate  = Arc::new(Barrier::new(3));            // 2 workers + main

    let h1 = spawn_probe(hosts[0].into(), nonce.clone(), gate.clone());
    let h2 = spawn_probe(hosts[1].into(), nonce.clone(), gate.clone());

    gate.wait();                                      // launch simultaneously

    let p1 = h1.join().map_err(|_| TimestampError::Join)??;
    let p2 = h2.join().map_err(|_| TimestampError::Join)??;

    // median-of-2 (earlier true_time wins)
    let (median_st, _) = if p1.true_time <= p2.true_time {
        (p1.true_time, p1.clone())
    } else {
        (p2.true_time, p2.clone())
    };

    let drift_us = (p1.offset_us - p2.offset_us).abs() as u64;

    Ok(TimestampResponse {
        input_hash: hex::encode(hash),
        timestamp: sys_to_us(median_st),
        metadata: Metadata {
            beacons: [p1, p2],
            drift_us,
        },
    })
}

// -------------------------------------------------------------------------
// Thread worker

fn spawn_probe(
    host: String,
    nonce: Arc<Vec<u8>>,
    gate: Arc<Barrier>,
) -> thread::JoinHandle<Result<BeaconMeta, TimestampError>> {
    thread::spawn(move || {
        let packet = build_packet(&nonce)?;
        let sock   = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_read_timeout(Some(Duration::from_secs(3)))?;

        gate.wait();

        let t_send_wall = SystemTime::now();
        let t_send_inst = Instant::now();
        sock.send_to(&packet, &host)?;
        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf)?;
        let rtt = t_send_inst.elapsed();

        parse_reply(&host, &nonce, &buf[..len], t_send_wall, rtt)
    })
}

// -------------------------------------------------------------------------
// Packet build & parse

fn build_packet(nonce: &[u8]) -> Result<Vec<u8>, TimestampError> {
    let mut req = RtMessage::with_capacity(2);
    req.add_field(Tag::NONC, nonce).map_err(rt_to_io)?;
    req.add_field(Tag::PAD, &[]).map_err(rt_to_io)?;
    let pad = vec![0u8; req.calculate_padding_length()];
    req.clear();
    req.add_field(Tag::NONC, nonce).map_err(rt_to_io)?;
    req.add_field(Tag::PAD, &pad).map_err(rt_to_io)?;
    Ok(req.encode().map_err(rt_to_io)?)
}

fn parse_reply(
    host: &str,
    nonce: &[u8],
    buf: &[u8],
    t_send_wall: SystemTime,
    rtt: Duration,
) -> Result<BeaconMeta, TimestampError> {
    let resp = RtMessage::from_bytes(buf).map_err(rt_to_io)?;
    let srep = RtMessage::from_bytes(resp.get_field(Tag::SREP).unwrap()).map_err(rt_to_io)?;

    let radius_us =
        u32::from_le_bytes(srep.get_field(Tag::RADI).unwrap()[..4].try_into().unwrap());
    let mid_us =
        u64::from_le_bytes(srep.get_field(Tag::MIDP).unwrap()[..8].try_into().unwrap());

    // Merkle inclusion proof
    let idx = u32::from_le_bytes(resp.get_field(Tag::INDX).unwrap()[..4].try_into().unwrap());
    let path = resp.get_field(Tag::PATH).unwrap();
    let root = MerkleTree::new_sha512_google().root_from_paths(idx as usize, nonce, path);
    assert_eq!(root, srep.get_field(Tag::ROOT).unwrap(), "Merkle path invalid");

    let half_rtt  = Duration::from_micros((rtt.as_micros() / 2) as u64);
    let true_time = t_send_wall + half_rtt;
    let mid_wall  = SystemTime::UNIX_EPOCH + Duration::from_micros(mid_us);

    let offset_us = match mid_wall.duration_since(true_time) {
        Ok(d)  =>  d.as_micros() as i128,
        Err(e) => -(e.duration().as_micros() as i128),
    };

    Ok(BeaconMeta {
        host: host.to_string(),                 // ← fixed line
        rtt_ms: rtt.as_secs_f64() * 1e3,
        true_time,
        offset_us,
        uncert_us: radius_us as i128 + half_rtt.as_micros() as i128,
        radius_us,
    })
}

// -------------------------------------------------------------------------
// Pretty-printer for quick manual test (optional)

#[allow(dead_code)]
fn print(resp: &TimestampResponse) {
    println!("input hash  : {}", resp.input_hash);
    println!("timestamp   : {}", resp.timestamp);
    for (i, b) in resp.metadata.beacons.iter().enumerate() {
        let dt_utc: DateTime<Utc> = b.true_time.into();
        let dt_loc: DateTime<Local> = b.true_time.into();
        println!("-- Beacon {i}  {host}", host = b.host);
        println!("   RTT          : {:.3} ms", b.rtt_ms);
        println!("   true-time    : {dt_utc}  (local {dt_loc})");
        println!("   offset       : {:+} µs", b.offset_us);
        println!("   uncert       : ±{} µs  (radius + ½ RTT)", b.uncert_us);
    }
    println!("drift (adj) : {} µs", resp.metadata.drift_us);
}
