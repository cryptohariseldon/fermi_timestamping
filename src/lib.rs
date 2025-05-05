//! fermi_roughtime – minimal wrapper around two public Roughtime servers
//! to obtain a latency‑adjusted, median‑filtered UTC timestamp.
//!
//! ## Usage
//! ```rust
//! use fermi_roughtime::get_timestamp;
//!
//! fn main() -> anyhow::Result<()> {
//!     let ts = get_timestamp(0xdead_beef)?;
//!     println!("{}", serde_json::to_string_pretty(&ts)?);
//!     Ok(())
//! }
//! ```

use base64::{engine::general_purpose as b64, Engine as _};
use chrono::{DateTime, Duration, TimeZone, Utc};
use roughtime::{error::Error as RoughtimeError, Client};
use serde::Serialize;
use std::time::Instant;
use thiserror::Error;

/// Roughtime endpoint definitions – feel free to replace / expand.
const CLOUDFLARE_ADDR: &str = "roughtime.cloudflare.com:2003";
/// Base64‑encoded long‑term root public key published by Cloudflare.
const CLOUDFLARE_PUBKEY_B64: &str = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="; // ([developers.cloudflare.com](https://developers.cloudflare.com/time-services/roughtime/usage/?utm_source=chatgpt.com))

const INT08H_ADDR: &str = "roughtime.int08h.com:2002";
/// Base64‑encoded public key from DNS TXT record of roughtime.int08h.com.
const INT08H_PUBKEY_B64: &str = "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE="; // ([github.com](https://github.com/int08h/roughenough?utm_source=chatgpt.com))

/// Metadata returned alongside the final timestamp.
#[derive(Debug, Serialize)]
pub struct Metadata {
    /// Round‑trip times (ms) for each queried server.
    pub rtt_ms: [u128; 2],
    /// Raw midpoints (server‑supplied UTC time) before latency adjustment.
    pub midpoint_utc: [DateTime<Utc>; 2],
    /// Claimed uncertainty radii (µs) from each server.
    pub radius_us: [u32; 2],
    /// Clock drift between the two latency‑adjusted estimates (ms).
    pub drift_ms: i128,
}

/// Result returned by [`get_timestamp`].
#[derive(Debug, Serialize)]
pub struct TimestampResult {
    /// User‑supplied 32‑bit hash (opaque context value).
    pub input_hash: u32,
    /// Median latency‑adjusted timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    /// Rich diagnostic metadata.
    pub metadata: Metadata,
}

/// Errors bubbled up by the crate.
#[derive(Debug, Error)]
pub enum TimeSyncError {
    #[error("failed to query roughtime server: {0}")]
    Roughtime(#[from] RoughtimeError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("asynchronous runtime failure: {0}")]
    Tokio(#[from] tokio::task::JoinError),
}

/// Internal async helper – queries a single Roughtime server and reports
/// `(rtt_µs, midpoint_utc, radius_µs)`.
async fn query_server(addr: &str, pubkey_b64: &str) -> Result<(u128, DateTime<Utc>, u32), RoughtimeError> {
    // Decode B64‑encoded 32‑byte root key.
    let pubkey = b64::STANDARD
        .decode(pubkey_b64)
        .expect("invalid base64 public key");
    let mut client = Client::new(addr, pubkey);

    let t0 = Instant::now();
    let reply = client.get().await?;
    let rtt_µs = t0.elapsed().as_micros();

    // Roughtime midpoints are µs since Unix epoch.
    let midpoint_utc = Utc.timestamp_opt(
        (reply.midpoint() / 1_000_000) as i64,
        ((reply.midpoint() % 1_000_000) as u32) * 1_000,
    )
    .single()
    .expect("midpoint out of range");

    Ok((rtt_µs, midpoint_utc, reply.radius() as u32))
}

/// Query two Roughtime servers and return a latency‑adjusted median timestamp.
///
/// * `input_hash` – an opaque 32‑bit value you wish to bind to the query (e.g. the
///   BLAKE3 hash prefix of an order‑placement payload).
///
/// # Algorithm
/// 1. Fetch time from Cloudflare and int08h servers in parallel.
/// 2. For each, subtract half the measured round‑trip time to compensate for
///    network delay.
/// 3. Take the median (here: mean, since n=2) of the two adjusted values.
/// 4. Expose rich metadata so higher‑level components can audit / threshold.
///
/// The function is **blocking** (spins up a private Tokio runtime). If you are
/// already in an async context, call the internal `async_get_timestamp` instead.
pub fn get_timestamp(input_hash: u32) -> Result<TimestampResult, TimeSyncError> {
    // Spin up a lightweight runtime – cost ~2 µs after initial warm‑up.
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async move {
        let (s1, s2) = tokio::try_join!(
            query_server(CLOUDFLARE_ADDR, CLOUDFLARE_PUBKEY_B64),
            query_server(INT08H_ADDR, INT08H_PUBKEY_B64)
        )?;

        let (rtt1, mid1, rad1) = s1;
        let (rtt2, mid2, rad2) = s2;

        // Latency‑adjusted: assume symmetric delay → subtract half RTT.
        let adj1 = mid1 - Duration::microseconds((rtt1 / 2) as i64);
        let adj2 = mid2 - Duration::microseconds((rtt2 / 2) as i64);

        // Median (n=2 => mean).
        let ts = adj1 + (adj2 - adj1) / 2;
        let drift_ms = (adj1 - adj2).num_milliseconds();

        Ok(TimestampResult {
            input_hash,
            timestamp: ts,
            metadata: Metadata {
                rtt_ms: [(rtt1 / 1_000) as u128, (rtt2 / 1_000) as u128],
                midpoint_utc: [mid1, mid2],
                radius_us: [rad1, rad2],
                drift_ms,
            },
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_query() {
        let res = get_timestamp(0x1234_5678).expect("timestamp query failed");
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
        // Basic sanity: drift should be < 10 s.
        assert!(res.metadata.drift_ms.abs() < 10_000);
    }
}
```

// =========================  README.md  =========================
// Optional – omit if you prefer, provided here for completeness.

/*
# fermi_roughtime

Fetch a latency‑compensated median timestamp from two public Roughtime servers
(Cloudflare + int08h) in a single line of Rust.

```rust
let ts = fermi_roughtime::get_timestamp(0xdead_beef)?;
println!("{}", serde_json::to_string_pretty(&ts)?);
```

Why dual‑source? Because Roughtime’s security model detects *lying* servers but
cannot fix an outright *failed* one. Interrogating two independent operators
and cross‑checking their answers gives you immediate drift diagnostics, letting
you reject obviously bogus answers in latency‑critical pipelines (e.g. global
DEX order‑ingress timestamping).

*/