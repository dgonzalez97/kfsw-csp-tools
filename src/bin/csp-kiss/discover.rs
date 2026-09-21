use super::*;
use serde_json::json;

#[derive(clap::Args)]
pub struct Args {
    /// Explicit node addresses, separated by commas (up to 64).
    #[arg(long, value_delimiter = ',', required_unless_present = "range", conflicts_with = "range",
          value_parser = clap::value_parser!(u16).range(0..16383))]
    nodes: Vec<u16>,
    /// Inclusive range, e.g. 1:8 (at most 64 addresses).
    #[arg(long)]
    range: Option<String>,
    /// Overall budget, including ping and identity requests.
    #[arg(long, default_value_t = 5000, value_parser = clap::value_parser!(u32).range(1..=60000))]
    budget_ms: u32,
    /// Create a new JSONL inventory; otherwise write to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl Args {
    pub fn nodes(&self, source: u16) -> Result<Vec<u16>> {
        let mut nodes = if let Some(range) = &self.range {
            let (first, last) = range.split_once(':').context("range must be first:last")?;
            let first: u16 = first.parse()?;
            let last: u16 = last.parse()?;
            ensure!(
                first <= last && last < 16383 && last - first < 64,
                "range must contain 1..64 unicast addresses"
            );
            (first..=last).collect()
        } else {
            self.nodes.clone()
        };
        ensure!(
            !nodes.is_empty() && nodes.len() <= 64,
            "provide 1..64 nodes"
        );
        ensure!(
            !nodes.contains(&source),
            "node list includes the local source address"
        );
        ensure!(
            nodes.iter().all(|node| *node < 16383),
            "broadcast addresses are not supported"
        );
        nodes.sort_unstable();
        nodes.dedup();
        Ok(nodes)
    }
}

fn identity(payload: &[u8]) -> Result<serde_json::Value> {
    ensure!(
        payload.len() == 93 && payload[..2] == [0xff, 1],
        "invalid CMP identity reply"
    );
    let mut fields = serde_json::Map::new();
    let mut offset = 2;
    for (name, size) in [
        ("hostname", 20),
        ("model", 30),
        ("revision", 20),
        ("date", 12),
        ("time", 9),
    ] {
        let bytes = &payload[offset..offset + size];
        let end = bytes
            .iter()
            .position(|b| *b == 0)
            .context("unterminated identity field")?;
        let text = std::str::from_utf8(&bytes[..end])?;
        ensure!(
            !text.chars().any(char::is_control),
            "control character in identity"
        );
        fields.insert(name.into(), json!(text));
        offset += size;
    }
    Ok(fields.into())
}

fn request(
    port: &mut dyn SerialPort,
    decoder: &mut Decoder,
    packet: &Packet,
    timeout: Duration,
    deadline: Instant,
) -> Result<Option<Packet>> {
    if Instant::now() >= deadline {
        return Ok(None);
    }
    port.set_timeout(
        timeout
            .min(deadline.saturating_duration_since(Instant::now()))
            .max(Duration::from_millis(1)),
    )?;
    port.write_all(&packet.encode())?;
    port.flush()?;
    receive_reply(
        port,
        decoder,
        packet,
        deadline.min(Instant::now() + timeout),
    )
}

pub fn run(
    port: &mut dyn SerialPort,
    decoder: &mut Decoder,
    source: u16,
    timeout: Duration,
    args: Args,
) -> Result<()> {
    let nodes = args.nodes(source)?;
    let mut output = output_file(&args.output)?;
    let deadline = Instant::now() + Duration::from_millis(u64::from(args.budget_ms));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_be_bytes();
    let mut queried = 0;
    let mut identified = 0;
    for (index, node) in nodes.iter().copied().enumerate() {
        let mut row = json!({"version":1, "kind":"neighbor", "node":node, "status":"not_queried"});
        if Instant::now() < deadline {
            queried += 1;
            let local_port = 16 + (index % 48) as u8;
            let ping = Packet::request(source, node, local_port, 1, &nonce)?;
            let started = Instant::now();
            row["status"] = json!("no_reply");
            if let Some(reply) = request(port, decoder, &ping, timeout, deadline)? {
                if reply.payload() != nonce {
                    row["status"] = json!("invalid_ping");
                } else {
                    row["status"] = json!("reachable");
                    row["rtt_ms"] = json!(started.elapsed().as_secs_f64() * 1000.0);
                    let mut payload = [0u8; 93];
                    payload[1] = 1;
                    let query = Packet::request(source, node, local_port, 0, &payload)?;
                    if let Some(reply) = request(port, decoder, &query, timeout, deadline)? {
                        match identity(reply.payload()) {
                            Ok(info) => {
                                row["status"] = json!("identified");
                                row["identity"] = info;
                                identified += 1;
                            }
                            Err(error) => {
                                row["identity_error"] = json!(error.to_string());
                            }
                        }
                    } else {
                        row["identity_error"] = json!("no reply within budget");
                    }
                }
            }
        }
        json_line(&mut *output, &row)?;
    }
    json_line(
        &mut *output,
        &json!({"version":1, "kind":"summary", "queried":queried,
        "requested":nodes.len(), "identified":identified, "complete":queried == nodes.len()}),
    )?;
    ensure!(
        queried == nodes.len(),
        "inventory budget exhausted; partial results retained"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_selection() {
        let mut args = Args {
            nodes: vec![2, 1, 2],
            range: None,
            budget_ms: 100,
            output: None,
        };
        assert_eq!(args.nodes(16).unwrap(), vec![1, 2]);
        assert!(args.nodes(1).is_err());
        for range in ["5:1", "0:64", "16382:16383", "0:65535", "1", "-1:2"] {
            args.range = Some(range.into());
            assert!(args.nodes(100).is_err(), "{range}");
        }
        args.range = Some("0:63".into());
        assert_eq!(args.nodes(100).unwrap().len(), 64);
    }

    #[test]
    fn identity_validates_fixed_fields() {
        let mut bytes = [0u8; 93];
        bytes[..2].copy_from_slice(&[0xff, 1]);
        bytes[2..6].copy_from_slice(b"node");
        assert_eq!(identity(&bytes).unwrap()["hostname"], "node");
        assert!(identity(&bytes[..92]).is_err());
        bytes[2] = 0x1b;
        assert!(identity(&bytes).is_err());
        bytes[2..22].fill(b'a');
        assert!(identity(&bytes).is_err());
    }
}
