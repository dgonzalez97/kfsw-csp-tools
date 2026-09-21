use super::*;
use serde_json::json;

#[derive(clap::Args)]
pub struct Args {
    #[arg(long, value_parser = clap::value_parser!(u16).range(0..16383))]
    pub node: u16,
    /// Most recent records to consider, before applying the severity filter.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=32))]
    count: u16,
    /// 0 debug, 1 info, 2 warning, 3 error.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
    min_level: u8,
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u8).range(1..=63))]
    port: u8,
    /// Create a new JSONL capture; otherwise write to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Default)]
struct Capture {
    window: Option<(u64, u64)>,
    previous: u64,
    received: u16,
    complete: bool,
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

impl Capture {
    fn accept(&mut self, body: &[u8], count: u16, minimum: u8) -> Result<serde_json::Value> {
        ensure!(
            !self.complete && body.len() >= 10 && body[0] == 1,
            "invalid log reply"
        );
        match body[1] {
            0 => {
                ensure!(
                    self.window.is_none() && body.len() == 34,
                    "invalid log start"
                );
                let first = u64_at(body, 10);
                let end = u64_at(body, 18);
                let overwritten = u64_at(body, 26);
                ensure!(
                    first > 0
                        && end >= first
                        && end - first <= u64::from(count)
                        && overwritten < first,
                    "invalid log window"
                );
                self.window = Some((first, end));
                self.previous = first - 1;
                Ok(json!({"kind":"start", "first":first, "end":end, "overwritten":overwritten}))
            }
            1 => {
                let (first, end) = self.window.context("log record before start")?;
                ensure!(
                    body.len() >= 30 && body[29] < 192 && body.len() == 30 + usize::from(body[29]),
                    "invalid log record length"
                );
                let sequence = u64_at(body, 10);
                ensure!(
                    sequence >= first && sequence < end && sequence > self.previous,
                    "duplicate or unordered log record"
                );
                ensure!(
                    body[27] >= minimum && body[27] <= 3 && body[28] <= 1,
                    "invalid log metadata"
                );
                self.previous = sequence;
                self.received += 1;
                Ok(
                    json!({"kind":"log", "sequence":sequence, "uptime_ms":u64_at(body, 18),
                    "module":body[26], "severity":body[27], "truncated":body[28] == 1,
                    "text":String::from_utf8_lossy(&body[30..]),
                    "text_hex":body[30..].iter().map(|b| format!("{b:02x}")).collect::<String>()}),
                )
            }
            2 => {
                let (first, end) = self.window.context("log end before start")?;
                ensure!(body.len() == 13 && body[10] <= 2, "invalid log end");
                let sent = u16::from_be_bytes([body[11], body[12]]);
                self.complete = body[10] == 0
                    && sent == self.received
                    && (minimum != 0 || u64::from(sent) == end - first);
                Ok(json!({"kind":"end", "status":body[10], "sent":sent,
                    "received":self.received, "complete":self.complete}))
            }
            _ => anyhow::bail!("unknown log reply type"),
        }
    }
}

pub fn run(
    port: &mut dyn SerialPort,
    decoder: &mut Decoder,
    source: u16,
    timeout: Duration,
    args: Args,
) -> Result<()> {
    let mut output = output_file(&args.output)?;
    let mut payload = [0u8; 12];
    payload[0] = 1;
    payload[1] = args.min_level;
    payload[2..4].copy_from_slice(&args.count.to_be_bytes());
    let nonce = (SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64).to_be_bytes();
    payload[4..].copy_from_slice(&nonce);
    let query = Packet::request(source, args.node, 40, args.port, &payload)?;
    let deadline = Instant::now() + timeout;
    port.set_timeout(timeout)?;
    port.write_all(&query.encode())?;
    port.flush()?;
    let mut capture = Capture::default();
    while let Some(reply) = receive_reply(port, decoder, &query, deadline)? {
        let body = reply.payload();
        if body.len() >= 10 && body[2..10] != nonce {
            continue;
        }
        let mut value = capture.accept(body, args.count, args.min_level)?;
        value["version"] = json!(1);
        value["node"] = json!(args.node);
        json_line(&mut *output, &value)?;
        if body[1] == 2 {
            ensure!(
                capture.complete,
                "incomplete log capture; partial records retained"
            );
            return Ok(());
        }
    }
    anyhow::bail!("log capture timeout before completion; partial records retained")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> Vec<u8> {
        let mut bytes = vec![0u8; 34];
        bytes[0] = 1;
        bytes[10..18].copy_from_slice(&1u64.to_be_bytes());
        bytes[18..26].copy_from_slice(&2u64.to_be_bytes());
        bytes
    }

    fn record() -> Vec<u8> {
        let mut bytes = vec![0u8; 31];
        bytes[..2].copy_from_slice(&[1, 1]);
        bytes[10..18].copy_from_slice(&1u64.to_be_bytes());
        bytes[27] = 2;
        bytes[28] = 1;
        bytes[29] = 1;
        bytes[30] = b'x';
        bytes
    }

    #[test]
    fn validates_window_records_and_completion() {
        let mut capture = Capture::default();
        assert!(capture.accept(&record(), 32, 0).is_err());
        capture.accept(&start(), 32, 0).unwrap();
        assert!(capture.accept(&start(), 32, 0).is_err());
        assert!(capture.accept(&record()[..30], 32, 0).is_err());
        assert_eq!(capture.accept(&record(), 32, 0).unwrap()["truncated"], true);
        assert!(capture.accept(&record(), 32, 0).is_err());
        let mut end = vec![0u8; 13];
        end[..2].copy_from_slice(&[1, 2]);
        end[12] = 1;
        assert_eq!(capture.accept(&end, 32, 0).unwrap()["complete"], true);
    }

    #[test]
    fn dropped_packet_and_server_failure_are_incomplete() {
        let mut end = vec![0u8; 13];
        end[..2].copy_from_slice(&[1, 2]);
        end[12] = 1;
        for status in 0..=2 {
            let mut capture = Capture::default();
            capture.accept(&start(), 32, 0).unwrap();
            end[10] = status;
            assert_eq!(capture.accept(&end, 32, 0).unwrap()["complete"], false);
        }
    }
}
