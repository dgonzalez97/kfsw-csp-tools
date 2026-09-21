use anyhow::{Context, Result, ensure};
use clap::Parser;
use csp_tools::{
    csp::{Flags, Header, Packet, Priority},
    interfaces::{CspInterface, Interface, open_csp_interfaces},
    kiss,
};
use serde_json::json;
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

/// Measure CSP echo throughput with validated replies and bounded runtime.
#[derive(Parser, Debug)]
struct Args {
    /// CSP 2 KISS serial device (CSP 1 is used for CAN and ZMQ).
    #[arg(long, alias = "kiss", conflicts_with = "can")]
    device: Option<String>,
    #[arg(long, default_value_t = 115200)]
    baud: u32,
    #[arg(long)]
    can: Option<String>,
    #[arg(long, default_value = "tcp://127.0.0.1:6000")]
    zmq_tx_socket: String,
    #[arg(long, default_value = "tcp://127.0.0.1:7000")]
    zmq_rx_socket: String,
    #[arg(long, default_value_t = 30)]
    src_addr: u16,
    #[arg(long)]
    src_port: Option<u8>,
    #[arg(long, alias = "node")]
    dest_addr: u16,
    #[arg(long, default_value_t = 1)]
    dest_port: u8,
    #[arg(long)]
    via_addr: Option<u8>,
    /// Total CSP bytes, including header and CSP CRC, excluding transport framing.
    #[arg(long, default_value_t = 64)]
    packet_size: usize,
    /// Expected total reply size; requires a matching csp-ping-server setting.
    #[arg(long)]
    reply_size: Option<usize>,
    #[arg(long, default_value_t = 16)]
    csp_port_max_bind: u8,
    /// Offered CSP bytes per second.
    #[arg(long, conflicts_with = "rx_rate", required_unless_present = "rx_rate")]
    tx_rate: Option<f64>,
    /// Expected reply CSP bytes per second, converted to a request rate.
    #[arg(long, conflicts_with = "tx_rate")]
    rx_rate: Option<f64>,
    #[arg(long, default_value_t = 10.0)]
    duration: f64,
    /// Maximum RTT in seconds; also bounds the final receive drain.
    #[arg(long, default_value_t = 1.0)]
    reply_timeout: f64,
    #[arg(long, default_value_t = 1.0)]
    stats_period: f64,
    /// Disable CSP CRC on legacy CAN/ZMQ only.
    #[arg(long)]
    no_crc: bool,
    /// Print the final result as JSON on stdout.
    #[arg(long)]
    json: bool,
}

impl Args {
    fn overhead(&self) -> usize {
        if self.device.is_some() {
            10
        } else {
            4 + usize::from(!self.no_crc) * 4
        }
    }

    fn reply_size(&self) -> usize {
        self.reply_size.unwrap_or(self.packet_size)
    }

    fn rate(&self) -> f64 {
        self.tx_rate.unwrap_or_else(|| {
            self.rx_rate.unwrap() * self.packet_size as f64 / self.reply_size() as f64
        })
    }

    fn source_port(&self, sequence: usize) -> u8 {
        self.src_port.unwrap_or_else(|| {
            self.csp_port_max_bind + (sequence % usize::from(64 - self.csp_port_max_bind)) as u8
        })
    }

    fn validate(&self) -> Result<()> {
        let address_limit = if self.device.is_some() { 16384 } else { 32 };
        ensure!(
            self.src_addr < address_limit - 1 && self.dest_addr < address_limit - 1,
            "source and destination must be unicast addresses within the transport range"
        );
        ensure!(
            self.src_addr != self.dest_addr,
            "source and destination must differ"
        );
        ensure!(
            self.src_port.is_none_or(|port| port < 64)
                && self.dest_port < 64
                && self.csp_port_max_bind < 64,
            "ports must be below 64"
        );
        ensure!(
            self.via_addr.is_none_or(|addr| addr < 32),
            "via address must be below 32"
        );
        ensure!(
            self.device.is_none() || (!self.no_crc && self.via_addr.is_none()),
            "KISS requires CRC and does not use --via-addr"
        );
        ensure!(self.baud > 0, "baud must be positive");
        let maximum = if self.can.is_some() {
            2042
        } else {
            kiss::MAX_FRAME - 4
        };
        for size in [self.packet_size, self.reply_size()] {
            ensure!(
                (self.overhead() + 16..=maximum).contains(&size),
                "packet and reply sizes must hold a 16-byte transaction ID and fit the transport"
            );
        }
        for (name, value) in [
            ("duration", self.duration),
            ("reply-timeout", self.reply_timeout),
            ("stats-period", self.stats_period),
        ] {
            ensure!(
                value.is_finite() && (0.001..=3600.0).contains(&value),
                "{name} must be between 0.001 and 3600 seconds"
            );
        }
        let rate = self.rate();
        ensure!(
            rate.is_finite() && rate > 0.0,
            "rate must be finite and positive"
        );
        let interval = self.packet_size as f64 / rate;
        ensure!(
            interval.is_finite() && (0.000001..=3600.0).contains(&interval),
            "packet interval must be between 1 microsecond and 3600 seconds"
        );
        ensure!(
            (self.duration / interval).ceil() <= 1_000_000.0,
            "run exceeds one million packets; lower rate or duration"
        );
        Ok(())
    }
}

struct Reply {
    source: u16,
    destination: u16,
    sport: u8,
    dport: u8,
    flags: u8,
    payload: Vec<u8>,
}

enum Transport {
    Kiss {
        port: Box<dyn serialport::SerialPort>,
        decoder: kiss::Decoder,
    },
    Legacy {
        tx: CspInterface,
        rx: CspInterface,
    },
}

impl Transport {
    fn open(args: &Args) -> Result<Self> {
        if let Some(device) = &args.device {
            let port = serialport::new(device, args.baud)
                .timeout(Duration::from_millis(1000))
                .open()?;
            Ok(Self::Kiss {
                port,
                decoder: kiss::Decoder::default(),
            })
        } else {
            let (tx, rx) = open_csp_interfaces(
                args.can.as_deref(),
                &args.zmq_tx_socket,
                &args.zmq_rx_socket,
                args.src_addr as u8,
            )?;
            tx.set_nonblocking()?;
            rx.set_nonblocking()?;
            // Allow ZMQ subscriptions to propagate before starting the measurement.
            if args.can.is_none() {
                std::thread::sleep(Duration::from_millis(300));
            }
            Ok(Self::Legacy { tx, rx })
        }
    }

    fn send(&mut self, args: &Args, sequence: usize, payload: &[u8]) -> Result<()> {
        match self {
            Self::Kiss { port, .. } => {
                let packet = kiss::Packet::request(
                    args.src_addr,
                    args.dest_addr,
                    args.source_port(sequence),
                    args.dest_port,
                    payload,
                )?;
                port.write_all(&packet.encode())?;
            }
            Self::Legacy { tx, .. } => tx.send(&Packet {
                via: args.via_addr,
                header: Header {
                    priority: Priority::Normal,
                    source_address: args.src_addr as u8,
                    destination_address: args.dest_addr as u8,
                    source_port: args.source_port(sequence),
                    destination_port: args.dest_port,
                    reserved: 0,
                    flags: Flags {
                        hmac: false,
                        xtea: false,
                        rdp: false,
                        crc: !args.no_crc,
                    },
                },
                payload: payload.to_vec(),
            })?,
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<Option<Reply>> {
        match self {
            Self::Kiss { port, decoder } => {
                // Consume at most one frame per poll so traffic cannot starve deadlines.
                for _ in 0..port.bytes_to_read()?.min(8192) {
                    let mut byte = [0];
                    port.read_exact(&mut byte)?;
                    if let Some(frame) = decoder.feed(byte[0]) {
                        return Ok(kiss::Packet::from_kiss(&frame).ok().map(|packet| Reply {
                            source: packet.source(),
                            destination: packet.destination(),
                            sport: packet.source_port(),
                            dport: packet.destination_port(),
                            flags: packet.flags(),
                            payload: packet.payload().to_vec(),
                        }));
                    }
                }
                Ok(None)
            }
            Self::Legacy { rx, .. } => Ok(rx.try_receive()?.map(|packet| Reply {
                source: packet.header.source_address.into(),
                destination: packet.header.destination_address.into(),
                sport: packet.header.source_port,
                dport: packet.header.destination_port,
                flags: u8::from(packet.header.flags.crc)
                    | (u8::from(
                        packet.header.flags.hmac
                            || packet.header.flags.xtea
                            || packet.header.flags.rdp,
                    ) << 1),
                payload: packet.payload,
            })),
        }
    }
}

fn payload(nonce: &[u8; 8], sequence: usize, length: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..length).map(|n| n as u8).collect();
    data[..8].copy_from_slice(nonce);
    data[8..16].copy_from_slice(&(sequence as u64).to_be_bytes());
    data
}

#[derive(Default)]
struct Stats {
    sent: Vec<(Instant, bool)>,
    received: usize,
    duplicate: usize,
    reordered: usize,
    late: usize,
    ignored: usize,
    highest: Option<usize>,
    rtt_sum: f64,
    rtt_min: Option<f64>,
    rtt_max: f64,
}

impl Stats {
    fn reply(&mut self, args: &Args, nonce: &[u8; 8], reply: Reply, now: Instant) {
        let data = &reply.payload;
        if reply.source != args.dest_addr
            || reply.destination != args.src_addr
            || reply.sport != args.dest_port
            || reply.flags != u8::from(!args.no_crc)
            || data.len() != args.reply_size() - args.overhead()
            || &data[..8] != nonce
        {
            self.ignored += 1;
            return;
        }
        let sequence = u64::from_be_bytes(data[8..16].try_into().unwrap());
        if sequence >= self.sent.len() as u64 {
            self.ignored += 1;
            return;
        }
        let sequence = sequence as usize;
        if reply.dport != args.source_port(sequence)
            || *data != payload(nonce, sequence, data.len())
        {
            self.ignored += 1;
            return;
        }
        let (sent, received) = &mut self.sent[sequence];
        if *received {
            self.duplicate += 1;
            return;
        }
        let rtt = now.duration_since(*sent).as_secs_f64();
        if rtt > args.reply_timeout {
            self.late += 1;
            return;
        }
        *received = true;
        self.received += 1;
        if self.highest.is_some_and(|highest| sequence < highest) {
            self.reordered += 1;
        }
        self.highest = Some(
            self.highest
                .map_or(sequence, |highest| highest.max(sequence)),
        );
        self.rtt_sum += rtt;
        self.rtt_min = Some(self.rtt_min.map_or(rtt, |minimum| minimum.min(rtt)));
        self.rtt_max = self.rtt_max.max(rtt);
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    args.validate()?;
    let mut nonce = [0; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let mut transport = Transport::open(&args).context("open CSP transport")?;
    let mut stats = Stats::default();
    let start = Instant::now();
    let end_tx = start + Duration::from_secs_f64(args.duration);
    let finish = end_tx + Duration::from_secs_f64(args.reply_timeout);
    let interval = Duration::from_secs_f64(args.packet_size as f64 / args.rate());
    let mut next_tx = start;
    let mut next_stats = start + Duration::from_secs_f64(args.stats_period);
    while Instant::now() < finish {
        let now = Instant::now();
        if now >= next_tx && now < end_tx && stats.sent.len() < 1_000_000 {
            let sequence = stats.sent.len();
            transport
                .send(
                    &args,
                    sequence,
                    &payload(&nonce, sequence, args.packet_size - args.overhead()),
                )
                .context("send CSP request")?;
            stats.sent.push((now, false));
            next_tx = Instant::now() + interval;
        }
        if let Some(reply) = transport.poll().context("receive CSP reply")? {
            stats.reply(&args, &nonce, reply, Instant::now());
        } else {
            std::thread::sleep(Duration::from_micros(100));
        }
        if now >= next_stats {
            eprintln!(
                "sent={} received={} pending={}",
                stats.sent.len(),
                stats.received,
                stats.sent.len() - stats.received
            );
            next_stats = now + Duration::from_secs_f64(args.stats_period);
        }
    }
    let lost = stats.sent.len() - stats.received;
    let elapsed = start.elapsed().as_secs_f64();
    let result = json!({
        "transport": if args.device.is_some() { "csp2-kiss" } else if args.can.is_some() { "csp1-can" } else { "csp1-zmq" },
        "sent": stats.sent.len(), "received": stats.received, "lost": lost,
        "duplicates": stats.duplicate, "reordered": stats.reordered, "late": stats.late, "ignored": stats.ignored,
        "tx_seconds": args.duration, "elapsed_seconds": elapsed,
        "tx_csp_bytes_per_second": stats.sent.len() as f64 * args.packet_size as f64 / args.duration,
        "rx_csp_bytes_per_second": stats.received as f64 * args.reply_size() as f64 / elapsed,
        "rx_payload_bytes_per_second": stats.received as f64 * (args.reply_size() - args.overhead()) as f64 / elapsed,
        "rtt_min_ms": stats.rtt_min.map(|rtt| rtt * 1000.0),
        "rtt_mean_ms": (stats.received > 0).then(|| stats.rtt_sum * 1000.0 / stats.received as f64),
        "rtt_max_ms": (stats.received > 0).then_some(stats.rtt_max * 1000.0),
    });
    if args.json {
        println!("{result}");
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    if lost > 0 {
        std::process::exit(2);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Args {
        Args::parse_from(
            [
                "csp-iperf",
                "--device",
                "/unused",
                "--dest-addr",
                "1",
                "--tx-rate",
                "640",
            ]
            .into_iter()
            .chain(extra.iter().copied()),
        )
    }

    #[test]
    fn invalid_parameters_fail_before_open() {
        for extra in [
            vec!["--duration", "NaN"],
            vec!["--reply-timeout", "0"],
            vec!["--packet-size", "25"],
            vec!["--src-port", "64"],
            vec!["--no-crc"],
            vec!["--packet-size", "4093"],
        ] {
            assert!(args(&extra).validate().is_err(), "{extra:?}");
        }
        for rate in [0.0, -1.0, f64::NAN, f64::INFINITY, 1e100] {
            let mut args = args(&[]);
            args.tx_rate = Some(rate);
            assert!(args.validate().is_err());
        }
    }

    fn reply(args: &Args, sequence: usize) -> Reply {
        Reply {
            source: 1,
            destination: 30,
            sport: 1,
            dport: args.source_port(sequence),
            flags: 1,
            payload: payload(&[7; 8], sequence, args.reply_size() - args.overhead()),
        }
    }

    #[test]
    fn reorder_duplicates_wrong_peer_corruption_and_tail_loss() {
        let args = args(&[]);
        let now = Instant::now();
        let mut stats = Stats {
            sent: vec![(now, false); 4],
            ..Stats::default()
        };
        let mut wrong = reply(&args, 0);
        wrong.source = 3;
        stats.reply(&args, &[7; 8], wrong, now);
        let mut corrupt = reply(&args, 0);
        corrupt.payload[20] ^= 1;
        stats.reply(&args, &[7; 8], corrupt, now);
        for sequence in [2, 0, 2] {
            stats.reply(&args, &[7; 8], reply(&args, sequence), now);
        }
        assert_eq!(
            (
                stats.received,
                stats.reordered,
                stats.duplicate,
                stats.ignored
            ),
            (2, 1, 1, 2)
        );
        assert_eq!(stats.sent.len() - stats.received, 2);
    }

    #[test]
    fn silence_and_late_replies_remain_lost() {
        let args = args(&[]);
        let now = Instant::now();
        let mut stats = Stats {
            sent: vec![(now, false); 2],
            ..Stats::default()
        };
        assert_eq!(stats.sent.len() - stats.received, 2);
        stats.reply(
            &args,
            &[7; 8],
            reply(&args, 0),
            now + Duration::from_secs(2),
        );
        assert_eq!((stats.received, stats.late), (0, 1));
    }
}
