use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use csp_tools::kiss::{Decoder, Packet};
use pcap_file::{
    DataLink,
    pcap::{PcapHeader, PcapPacket, PcapWriter},
};
use serialport::SerialPort;
use std::{
    fs::OpenOptions,
    io,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[path = "csp-kiss/history.rs"]
mod history;
#[path = "csp-kiss/neighbors.rs"]
mod neighbors;

/// CSP 2 diagnostics on a libcsp KISS serial device or native_sim PTY.
#[derive(Parser)]
struct Args {
    #[arg(long)]
    device: String,
    #[arg(long, default_value_t = 115200)]
    baud: u32,
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u16).range(0..16384))]
    source: u16,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=60000))]
    timeout_ms: u32,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Retrieve recent K-FSW text logs as JSON lines.
    Logs(history::Args),
    /// Query a bounded list of CSP nodes and save their identities as JSON lines.
    Neighbors(neighbors::Args),
    /// Measure ping round trips. A missing or corrupted reply fails the run.
    Ping {
        #[arg(long, value_parser = clap::value_parser!(u16).range(0..16384))]
        node: u16,
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=10000))]
        count: u32,
        /// Payload bytes (excludes the header and checksums).
        #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u16).range(12..=240))]
        size: u16,
    },
    /// Read a named interface's counters using CMP.
    Ifstat {
        #[arg(long, value_parser = clap::value_parser!(u16).range(0..16384))]
        node: u16,
        #[arg(long)]
        interface: String,
    },
    /// Passively capture CSP 2 packets to a new PCAP (LINKTYPE_USER0).
    Dump {
        #[arg(long)]
        pcap_file: PathBuf,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=86400))]
        seconds: u32,
    },
}

fn receive(
    port: &mut dyn SerialPort,
    decoder: &mut Decoder,
    deadline: Instant,
) -> Result<Option<Packet>> {
    let mut byte = [0u8; 1];
    while Instant::now() < deadline {
        port.set_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50))
                .max(Duration::from_millis(1)),
        )?;
        match port.read(&mut byte) {
            Ok(0) => anyhow::bail!("serial device closed"),
            Ok(_) => {
                if let Some(frame) = decoder.feed(byte[0]) {
                    match Packet::from_kiss(&frame) {
                        Ok(packet) => return Ok(Some(packet)),
                        Err(error) => eprintln!("dropped frame: {error}"),
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(None)
}

fn exchange(
    port: &mut dyn SerialPort,
    decoder: &mut Decoder,
    request: &Packet,
    timeout: Duration,
) -> Result<Packet> {
    let deadline = Instant::now() + timeout;
    port.write_all(&request.encode())?;
    port.flush()?;
    receive_reply(port, decoder, request, deadline)?.context("no matching reply before timeout")
}

fn receive_reply(
    port: &mut dyn SerialPort,
    decoder: &mut Decoder,
    request: &Packet,
    deadline: Instant,
) -> Result<Option<Packet>> {
    while let Some(reply) = receive(port, decoder, deadline)? {
        if reply.source() == request.destination()
            && reply.destination() == request.source()
            && reply.source_port() == request.destination_port()
            && reply.destination_port() == request.source_port()
            && reply.flags() == 1
        {
            return Ok(Some(reply));
        }
    }
    Ok(None)
}

fn json_line(output: &mut dyn io::Write, value: &serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn output_file(path: &Option<PathBuf>) -> Result<Box<dyn io::Write>> {
    Ok(match path {
        Some(path) => Box::new(OpenOptions::new().write(true).create_new(true).open(path)?),
        None => Box::new(io::stdout()),
    })
}

fn print_ifstat(payload: &[u8], interface: &str) -> Result<()> {
    ensure!(
        payload.len() == 53 && payload[..2] == [0xff, 3],
        "invalid CMP reply"
    );
    let mut name = [0u8; 11];
    name[..interface.len()].copy_from_slice(interface.as_bytes());
    ensure!(
        payload[2..2 + interface.len() + 1] == name[..interface.len() + 1],
        "interface mismatch"
    );
    print!("interface={interface}");
    for (name, bytes) in [
        "tx", "rx", "txerr", "rxerr", "drop", "autherr", "frame", "txbytes", "rxbytes", "irq",
    ]
    .iter()
    .zip(payload[13..].as_chunks::<4>().0)
    {
        print!(" {name}={}", u32::from_be_bytes(*bytes));
    }
    println!();
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    match &args.command {
        Command::Neighbors(options) => {
            options.nodes(args.source)?;
        }
        Command::Logs(options) => ensure!(
            options.node != args.source,
            "source and destination must differ"
        ),
        _ => {}
    }
    let timeout = Duration::from_millis(u64::from(args.timeout_ms));
    let mut port = serialport::new(&args.device, args.baud)
        .timeout(Duration::from_millis(50).min(timeout))
        .open()
        .with_context(|| format!("opening {}", args.device))?;
    let mut decoder = Decoder::default();
    match args.command {
        Command::Logs(options) => {
            history::run(&mut *port, &mut decoder, args.source, timeout, options)?
        }
        Command::Neighbors(options) => {
            neighbors::run(&mut *port, &mut decoder, args.source, timeout, options)?
        }
        Command::Ping { node, count, size } => {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
            for sequence in 0..count {
                let mut payload = vec![0xa5; usize::from(size)];
                payload[..8].copy_from_slice(&nonce.to_be_bytes());
                payload[8..12].copy_from_slice(&sequence.to_be_bytes());
                let request =
                    Packet::request(args.source, node, 40 + (sequence % 24) as u8, 1, &payload)?;
                let start = Instant::now();
                let reply = exchange(&mut *port, &mut decoder, &request, timeout)?;
                ensure!(reply.payload() == payload, "ping payload mismatch");
                println!(
                    "ping node={node} seq={sequence} bytes={size} rtt_ms={:.3}",
                    start.elapsed().as_secs_f64() * 1000.0
                );
            }
            println!("PING RESULT: PASS received={count}");
        }
        Command::Ifstat { node, interface } => {
            ensure!(
                !interface.is_empty() && interface.len() <= 10 && !interface.contains('\0'),
                "interface must be 1..10 bytes without NUL"
            );
            let mut payload = vec![0u8; 53];
            payload[1] = 3;
            payload[2..2 + interface.len()].copy_from_slice(interface.as_bytes());
            let request = Packet::request(args.source, node, 40, 0, &payload)?;
            let reply = exchange(&mut *port, &mut decoder, &request, timeout)?;
            print_ifstat(reply.payload(), &interface)?;
        }
        Command::Dump { pcap_file, seconds } => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(pcap_file)?;
            let mut writer = PcapWriter::with_header(
                file,
                PcapHeader {
                    datalink: DataLink::USER0,
                    ..Default::default()
                },
            )?;
            let deadline = Instant::now() + Duration::from_secs(u64::from(seconds));
            let mut count = 0;
            while let Some(packet) = receive(&mut *port, &mut decoder, deadline)? {
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;
                writer.write_packet(&PcapPacket::new(
                    timestamp,
                    packet.bytes().len() as u32,
                    packet.bytes(),
                ))?;
                count += 1;
            }
            ensure!(count != 0, "no packets captured");
            println!("CAPTURE RESULT: PASS packets={count}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_reply_bounds_and_identity() {
        let mut reply = vec![0u8; 53];
        reply[..2].copy_from_slice(&[0xff, 3]);
        reply[2..6].copy_from_slice(b"KISS");
        assert!(print_ifstat(&reply, "KISS").is_ok());
        assert!(print_ifstat(&reply[..52], "KISS").is_err());
        assert!(print_ifstat(&reply, "LOOP").is_err());
        reply[6] = b'x';
        assert!(print_ifstat(&reply, "KISS").is_err());
        reply[6] = 0;
        reply[0] = 0;
        assert!(print_ifstat(&reply, "KISS").is_err());
        reply[0] = 0xff;
        reply[1] = 1;
        assert!(print_ifstat(&reply, "KISS").is_err());
    }
}
