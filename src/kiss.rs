//! CSP 2 packets over libcsp's CRC-protected KISS serial link.

use anyhow::{Result, ensure};

const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
const FEND: u8 = 0xc0;
const FESC: u8 = 0xdb;
/// Maximum decoded frame, including both CRCs.
pub const MAX_FRAME: usize = 4096;

/// A validated CSP 2 packet, without the KISS checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Network-order CSP header and payload, including any CSP checksum.
    bytes: Vec<u8>,
}

impl Packet {
    /// Build a normal-priority request with CSP CRC32 enabled.
    pub fn request(
        source: u16,
        destination: u16,
        sport: u8,
        dport: u8,
        payload: &[u8],
    ) -> Result<Self> {
        ensure!(
            source < 16384 && destination < 16384 && sport < 64 && dport < 64,
            "invalid CSP address or port"
        );
        ensure!(payload.len() + 14 <= MAX_FRAME, "packet too large");
        let header = (2u64 << 46)
            | (u64::from(destination) << 32)
            | (u64::from(source) << 18)
            | (u64::from(dport) << 12)
            | (u64::from(sport) << 6)
            | 1;
        let mut bytes = header.to_be_bytes()[2..].to_vec();
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&CRC.checksum(payload).to_be_bytes());
        Ok(Self { bytes })
    }

    /// Validate and remove the KISS checksum while preserving original CSP bytes.
    pub fn from_kiss(frame: &[u8]) -> Result<Self> {
        ensure!(
            (10..=MAX_FRAME).contains(&frame.len()),
            "invalid CSP/KISS frame length"
        );
        check_crc(&frame[6..])?;
        let bytes = frame[..frame.len() - 4].to_vec();
        if bytes[5] & 1 != 0 {
            check_crc(&bytes[6..])?;
        }
        Ok(Self { bytes })
    }

    fn header(&self) -> u64 {
        let mut header = [0u8; 8];
        header[2..].copy_from_slice(&self.bytes[..6]);
        u64::from_be_bytes(header)
    }

    /// Original network-order CSP header, payload and optional checksum.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Source node.
    pub fn source(&self) -> u16 {
        ((self.header() >> 18) & 0x3fff) as u16
    }
    /// Destination node.
    pub fn destination(&self) -> u16 {
        ((self.header() >> 32) & 0x3fff) as u16
    }
    /// Source port.
    pub fn source_port(&self) -> u8 {
        ((self.header() >> 6) & 0x3f) as u8
    }
    /// Destination port.
    pub fn destination_port(&self) -> u8 {
        ((self.header() >> 12) & 0x3f) as u8
    }
    /// CSP flags.
    pub fn flags(&self) -> u8 {
        self.bytes[5] & 0x3f
    }
    /// Payload, excluding the CSP checksum when present.
    pub fn payload(&self) -> &[u8] {
        let end = self.bytes.len() - if self.flags() & 1 != 0 { 4 } else { 0 };
        &self.bytes[6..end]
    }
    /// Encode a KISS data frame with its mandatory payload checksum.
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = self.bytes.clone();
        raw.extend_from_slice(&CRC.checksum(&self.bytes[6..]).to_be_bytes());
        let mut wire = vec![FEND, 0];
        for byte in raw {
            match byte {
                FEND => wire.extend_from_slice(&[FESC, 0xdc]),
                FESC => wire.extend_from_slice(&[FESC, 0xdd]),
                _ => wire.push(byte),
            }
        }
        wire.push(FEND);
        wire
    }
}

fn check_crc(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() >= 4, "missing CRC32C");
    let (payload, checksum) = bytes.split_at(bytes.len() - 4);
    ensure!(
        CRC.checksum(payload).to_be_bytes() == checksum,
        "CRC32C mismatch"
    );
    Ok(())
}

/// Streaming bounded KISS decoder. Invalid frames are discarded through FEND.
#[derive(Default)]
pub struct Decoder {
    frame: Vec<u8>,
    started: bool,
    escaped: bool,
    command: bool,
}

impl Decoder {
    /// Consume one byte and return a complete unescaped frame when available.
    pub fn feed(&mut self, byte: u8) -> Option<Vec<u8>> {
        if byte == FEND {
            let complete = self.started && !self.command && !self.escaped && !self.frame.is_empty();
            let frame = std::mem::take(&mut self.frame);
            self.started = true;
            self.escaped = false;
            self.command = true;
            return complete.then_some(frame);
        }
        if !self.started {
            return None;
        }
        if self.command {
            self.command = false;
            self.started = byte == 0;
            return None;
        }
        if self.escaped {
            self.escaped = false;
            match byte {
                0xdc => self.frame.push(FEND),
                0xdd => self.frame.push(FESC),
                _ => self.started = false,
            }
        } else if byte == FESC {
            self.escaped = true;
        } else {
            self.frame.push(byte);
        }
        if self.frame.len() > MAX_FRAME {
            self.started = false;
        }
        if !self.started {
            self.frame.clear();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(wire: &[u8]) -> Vec<Vec<u8>> {
        let mut decoder = Decoder::default();
        wire.iter().filter_map(|&b| decoder.feed(b)).collect()
    }

    #[test]
    fn csp2_addresses_escapes_and_crc() {
        let packet = Packet::request(1234, 16383, 40, 14, &[0xc0, 0xdb, 1]).unwrap();
        let frames = decode(&packet.encode());
        let received = Packet::from_kiss(&frames[0]).unwrap();
        assert_eq!(received, packet);
        assert_eq!(received.source(), 1234);
        assert_eq!(received.destination(), 16383);
        assert_eq!(received.source_port(), 40);
        assert_eq!(received.destination_port(), 14);
        assert_eq!(received.payload(), &[0xc0, 0xdb, 1]);
        assert_eq!(CRC.checksum(b"123456789"), 0xe3069283);
    }

    #[test]
    fn malformed_frames_resynchronize() {
        let good = Packet::request(16, 1, 40, 1, b"hello").unwrap().encode();
        for mut bad in [
            vec![FEND, 1, 1],
            vec![FEND, 0, FESC, 0x12],
            vec![FEND, 0, 1, FESC],
            [vec![FEND, 0], vec![1; MAX_FRAME + 1]].concat(),
        ] {
            bad.extend_from_slice(&good);
            let frames = decode(&bad);
            assert_eq!(frames.len(), 1);
            assert!(Packet::from_kiss(&frames[0]).is_ok());
        }
    }

    #[test]
    fn both_checksums_and_bounds_are_checked() {
        assert!(Packet::request(16384, 1, 40, 1, &[]).is_err());
        assert!(Packet::request(1, 1, 64, 1, &[]).is_err());
        assert!(Packet::from_kiss(&[0; 9]).is_err());
        let wire = Packet::request(16, 1, 40, 1, b"hello").unwrap().encode();
        let mut frame = decode(&wire).remove(0);
        frame[6] ^= 1;
        assert!(Packet::from_kiss(&frame).is_err());
        let n = frame.len();
        let checksum = CRC.checksum(&frame[6..n - 4]).to_be_bytes();
        frame[n - 4..].copy_from_slice(&checksum);
        assert!(Packet::from_kiss(&frame).is_err());
    }
}
