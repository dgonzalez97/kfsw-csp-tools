# csp-tools

This is a Rust crate that contains some CLI tools for the [Cubesat Space
Protocol](https://en.wikipedia.org/wiki/Cubesat_Space_Protocol) (CSP). It can
also be used as a library for processing CSP and related protocols.

The tools included are:

- `cspdump`. A tool similar to `tcpdump`. It receives CSP packets from a ZMQ
  socket or a CAN interface and writes them to a PCAP file.

- `csp-iperf`. A tool similar to `iperf`. It sends CSP packets through a ZMQ
  socket or a CAN interface, expects these packets to be replied by a ping
  service, and measures throughput, RTT and lost packets.

- `csp-ping-server`. A tool that implements a ping service. It can be used in
  combination with `csp-iperf` to perform network performance measurements.

## K-FSW CSP 2 over KISS

`csp-kiss` works directly with a K-FSW Linux node's CSP PTY or its serial KISS
link. The original CAN/ZMQ tools below remain CSP 1 tools.

```bash
cargo build --locked --release --bin csp-kiss
target/release/csp-kiss --device /dev/pts/7 ping --node 1 --count 5
target/release/csp-kiss --device /dev/pts/7 ifstat --node 1 --interface KISS
target/release/csp-kiss --device /dev/pts/7 logs --node 1 --output logs.jsonl
target/release/csp-kiss --device /dev/pts/7 discover --nodes 1,2 --output nodes.jsonl
target/release/csp-kiss --device /dev/pts/7 dump --seconds 10 --pcap-file traffic.pcap
```

Rust 1.88 or newer is required. The serial source address defaults to 16 and
baud rate to 115200. Node addresses span 0..16383. Ping verifies the entire
reply and fails on loss. CMP statistics require a known interface name of at
most ten bytes; unknown interfaces time out. Only one process can own the
serial link at a time.

`logs` reads the last 1–32 K-FSW messages (`--count`, default 32), filtered by
`--min-level` (0 debug through 3 error). The node needs K-FSW log history and
its CSP server, on port 13 unless overridden with `logs --port`. Each JSONL
capture contains start/log/end records. Check the final `complete` field:
packet loss, a busy writer overwriting requested history, or a timeout fails
the command and leaves partial output. `text_hex` retains the exact bytes;
`text` decodes UTF-8 with replacement. History is RAM-only and reads do not
consume it. The global `--timeout-ms` bounds the entire transfer.

`discover` pings an explicit list or `--range first:last`, then requests CMP
identity. Lists/ranges are limited to 64 unicast addresses and must exclude
the local source address and 16383. `--budget-ms` (default 5000) bounds the
whole run, while `--timeout-ms` bounds each exchange. Results distinguish
identified nodes, reachable nodes without identity, invalid ping replies,
no reply and nodes not queried before the deadline. An unanswered node does
not fail an otherwise complete inventory; an expired budget with remaining
nodes does. It follows configured CSP routes and does not implement IP ARP.

Both commands write JSON lines to stdout or an exclusive-create `--output`
file. Every record is flushed. Interrupted commands leave partial output
without a successful final marker. Neither command changes node clocks.

Dump sends nothing, records the node's outgoing traffic, and fails on an empty
capture. Trigger traffic through the node's console or configure HK beacons.
It writes a new PCAP with LINKTYPE_USER0 (147): each record contains the exact
CSP 2 header and payload, including any CSP checksum. KISS framing and the
outer checksum are removed after validation. The CSP 1/ZMQ dissector below
is not a decoder for these captures.

`cargo test --locked` checks framing, CRCs, address bounds and CMP validation.
K-FSW's `tests/diagnostics-smoke.py` additionally exercises real native_sim PTYs.

## Wireshark dissector

This repository also contains a Wireshark Lua dissector that can parse CSP and
RDP packets (in this context, RDP is the [reliable datagram
protocol](https://github.com/libcsp/libcsp/blob/develop/src/csp_rdp.c) used in
CSP for sequence controlled reliable delivery). The dissector can be installed
by running

```
just install-wireshark
```

Running this requires [just](github.com/casey/just).

There are also some recommended Wireshark coloring rules in
[wireshark-dissector/coloring-rules](./wireshark-dissector/coloring-rules). These
can be imported into Wireshark by going to "View > Coloring Rules..." and
clicking on "Import...".

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
