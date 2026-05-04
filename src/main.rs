mod args;
mod crypto;
mod display;
mod frame;
mod proto;
mod tcp;

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use clap::Parser;
use pcap_file::pcap::PcapReader;

use crate::args::{Args, resolve_iv, resolve_key, resolve_msgid_map};
use crate::crypto::FrameCrypto;
use crate::display::FrameInfo;
use crate::tcp::{StreamKey, TcpTracker};

fn main() -> Result<()> {
    let args = Args::parse();

    // Note: the actual FrameCrypto instance is built per-stream below, because
    // ChaCha20 keystream state must advance contiguously across the frames of
    // a single TCP direction.  Sharing one cipher across streams would burn
    // keystream from the wrong direction and corrupt every frame after the
    // first one.
    let key = resolve_key(&args)?;
    let iv = resolve_iv(&args)?;
    let msgid_map = resolve_msgid_map(&args)?;

    let schema = match (&args.proto, &msgid_map) {
        (Some(proto_path), Some(map_str)) => {
            let s = proto::Schema::load(proto_path, map_str)
                .with_context(|| "Failed to load proto schema")?;
            println!(
                "Loaded schema from {:?} with {} message type(s).",
                proto_path,
                s.messages.len()
            );
            Some(s)
        }
        (Some(_proto_path), None) => {
            eprintln!(
                "Warning: --proto supplied but --msgid-map is missing. \
                 Field names will NOT be resolved."
            );
            None
        }
        _ => None,
    };

    let host_filter: Option<IpAddr> = args
        .host
        .as_deref()
        .map(|s| s.parse().with_context(|| format!("Invalid host IP: {}", s)))
        .transpose()?;

    let path = &args.pcap;
    let file = File::open(path).with_context(|| format!("Cannot open {:?}", path))?;

    let mut f = BufReader::new(file);
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .context("Failed to read file magic")?;
    f.seek(SeekFrom::Start(0))?;

    let file = File::open(path)?;
    let mut tracker = TcpTracker::new();

    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0xc3, 0xd4]
        | [0x4d, 0x3c, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d] => {
            let mut reader = PcapReader::new(file).context("Failed to open pcap")?;
            let link_type = reader.header().datalink;
            while let Some(pkt) = reader.next_packet() {
                let pkt = pkt.context("Corrupt packet")?;
                if let Err(e) = handle_packet(&pkt.data, link_type, &host_filter, &mut tracker) {
                    eprintln!("Packet parse error: {:#}", e);
                }
            }
        }
        [0x0a, 0x0d, 0x0d, 0x0a] => {
            bail!(
                "pcapng format detected. \
                 Please convert to pcap first:\n  \
                 tshark -F pcap -r input.pcapng -w output.pcap"
            );
        }
        _ => bail!("Unrecognized file format (magic = {:02X?})", magic),
    }

    let mut total_frames = 0usize;
    let mut valid = 0usize;
    let mut invalid = 0usize;
    let mut crc_fail = 0usize;

    let mut streams: Vec<&crate::tcp::TcpStream> = tracker.streams().collect();
    streams.sort_by_key(|s| s.key.label());

    for stream in streams {
        let frames = frame::parse_frames(&stream.data);
        if frames.is_empty() {
            continue;
        }

        display::print_stream_header(&stream.key, frames.len());

        // One ChaCha20 keystream per stream direction, advanced across every
        // encrypted frame in send order.  Plaintext frames do not consume any
        // keystream, they are passed through untouched.
        let mut crypto = FrameCrypto::new(&key, &iv);

        for raw_frame in &frames {
            total_frames += 1;

            let is_plaintext = raw_frame.index < args.plaintext_frames;

            // Decrypt: head and body are decrypted together as one contiguous blob.
            let mut combined = Vec::with_capacity(raw_frame.head.len() + raw_frame.body.len());
            combined.extend_from_slice(&raw_frame.head);
            combined.extend_from_slice(&raw_frame.body);

            if !is_plaintext {
                crypto.decrypt_frame(&mut combined);
            }

            let hl = raw_frame.head.len();
            let dec_head = &combined[..hl];
            let dec_body = &combined[hl..];

            let cshead = match proto::parse_cshead(dec_head) {
                Some(h) => h,
                None => {
                    invalid += 1;
                    if args.show_invalid {
                        display::print_invalid_frame(raw_frame.index, dec_head, dec_body);
                    }
                    continue;
                }
            };

            let computed_crc = crc32fast::hash(dec_body);
            let crc_ok = computed_crc == cshead.checksum;
            if !crc_ok {
                crc_fail += 1;
            }

            let schema_info = schema.as_ref().and_then(|s| s.get(cshead.msgid));
            let type_name = schema_info.map(|(n, _)| n.as_str());
            let field_names = schema_info.map(|(_, m)| m);
            let body_fields = proto::decode_body(dec_body, field_names);

            display::print_frame(FrameInfo {
                frame_index: raw_frame.index,
                is_plaintext,
                head: &cshead,
                body_fields: body_fields.as_ref(),
                type_name,
                crc_ok,
                raw_head: dec_head,
                raw_body: dec_body,
                show_raw: args.raw,
            });

            valid += 1;
        }
    }

    display::print_summary(total_frames, valid, invalid, crc_fail);
    Ok(())
}

fn handle_packet(
    data: &[u8],
    link_type: pcap_file::DataLink,
    host_filter: &Option<IpAddr>,
    tracker: &mut TcpTracker,
) -> Result<()> {
    let sliced = match link_type {
        pcap_file::DataLink::ETHERNET => {
            etherparse::SlicedPacket::from_ethernet(data).map_err(|e| anyhow::anyhow!("{:?}", e))?
        }
        pcap_file::DataLink::LINUX_SLL => etherparse::SlicedPacket::from_linux_sll(data)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?,
        pcap_file::DataLink::NULL | pcap_file::DataLink::LOOP => {
            if data.len() < 4 {
                return Ok(());
            }
            etherparse::SlicedPacket::from_ip(&data[4..]).map_err(|e| anyhow::anyhow!("{:?}", e))?
        }
        pcap_file::DataLink::RAW => {
            etherparse::SlicedPacket::from_ip(data).map_err(|e| anyhow::anyhow!("{:?}", e))?
        }
        other => {
            bail!("Unsupported link type: {:?}", other);
        }
    };

    let (src_ip, dst_ip) = match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(ip)) => (
            IpAddr::V4(ip.header().source_addr()),
            IpAddr::V4(ip.header().destination_addr()),
        ),
        Some(etherparse::NetSlice::Ipv6(ip)) => (
            IpAddr::V6(ip.header().source_addr()),
            IpAddr::V6(ip.header().destination_addr()),
        ),
        _ => return Ok(()),
    };

    let matches_host = host_filter
        .map(|host| src_ip == host || dst_ip == host)
        .unwrap_or(true);

    if !matches_host {
        return Ok(());
    }

    let (tcp, payload) = match &sliced.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => (tcp, tcp.payload()),
        _ => return Ok(()),
    };

    if payload.is_empty() {
        return Ok(());
    }

    let key = StreamKey::new(src_ip, tcp.source_port(), dst_ip, tcp.destination_port());
    tracker.feed(key, tcp.sequence_number(), payload);
    Ok(())
}
