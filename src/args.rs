use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "OxidizedRelay",
    about = "ChaCha20-encrypted protobuf PCAP analyzer",
    long_about = "Decrypts and parses ChaCha20-encrypted protobuf game-protocol traffic from a PCAP file."
)]
pub struct Args {
    /// Input PCAP file (.pcap format; convert .pcapng first with tshark)
    pub pcap: PathBuf,

    /// Session key, hex string, 64 chars (32 bytes). Prompted interactively if omitted.
    #[arg(short = 'k', long, value_name = "HEX64")]
    pub key: Option<String>,

    /// Server encryption IV/nonce, hex string, 24 chars (12 bytes).
    /// Prompted interactively if omitted.
    #[arg(short = 'i', long, value_name = "HEX16")]
    pub iv: Option<String>,

    /// Only process TCP streams where one endpoint is this IP address (the server).
    /// (future plan), Streams in the direction client→host are labelled C→S; host→client are S→C.
    #[arg(long, value_name = "IP")]
    pub host: Option<String>,

    /// Path to a .proto file whose message definitions should be used to decode frame bodies.
    /// Requires --msgid-map to associate message-IDs with type names.
    #[arg(long, value_name = "FILE")]
    pub proto: Option<PathBuf>,

    /// Path to a file containing msgid:TypeName pairs.
    /// Each line should be "msgid:TypeName".
    /// Only needed when --proto is supplied.
    #[arg(long, value_name = "FILE")]
    pub msgid_map: Option<PathBuf>,

    /// Also print frames whose CSHead cannot be parsed or whose CRC does not match.
    /// By default these are silently skipped as non-protocol traffic.
    #[arg(long)]
    pub show_invalid: bool,

    /// Dump the raw (post-decryption) hex bytes for every frame.
    #[arg(long)]
    pub raw: bool,

    /// Treat this many leading frames per stream as plaintext (default: 1).
    #[arg(long, value_name = "N", default_value = "1")]
    pub plaintext_frames: usize,
}

pub fn resolve_key(args: &Args) -> anyhow::Result<[u8; 32]> {
    let hex_str = match &args.key {
        Some(s) => s.clone(),
        None => dialoguer::Password::new()
            .with_prompt("Session key (hex, 64 chars / 32 bytes)")
            .interact()?,
    };
    let bytes = hex::decode(hex_str.trim())?;
    anyhow::ensure!(
        bytes.len() == 32,
        "Key must be exactly 32 bytes (64 hex chars), got {}",
        bytes.len()
    );
    Ok(bytes.try_into().unwrap())
}

pub fn resolve_iv(args: &Args) -> anyhow::Result<[u8; 12]> {
    let hex_str = match &args.iv {
        Some(s) => s.clone(),
        None => dialoguer::Password::new()
            .with_prompt("Encryption IV / server nonce (hex, 24 chars / 12 bytes)")
            .interact()?,
    };
    let bytes = hex::decode(hex_str.trim())?;
    anyhow::ensure!(
        bytes.len() == 12,
        "IV must be exactly 12 bytes (16 hex chars), got {}",
        bytes.len()
    );
    Ok(bytes.try_into().unwrap())
}

pub fn resolve_msgid_map(args: &Args) -> anyhow::Result<Option<String>> {
    if let Some(path) = &args.msgid_map {
        let content = fs::read_to_string(path)?;
        // Convert multi-line file to comma-separated string for Schema::load compatibility
        let map_str = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(",");
        Ok(Some(map_str))
    } else {
        Ok(None)
    }
}
