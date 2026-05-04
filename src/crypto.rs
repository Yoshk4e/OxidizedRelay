use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

/// Per-session ChaCha20 decryption state.
///
/// RFC 7539 parameters:
///   key   = 32-byte session key
///   nonce = 12-byte IV
///
/// **Wire model:**
/// The server runs ONE ChaCha20 keystream per (key, nonce) pair, starting at
/// block 1 (byte offset 64, block 0 is reserved by the AEAD-style construction).
/// That single keystream is consumed *contiguously* across every encrypted frame
/// in the TCP stream, in send order: each frame's `head ++ body` is XOR'd with
/// the next `hl + bl` bytes of keystream.
///
/// The 1-byte `hl` and 2-byte little-endian `bl` length prefix between frames
/// is sent in the clear and does NOT consume keystream.
///
/// The very first frame of the stream (the login response) is plaintext on the
/// wire and does NOT consume keystream either; the cipher pointer therefore
/// remains at byte 64 when frame #1 begins.
///
/// Because the keystream is stateful, callers MUST construct one
/// `FrameCrypto` per direction of each TCP stream and feed frames through
/// `decrypt_frame` in arrival order, there is no per-frame independent
/// decryption.
pub struct FrameCrypto {
    cipher: ChaCha20,
}

impl FrameCrypto {
    /// Build a fresh crypto state positioned at the first encrypted byte
    /// (block 1 / offset 64).
    pub fn new(key: &[u8; 32], iv: &[u8; 12]) -> Self {
        let mut cipher = ChaCha20::new(
            chacha20::Key::from_slice(key),
            chacha20::Nonce::from_slice(iv),
        );
        // Skip block 0 once, at construction.  All subsequent decryption
        // continues from block 1 onwards across every frame.
        cipher.seek(64u64);
        Self { cipher }
    }

    /// Decrypt `data` in-place, advancing the per-stream keystream by
    /// `data.len()` bytes.
    pub fn decrypt_frame(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        self.cipher.apply_keystream(data);
    }
}
