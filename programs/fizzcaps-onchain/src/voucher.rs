//! Loot voucher v1: binary message, Ed25519 instruction parser, replay accounts.
//!
//! The Ed25519 precompile header is `num_sigs: u8`, `padding: u8`, then one
//! 14-byte `Ed25519SignatureOffsets` record. Byte 2 is the **signature**
//! offset. The public key offset is the next field, at byte 6. An earlier
//! parser treated byte 2 as the pubkey offset and compared signature bytes
//! to the server key.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked, load_instruction_at_checked,
};
use solana_sdk_ids::ed25519_program;
use solana_sha256_hasher::hash;

pub const VOUCHER_DOMAIN: &[u8; 24] = b"FIZZCAPS:LOOT_VOUCHER:v1";
pub const VOUCHER_MSG_LEN: usize = 169;
pub const MAX_HINT_LEN: usize = 64;
/// Security requirement: vouchers live at most 5 minutes (the spec draft used 3600).
pub const MAX_VOUCHER_TTL_SECS: i64 = 300;
pub const MAX_CLOCK_SKEW_SECS: i64 = 30;

/// Anchor instruction discriminator: first 8 bytes of sha256("global:{name}").
pub fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hashed = hash(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hashed.as_ref()[..8]);
    out
}

pub const VOUCHER_CLAIM_SEED: &[u8] = b"voucher-claim";
pub const LOOT_ID_CLAIM_SEED: &[u8] = b"loot-id-claim";

/// 1 = mainnet-beta, 2 = devnet, 3 = localnet. Compile-time, never client-supplied.
pub const CLUSTER_TAG: u8 = if cfg!(feature = "mainnet") {
    1
} else if cfg!(feature = "devnet") {
    2
} else if cfg!(feature = "localnet") {
    3
} else {
    0
};

/// Pick the server key for the cluster this binary was built for.
pub fn active_server_key(localnet: Pubkey, devnet: Pubkey, mainnet: Pubkey) -> Pubkey {
    match CLUSTER_TAG {
        1 => mainnet,
        2 => devnet,
        3 => localnet,
        _ => Pubkey::default(),
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LootVoucherV1 {
    pub voucher_id: [u8; 16],
    pub loot_id: u64,
    pub lat_e6: i32,
    pub lng_e6: i32,
    /// UTF-8 hint, at most 64 bytes. The signed message commits to sha256(hint).
    pub location_hint: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl LootVoucherV1 {
    pub fn check_shape_and_time(&self, now: i64) -> Result<()> {
        require!(
            self.location_hint.len() <= MAX_HINT_LEN,
            crate::ErrorCode::VoucherBadShape
        );
        require!(
            (-90_000_000..=90_000_000).contains(&self.lat_e6),
            crate::ErrorCode::VoucherBadShape
        );
        require!(
            (-180_000_000..=180_000_000).contains(&self.lng_e6),
            crate::ErrorCode::VoucherBadShape
        );
        let ttl = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or(error!(crate::ErrorCode::VoucherBadShape))?;
        require!(ttl > 0, crate::ErrorCode::VoucherBadShape);
        require!(ttl <= MAX_VOUCHER_TTL_SECS, crate::ErrorCode::VoucherTtlTooLong);
        require!(
            self.issued_at <= now.saturating_add(MAX_CLOCK_SKEW_SECS),
            crate::ErrorCode::VoucherNotYetValid
        );
        require!(now <= self.expires_at, crate::ErrorCode::VoucherExpired);
        Ok(())
    }

    /// Rebuild the 169-byte message. `program_id` is `crate::ID` and `player`
    /// is the transaction signer. Neither value is read from the client.
    pub fn message(&self, program_id: &Pubkey, player: &Pubkey) -> [u8; VOUCHER_MSG_LEN] {
        let mut m = [0u8; VOUCHER_MSG_LEN];
        let mut o = 0usize;
        let mut put = |b: &[u8]| {
            let end = o + b.len();
            m[o..end].copy_from_slice(b);
            o = end;
        };
        put(VOUCHER_DOMAIN);
        put(&[CLUSTER_TAG]);
        put(program_id.as_ref());
        put(player.as_ref());
        put(&self.voucher_id);
        put(&self.loot_id.to_le_bytes());
        put(&self.lat_e6.to_le_bytes());
        put(&self.lng_e6.to_le_bytes());
        put(hash(self.location_hint.as_bytes()).as_ref());
        put(&self.issued_at.to_le_bytes());
        put(&self.expires_at.to_le_bytes());
        assert_eq!(o, VOUCHER_MSG_LEN, "voucher message layout drift");
        m
    }

    pub fn instruction_data(&self) -> Vec<u8> {
        let mut data = anchor_discriminator("claim_loot").to_vec();
        data.extend(self.try_to_vec().expect("voucher borsh"));
        data
    }
}

/// Parse one Ed25519 precompile instruction's data.
/// Returns `(pubkey, signature, message)` slices living inside `d`.
///
/// Offsets are read from the header. They are not hard-coded, and the
/// public key is **not** taken from the signature-offset field at byte 2.
pub fn parse_ed25519_ix_data(d: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    require!(d.len() >= 16, crate::ErrorCode::Ed25519BadLayout);
    require!(d[0] == 1, crate::ErrorCode::Ed25519BadLayout);
    let rd = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
    // Layout after the 2-byte header (num_sigs, padding):
    //   2 signature_offset, 4 signature_instruction_index,
    //   6 public_key_offset, 8 public_key_instruction_index,
    //  10 message_data_offset, 12 message_data_size, 14 message_instruction_index.
    let (sig_off, sig_ix) = (rd(2), rd(4));
    let (pk_off, pk_ix) = (rd(6), rd(8));
    let (msg_off, msg_len, msg_ix) = (rd(10), rd(12), rd(14));
    require!(
        sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX,
        crate::ErrorCode::Ed25519BadLayout
    );
    require!(
        msg_len as usize == VOUCHER_MSG_LEN,
        crate::ErrorCode::Ed25519BadLayout
    );
    let take = |off: u16, len: u16| -> Result<&[u8]> {
        let end = off
            .checked_add(len)
            .ok_or(error!(crate::ErrorCode::Ed25519BadLayout))? as usize;
        let start = off as usize;
        d.get(start..end).ok_or(error!(crate::ErrorCode::Ed25519BadLayout))
    };
    Ok((take(pk_off, 32)?, take(sig_off, 64)?, take(msg_off, msg_len)?))
}

pub fn verify_voucher_ed25519(
    ix_sysvar: &AccountInfo,
    expected_signer: &Pubkey,
    expected_msg: &[u8],
) -> Result<()> {
    require!(
        *expected_signer != Pubkey::default(),
        crate::ErrorCode::WrongVoucherSigner
    );
    require!(
        expected_msg.len() == VOUCHER_MSG_LEN,
        crate::ErrorCode::VoucherMessageMismatch
    );
    let cur = load_current_index_checked(ix_sysvar)? as usize;
    let cur_ix = load_instruction_at_checked(cur, ix_sysvar)?;
    require_keys_eq!(cur_ix.program_id, crate::ID, crate::ErrorCode::CpiNotAllowed);
    require!(cur > 0, crate::ErrorCode::MissingEd25519Ix);
    let ed = load_instruction_at_checked(cur - 1, ix_sysvar)?;
    require_keys_eq!(ed.program_id, ed25519_program::ID, crate::ErrorCode::MissingEd25519Ix);
    require!(ed.accounts.is_empty(), crate::ErrorCode::Ed25519BadLayout);
    let (pk, _sig, msg) = parse_ed25519_ix_data(&ed.data)?;
    require!(pk == expected_signer.as_ref(), crate::ErrorCode::WrongVoucherSigner);
    require!(msg == expected_msg, crate::ErrorCode::VoucherMessageMismatch);
    Ok(())
}

#[account]
pub struct VoucherClaim {
    pub voucher_id: [u8; 16],
    pub player: Pubkey,
    pub loot_id: u64,
    pub claimed_at: i64,
    pub bump: u8,
}

impl VoucherClaim {
    pub const SIZE: usize = 8 + 16 + 32 + 8 + 8 + 1;
}

/// One claim per loot id, independent of the voucher id replay account.
#[account]
pub struct LootIdClaim {
    pub loot_id: u64,
    pub player: Pubkey,
    pub voucher_id: [u8; 16],
    pub claimed_at: i64,
    pub bump: u8,
}

impl LootIdClaim {
    pub const SIZE: usize = 8 + 8 + 32 + 16 + 8 + 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn json_string(json: &str, key: &str) -> String {
        let pat = format!("\"{key}\": \"");
        let i = json.find(&pat).unwrap_or_else(|| panic!("missing {key}"));
        let rest = &json[i + pat.len()..];
        let end = rest.find('"').unwrap();
        rest[..end].to_string()
    }

    fn sample() -> LootVoucherV1 {
        let mut voucher_id = [0u8; 16];
        voucher_id.copy_from_slice(&decode_hex("000102030405060708090a0b0c0d0e0f"));
        LootVoucherV1 {
            voucher_id,
            loot_id: 42,
            lat_e6: 37_774_930,
            lng_e6: -122_419_400,
            location_hint: "Vault 77".to_string(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        }
    }

    fn player() -> Pubkey {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(1);
        }
        Pubkey::new_from_array(b)
    }

    #[test]
    fn golden_message_matches_js_fixture() {
        assert_eq!(CLUSTER_TAG, 3, "golden vector is built for the localnet feature");
        assert_eq!(VOUCHER_MSG_LEN, 169);
        let fixture = include_str!("../../../anchor-tests/fixtures/voucher_v1_golden.json");
        let msg = sample().message(&crate::ID, &player());
        assert_eq!(msg.len(), 169);
        assert_eq!(hex_encode(&msg), json_string(fixture, "messageHex"));
        assert_eq!(
            crate::ID,
            Pubkey::from_str(&json_string(fixture, "programId")).unwrap()
        );
    }

    #[test]
    fn message_len_and_hint_bounds() {
        let now = 1_700_000_000;
        let mut ok = sample();
        ok.location_hint = "x".repeat(64);
        ok.issued_at = now;
        ok.expires_at = now + 300;
        assert!(ok.check_shape_and_time(now).is_ok());
        assert_eq!(ok.message(&crate::ID, &player()).len(), 169);
        ok.location_hint = "x".repeat(65);
        assert!(err_has(ok.check_shape_and_time(now), "VoucherBadShape"));
    }

    #[test]
    fn parser_reads_pubkey_not_signature_offset() {
        let fixture = include_str!("../../../anchor-tests/fixtures/ed25519_ix_v1.json");
        let raw = decode_hex(&json_string(fixture, "dataHex"));
        let (pk, sig, msg) = parse_ed25519_ix_data(&raw).unwrap();
        // web3.js Ed25519Program.createInstructionWithPublicKey layout.
        assert_eq!(pk, &raw[16..48], "pubkey lives at offset 16");
        assert_eq!(sig, &raw[48..112], "signature lives at offset 48");
        assert_eq!(msg.len(), 169);
        assert_eq!(msg, &raw[112..112 + 169]);
        // Byte 2 is the signature offset (48). Using it as the pubkey offset
        // yields the first 32 signature bytes, which are not the pubkey.
        let sig_off = u16::from_le_bytes([raw[2], raw[3]]) as usize;
        assert_eq!(sig_off, 48);
        assert_ne!(&raw[sig_off..sig_off + 32], pk);
        let pk_off = u16::from_le_bytes([raw[6], raw[7]]) as usize;
        assert_eq!(pk_off, 16);
        assert_eq!(&raw[pk_off..pk_off + 32], pk);
    }

    #[test]
    fn parser_rejects_bad_layouts() {
        let pk = [0xABu8; 32];
        let sig = [0xCDu8; 64];
        let msg = [0x11u8; 169];
        let ok = pack(&pk, &sig, &msg, 1, u16::MAX, 16, 48, 112, 169);
        assert!(parse_ed25519_ix_data(&ok).is_ok());

        for n in [0u8, 2] {
            let mut bad = ok.clone();
            bad[0] = n;
            assert!(parse_ed25519_ix_data(&bad).is_err(), "num_sigs={n}");
        }
        // Any instruction index other than u16::MAX is rejected.
        let bad_ix = pack(&pk, &sig, &msg, 1, 1, 16, 48, 112, 169);
        assert!(parse_ed25519_ix_data(&bad_ix).is_err());
        // Offset past the buffer. `pack` grows the data to fit, so poke the
        // header of a valid instruction instead of asking pack to allocate.
        let mut bad_off = ok.clone();
        bad_off[6..8].copy_from_slice(&1000u16.to_le_bytes());
        assert!(parse_ed25519_ix_data(&bad_off).is_err());
        // u16 offset + length overflow.
        let bad_ovf = pack(&pk, &sig, &msg, 1, u16::MAX, 16, 65_500, 112, 169);
        assert!(parse_ed25519_ix_data(&bad_ovf).is_err());
        assert!(parse_ed25519_ix_data(&[1, 0, 0, 0]).is_err());
        // Message length must be exactly 169.
        let mut short_msg = msg.to_vec();
        short_msg.pop();
        let bad_len = pack(&pk, &sig, &short_msg, 1, u16::MAX, 16, 48, 112, 168);
        assert!(parse_ed25519_ix_data(&bad_len).is_err());
    }

    #[test]
    fn time_rules() {
        let now: i64 = 1_700_000_100;
        let mut v = sample();
        let cases: &[(i64, i64, &str, bool)] = &[
            (now - 100, now - 10, "VoucherExpired", false),
            (now + 31, now + 31 + 300, "VoucherNotYetValid", false),
            (now, now, "VoucherBadShape", false),
            (now, now + 301, "VoucherTtlTooLong", false),
            (now, now + 300, "", true),
            (now + 30, now + 30 + 300, "", true),
            (now + 31, now + 31 + 60, "VoucherNotYetValid", false),
        ];
        for (issued, expires, needle, ok) in cases {
            v.issued_at = *issued;
            v.expires_at = *expires;
            v.location_hint = "Vault 77".into();
            let res = v.check_shape_and_time(now);
            if *ok {
                assert!(res.is_ok(), "expected ok for {issued}..{expires}: {res:?}");
            } else {
                assert!(err_has(res, needle), "expected {needle} for {issued}..{expires}");
            }
        }
    }

    #[test]
    fn active_key_follows_localnet_feature() {
        assert_eq!(CLUSTER_TAG, 3);
        let local = Pubkey::new_from_array([1u8; 32]);
        let dev = Pubkey::new_from_array([2u8; 32]);
        let main = Pubkey::new_from_array([3u8; 32]);
        assert_eq!(active_server_key(local, dev, main), local);
        assert_ne!(active_server_key(local, dev, main), dev);
    }

    fn pack(
        pk: &[u8; 32],
        sig: &[u8; 64],
        msg: &[u8],
        num_sigs: u8,
        ix_index: u16,
        pk_off: u16,
        sig_off: u16,
        msg_off: u16,
        msg_len: u16,
    ) -> Vec<u8> {
        let mut d = vec![num_sigs, 0];
        d.extend_from_slice(&sig_off.to_le_bytes());
        d.extend_from_slice(&ix_index.to_le_bytes());
        d.extend_from_slice(&pk_off.to_le_bytes());
        d.extend_from_slice(&ix_index.to_le_bytes());
        d.extend_from_slice(&msg_off.to_le_bytes());
        d.extend_from_slice(&msg_len.to_le_bytes());
        d.extend_from_slice(&ix_index.to_le_bytes());
        let need = std::cmp::max(
            d.len(),
            std::cmp::max(pk_off as usize + 32, sig_off as usize + 64),
        );
        let need = std::cmp::max(need, msg_off as usize + msg.len());
        if d.len() < need {
            d.resize(need, 0);
        }
        if (pk_off as usize) + 32 <= d.len() {
            d[pk_off as usize..pk_off as usize + 32].copy_from_slice(pk);
        }
        if (sig_off as usize) + 64 <= d.len() {
            d[sig_off as usize..sig_off as usize + 64].copy_from_slice(sig);
        }
        if (msg_off as usize) + msg.len() <= d.len() {
            d[msg_off as usize..msg_off as usize + msg.len()].copy_from_slice(msg);
        }
        d
    }

    fn err_has(res: Result<()>, needle: &str) -> bool {
        match res {
            Ok(()) => false,
            Err(e) => format!("{e:?}").contains(needle),
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }
}
