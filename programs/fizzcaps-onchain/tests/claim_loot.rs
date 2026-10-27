//! Executes claim_loot against a local banks server (solana-program-test).
//!
//! Requires the SBF artifacts:
//!   target/deploy/fizzcaps_onchain.so
//!   target/deploy/mpl_token_metadata.so
//!
//! Build with:
//!   cargo-build-sbf --manifest-path programs/fizzcaps-onchain/Cargo.toml --features localnet --tools-version v1.58 --no-rustup-override

use fizzcaps_onchain::voucher::{anchor_discriminator, LootVoucherV1};
use solana_ed25519_program::new_ed25519_instruction_with_signature;
use solana_program::bpf_loader_upgradeable::{get_program_data_address, UpgradeableLoaderState};
use solana_program_test::*;
use solana_sdk::{
    account::AccountSharedData,
    clock::Clock,
    compute_budget::ComputeBudgetInstruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use spl_token::{instruction as token_ix, state::Account as TokenAccountState};
use std::path::PathBuf;

const NOW: i64 = 1_700_000_100;
const METADATA_PROGRAM_ID: Pubkey = solana_sdk::pubkey!(
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
);

fn so_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy")
}

fn point_at_shared_objects() {
    let dir = so_dir();
    assert!(
        dir.join("fizzcaps_onchain.so").is_file(),
        "missing {} — build the SBF program first",
        dir.join("fizzcaps_onchain.so").display()
    );
    assert!(
        dir.join("mpl_token_metadata.so").is_file(),
        "missing Metaplex token-metadata program at {}",
        dir.join("mpl_token_metadata.so").display()
    );
    std::env::set_var("SBF_OUT_DIR", &dir);
}

async fn send(
    ctx: &mut ProgramTestContext,
    ixs: &[solana_sdk::instruction::Instruction],
    signers: &[&Keypair],
) -> solana_banks_interface::BanksTransactionResultWithMetadata {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
    all.extend_from_slice(ixs);
    let tx = Transaction::new_signed_with_payer(&all, Some(&ctx.payer.pubkey()), signers, blockhash);
    ctx.banks_client
        .process_transaction_with_metadata(tx)
        .await
        .unwrap()
}

fn logs(res: &solana_banks_interface::BanksTransactionResultWithMetadata) -> String {
    res.metadata
        .as_ref()
        .map(|m| m.log_messages.join("\n"))
        .unwrap_or_default()
}

fn retarget_upgrade_authority(data: &mut [u8], authority: &Pubkey) {
    let mut cursor = std::io::Cursor::new(&data[..]);
    let state: UpgradeableLoaderState = bincode::deserialize_from(&mut cursor).unwrap();
    let header_len = cursor.position() as usize;
    let UpgradeableLoaderState::ProgramData { slot, .. } = state else {
        panic!("program data account is not ProgramData");
    };
    let new_state = UpgradeableLoaderState::ProgramData {
        slot,
        upgrade_authority_address: Some(*authority),
    };
    let header = bincode::serialize(&new_state).unwrap();
    assert_eq!(header.len(), header_len, "upgrade-authority header changed size");
    data[..header_len].copy_from_slice(&header);
}

fn ix_data(name: &str, args: &[u8]) -> Vec<u8> {
    let mut data = anchor_discriminator(name).to_vec();
    data.extend_from_slice(args);
    data
}

fn ix(program: Pubkey, data: Vec<u8>, accounts: Vec<solana_sdk::instruction::AccountMeta>) -> solana_sdk::instruction::Instruction {
    solana_sdk::instruction::Instruction {
        program_id: program,
        accounts,
        data,
    }
}

fn meta(pubkey: Pubkey, is_signer: bool, is_writable: bool) -> solana_sdk::instruction::AccountMeta {
    solana_sdk::instruction::AccountMeta { pubkey, is_signer, is_writable }
}

fn voucher(id_byte: u8, loot_id: u64) -> LootVoucherV1 {
    let mut voucher_id = [0u8; 16];
    voucher_id[0] = id_byte;
    LootVoucherV1 {
        voucher_id,
        loot_id,
        lat_e6: 36_115_900,
        lng_e6: -115_173_400,
        location_hint: "Vault 77".into(),
        issued_at: NOW,
        expires_at: NOW + 300,
    }
}

fn ed25519_ix(server: &Keypair, message: &[u8]) -> solana_sdk::instruction::Instruction {
    let sig = server.sign_message(message);
    let sig_bytes: [u8; 64] = sig.as_ref().try_into().unwrap();
    let ix = new_ed25519_instruction_with_signature(message, &sig_bytes, &server.pubkey().to_bytes());
    solana_sdk::instruction::Instruction {
        program_id: ix.program_id,
        accounts: ix.accounts,
        data: ix.data,
    }
}

async fn token_amount(ctx: &mut ProgramTestContext, ata: &Pubkey) -> u64 {
    let account = ctx.banks_client.get_account(*ata).await.unwrap().unwrap();
    TokenAccountState::unpack(&account.data).unwrap().amount
}

#[tokio::test]
async fn claim_loot_happy_path_replay_wrong_signer_and_missing_ed25519() {
    point_at_shared_objects();
    let program_id = fizzcaps_onchain::ID;
    let mut pt = ProgramTest::default();
    pt.prefer_bpf(true);
    pt.add_upgradeable_program_to_genesis("fizzcaps_onchain", &program_id);
    pt.add_upgradeable_program_to_genesis("mpl_token_metadata", &METADATA_PROGRAM_ID);

    let mut ctx = pt.start_with_context().await;
    let mut clock = ctx.banks_client.get_sysvar::<Clock>().await.unwrap();
    clock.unix_timestamp = NOW;
    ctx.set_sysvar(&clock);

    let player = Keypair::from_bytes(&ctx.payer.to_bytes()).unwrap();
    let server = Keypair::new();
    let program_data = get_program_data_address(&program_id);

    let mut program_data_account = ctx
        .banks_client
        .get_account(program_data)
        .await
        .unwrap()
        .expect("ProgramData");
    retarget_upgrade_authority(&mut program_data_account.data, &player.pubkey());
    ctx.set_account(
        &program_data,
        &AccountSharedData::from(program_data_account),
    );

    let (caps_mint, _) = Pubkey::find_program_address(&[b"caps-mint"], &program_id);
    let init_caps = ix(
        program_id,
        ix_data("initialize_caps", &[]),
        vec![
            meta(player.pubkey(), true, true),
            meta(program_id, false, false),
            meta(program_data, false, false),
            meta(caps_mint, false, true),
            meta(spl_token::id(), false, false),
            meta(solana_sdk::system_program::id(), false, false),
        ],
    );
    let init_caps_res = send(&mut ctx, &[init_caps], &[&player]).await;
    assert!(
        init_caps_res.result.is_ok(),
        "initialize_caps failed:\n{}",
        logs(&init_caps_res)
    );

    let (config, _) = Pubkey::find_program_address(&[b"fizz-config"], &program_id);
    let local = Pubkey::new_unique();
    let dev = Pubkey::new_unique();
    let mut init_args = Vec::new();
    init_args.extend_from_slice(server.pubkey().as_ref());
    init_args.extend_from_slice(dev.as_ref());
    init_args.extend_from_slice(local.as_ref());
    let fizz_init = ix(
        program_id,
        ix_data("fizz_init", &init_args),
        vec![
            meta(player.pubkey(), true, true),
            meta(program_id, false, false),
            meta(program_data, false, false),
            meta(config, false, true),
            meta(player.pubkey(), false, false),
            meta(caps_mint, false, false),
            meta(solana_sdk::system_program::id(), false, false),
        ],
    );
    let init_res = send(&mut ctx, &[fizz_init], &[&player]).await;
    assert!(init_res.result.is_ok(), "fizz_init failed:\n{}", logs(&init_res));

    let (loot_auth, _) = Pubkey::find_program_address(&[b"loot-mint-auth"], &program_id);
    let caps_ata = get_associated_token_address(&player.pubkey(), &caps_mint);
    let create_caps_ata = create_associated_token_account(
        &player.pubkey(),
        &player.pubkey(),
        &caps_mint,
        &spl_token::id(),
    );
    let mint_caps = token_ix::mint_to(
        &spl_token::id(),
        &caps_mint,
        &caps_ata,
        &player.pubkey(),
        &[],
        200 * 1_000_000_000,
    )
    .unwrap();
    let funded = send(&mut ctx, &[create_caps_ata, mint_caps], &[&player]).await;
    assert!(funded.result.is_ok(), "fund CAPS failed:\n{}", logs(&funded));
    assert_eq!(token_amount(&mut ctx, &caps_ata).await, 200 * 1_000_000_000);

    async fn prepare_loot(ctx: &mut ProgramTestContext, player: &Keypair, loot_auth: &Pubkey) -> (Keypair, Pubkey) {
        let loot_mint = Keypair::new();
        let rent = ctx.banks_client.get_rent().await.unwrap();
        let space = spl_token::state::Mint::LEN as u64;
        let create = system_instruction::create_account(
            &player.pubkey(),
            &loot_mint.pubkey(),
            rent.minimum_balance(space as usize),
            space,
            &spl_token::id(),
        );
        let init = token_ix::initialize_mint(
            &spl_token::id(),
            &loot_mint.pubkey(),
            loot_auth,
            Some(loot_auth),
            0,
        )
        .unwrap();
        let ata = get_associated_token_address(&player.pubkey(), &loot_mint.pubkey());
        let create_ata = create_associated_token_account(
            &player.pubkey(),
            &player.pubkey(),
            &loot_mint.pubkey(),
            &spl_token::id(),
        );
        let res = send(ctx, &[create, init, create_ata], &[player, &loot_mint]).await;
        assert!(res.result.is_ok(), "prepare loot mint failed:\n{}", logs(&res));
        (loot_mint, ata)
    }

    fn claim_ix(
        player: &Pubkey,
        config: Pubkey,
        caps_mint: Pubkey,
        caps_ata: Pubkey,
        loot_mint: Pubkey,
        loot_ata: Pubkey,
        loot_auth: Pubkey,
        voucher: &LootVoucherV1,
    ) -> solana_sdk::instruction::Instruction {
        let (voucher_claim, _) = Pubkey::find_program_address(
            &[b"voucher-claim", voucher.voucher_id.as_ref()],
            &fizzcaps_onchain::ID,
        );
        let (loot_id_claim, _) = Pubkey::find_program_address(
            &[b"loot-id-claim", &voucher.loot_id.to_le_bytes()],
            &fizzcaps_onchain::ID,
        );
        let (metadata, _) = Pubkey::find_program_address(
            &[
                b"metadata",
                METADATA_PROGRAM_ID.as_ref(),
                loot_mint.as_ref(),
            ],
            &METADATA_PROGRAM_ID,
        );
        let (master_edition, _) = Pubkey::find_program_address(
            &[
                b"metadata",
                METADATA_PROGRAM_ID.as_ref(),
                loot_mint.as_ref(),
                b"edition",
            ],
            &METADATA_PROGRAM_ID,
        );
        ix(
            fizzcaps_onchain::ID,
            voucher.instruction_data(),
            vec![
                meta(*player, true, true),
                meta(config, false, false),
                meta(caps_mint, false, true),
                meta(caps_ata, false, true),
                meta(loot_mint, false, true),
                meta(loot_ata, false, true),
                meta(loot_auth, false, false),
                meta(metadata, false, true),
                meta(master_edition, false, true),
                meta(voucher_claim, false, true),
                meta(loot_id_claim, false, true),
                meta(spl_token::id(), false, false),
                meta(spl_associated_token_account::id(), false, false),
                meta(METADATA_PROGRAM_ID, false, false),
                meta(solana_sdk::system_program::id(), false, false),
                meta(solana_sdk::sysvar::instructions::id(), false, false),
            ],
        )
    }

    let (loot_mint, loot_ata) = prepare_loot(&mut ctx, &player, &loot_auth).await;
    let v = voucher(1, 42);
    let message = v.message(&program_id, &player.pubkey());
    let happy = send(
        &mut ctx,
        &[
            ed25519_ix(&server, &message),
            claim_ix(
                &player.pubkey(),
                config,
                caps_mint,
                caps_ata,
                loot_mint.pubkey(),
                loot_ata,
                loot_auth,
                &v,
            ),
        ],
        &[&player],
    )
    .await;
    assert!(happy.result.is_ok(), "happy path failed:\n{}", logs(&happy));
    assert_eq!(token_amount(&mut ctx, &loot_ata).await, 1);
    assert_eq!(token_amount(&mut ctx, &caps_ata).await, 100 * 1_000_000_000);

    let replay = send(
        &mut ctx,
        &[
            ed25519_ix(&server, &message),
            claim_ix(
                &player.pubkey(),
                config,
                caps_mint,
                caps_ata,
                loot_mint.pubkey(),
                loot_ata,
                loot_auth,
                &v,
            ),
        ],
        &[&player],
    )
    .await;
    assert!(replay.result.is_err(), "replay must fail:\n{}", logs(&replay));
    let replay_logs = logs(&replay);
    assert!(
        replay_logs.contains("already in use"),
        "replay logs:\n{replay_logs}"
    );

    let (loot_mint_bad, loot_ata_bad) = prepare_loot(&mut ctx, &player, &loot_auth).await;
    let v_bad = voucher(2, 43);
    let bad_message = v_bad.message(&program_id, &player.pubkey());
    let attacker = Keypair::new();
    let wrong = send(
        &mut ctx,
        &[
            ed25519_ix(&attacker, &bad_message),
            claim_ix(
                &player.pubkey(),
                config,
                caps_mint,
                caps_ata,
                loot_mint_bad.pubkey(),
                loot_ata_bad,
                loot_auth,
                &v_bad,
            ),
        ],
        &[&player],
    )
    .await;
    assert!(wrong.result.is_err(), "wrong signer must fail");
    assert!(
        logs(&wrong).contains("WrongVoucherSigner") || logs(&wrong).contains("not the configured server key"),
        "wrong signer logs:\n{}",
        logs(&wrong)
    );

    let (loot_mint_miss, loot_ata_miss) = prepare_loot(&mut ctx, &player, &loot_auth).await;
    let v_miss = voucher(3, 44);
    let missing = send(
        &mut ctx,
        &[claim_ix(
            &player.pubkey(),
            config,
            caps_mint,
            caps_ata,
            loot_mint_miss.pubkey(),
            loot_ata_miss,
            loot_auth,
            &v_miss,
        )],
        &[&player],
    )
    .await;
    assert!(missing.result.is_err(), "missing ed25519 must fail");
    assert!(
        logs(&missing).contains("MissingEd25519Ix") || logs(&missing).contains("Missing Ed25519"),
        "missing ed25519 logs:\n{}",
        logs(&missing)
    );
}
