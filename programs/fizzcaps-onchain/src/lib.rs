#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{bpf_loader_upgradeable, program_option::COption};
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, burn, Burn, Mint, MintTo, Token, TokenAccount, Transfer},
};
use mpl_token_metadata::{
    instructions::CreateV1CpiBuilder,
    types::{Creator, PrintSupply, TokenStandard},
    ID as METADATA_PROGRAM_ID,
};

// Exactly one cluster feature. Zero or two or more is a compile error.
// There is no default = ["localnet"] feature.
#[cfg(not(any(
    all(feature = "localnet", not(feature = "devnet"), not(feature = "mainnet")),
    all(feature = "devnet", not(feature = "localnet"), not(feature = "mainnet")),
    all(feature = "mainnet", not(feature = "localnet"), not(feature = "devnet")),
)))]
compile_error!(
    "exactly one cluster feature must be set: localnet, devnet, or mainnet. Do not set default = [\"localnet\"]."
);

// Each cluster has its own program id. These are not the canonical ids in
// Unwrenchable/ATOMIC-FIZZ-CAPS-VAULT-77-WASTELAND-GPS. Do not deploy this copy.
// CI checks that each declare_id matches the matching Anchor.toml section.
#[cfg(all(feature = "localnet", not(feature = "devnet"), not(feature = "mainnet")))]
declare_id!("3mPuzEmF6YrMP3Lfn4qm9TY2tSKsanJDhsr6ZkSbSURP"); // cluster:localnet
#[cfg(all(feature = "devnet", not(feature = "localnet"), not(feature = "mainnet")))]
declare_id!("9uc8Tvas9j4SYnvHYYiCbQiv7DqdzkYQU4vv5mag5bcA"); // cluster:devnet
#[cfg(all(feature = "mainnet", not(feature = "localnet"), not(feature = "devnet")))]
declare_id!("6DnVzBtMzQcnSUeLGX93d68WZ8cz4qwq6GQvbhhnA2s8"); // cluster:mainnet

pub mod voucher;
use voucher::{
    verify_voucher_ed25519, LootIdClaim, LootVoucherV1, VoucherClaim, CLUSTER_TAG,
    LOOT_ID_CLAIM_SEED, VOUCHER_CLAIM_SEED,
};

// ============ SEEDS ============
const CAPS_MINT_SEEDS: &[u8] = b"caps-mint";
const LOOT_MINT_AUTHORITY_SEEDS: &[u8] = b"loot-mint-auth";
const FIZZ_CONFIG_SEEDS: &[u8] = b"fizz-config";
const FIZZ_CURVE_SEEDS: &[u8] = b"fizz-curve";
const FIZZ_SOL_VAULT_SEEDS: &[u8] = b"fizz-sol-vault";
const FIZZ_ADMIN_SEEDS: &[u8] = b"fizz-admin";
// SEC-AUDIT-011 NOTE: fizz_init is guarded by the PDA `init` constraint (Anchor
// ensures the account can only be initialized once) and requires a Signer.
// For additional protection against front-running on deployment, call fizz_init
// in the same transaction as the program deployment or use a private RPC endpoint.

// ============ FIZZ.FUN CONSTANTS ============
/// Total supply per token: 1 billion with 9 decimals
const TOTAL_SUPPLY: u64 = 1_000_000_000_000_000_000;
/// Tokens available in bonding curve: 800 million
const CURVE_SUPPLY: u64 = 800_000_000_000_000_000;
/// SOL needed to graduate: 85 SOL
const GRADUATION_SOL: u64 = 85_000_000_000;
/// Virtual SOL for initial price: 30 SOL
const VIRTUAL_SOL: u64 = 30_000_000_000;
/// Trading fee: 1% (100 basis points)
const FEE_BPS: u64 = 100;
/// CAPS decimals
const CAPS_DECIMALS: u64 = 1_000_000_000;
/// CAPS required to launch
const CAPS_TO_LAUNCH: u64 = 1000 * CAPS_DECIMALS;
/// Standard launch fee (burned)
const CAPS_LAUNCH_FEE: u64 = 100 * CAPS_DECIMALS;
/// Veteran threshold (10k CAPS)
const CAPS_VETERAN_THRESHOLD: u64 = 10_000 * CAPS_DECIMALS;
/// Veteran launch fee (burned)
const CAPS_VETERAN_FEE: u64 = 50 * CAPS_DECIMALS;

#[program]
pub mod fizzcaps_onchain {
    use super::*;

    // ============ EXISTING: LOOT CLAIM ============
    
    pub fn claim_loot(ctx: Context<ClaimLoot>, voucher: LootVoucherV1) -> Result<()> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProgramPaused);

        let fee_amount = 100 * 10u64.pow(9);
        let now = Clock::get()?.unix_timestamp;

        // Shape and time window are checked against fields that are also
        // covered by the server signature below.
        voucher.check_shape_and_time(now)?;

        // Rebuild the message on-chain. The player binding is the transaction
        // signer, not a field the caller can swap after signing.
        let msg = voucher.message(&crate::ID, &ctx.accounts.player.key());
        verify_voucher_ed25519(
            &ctx.accounts.instructions_sysvar.to_account_info(),
            &ctx.accounts.config.server_key(),
            &msg,
        )?;

        // Replay accounts were created by `init`. A second claim of the same
        // voucher_id or loot_id fails in the system program ("already in use")
        // before this body runs; a later error rolls the inits back.
        let player = ctx.accounts.player.key();
        let vc = &mut ctx.accounts.voucher_claim;
        vc.voucher_id = voucher.voucher_id;
        vc.player = player;
        vc.loot_id = voucher.loot_id;
        vc.claimed_at = now;
        vc.bump = ctx.bumps.voucher_claim;

        let lc = &mut ctx.accounts.loot_id_claim;
        lc.loot_id = voucher.loot_id;
        lc.player = player;
        lc.voucher_id = voucher.voucher_id;
        lc.claimed_at = now;
        lc.bump = ctx.bumps.loot_id_claim;

        burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.caps_mint.to_account_info(),
                    from: ctx.accounts.player_caps_ata.to_account_info(),
                    authority: ctx.accounts.player.to_account_info(),
                },
            ),
            fee_amount,
        )?;

        let name = format!("Fizz Cache #{}", voucher.loot_id);
        require!(name.len() <= 32, ErrorCode::VoucherBadShape);

        // Entry constraint requires supply == 0. Mint the single token before
        // CreateV1: that instruction sets the mint authority to none (print
        // supply zero), so a later mint_to cannot succeed. The mint account
        // is already initialized, so it is not a signer of CreateV1.
        // An empty creators list is a Metaplex error (0x25). One unverified
        // creator satisfies the check without a second signature. Collection
        // stays unset: there is no collection mint.
        let loot_auth_bump = ctx.bumps.loot_mint_authority;
        anchor_spl::token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.loot_mint.to_account_info(),
                    to: ctx.accounts.player_loot_ata.to_account_info(),
                    authority: ctx.accounts.loot_mint_authority.to_account_info(),
                },
                &[&[LOOT_MINT_AUTHORITY_SEEDS, &[loot_auth_bump]]],
            ),
            1,
        )?;

        CreateV1CpiBuilder::new(&ctx.accounts.metadata_program.to_account_info())
            .metadata(&ctx.accounts.loot_metadata.to_account_info())
            .master_edition(Some(&ctx.accounts.loot_master_edition.to_account_info()))
            .mint(&ctx.accounts.loot_mint.to_account_info(), false)
            .authority(&ctx.accounts.loot_mint_authority.to_account_info())
            .payer(&ctx.accounts.player.to_account_info())
            .update_authority(&ctx.accounts.loot_mint_authority.to_account_info(), true)
            .system_program(&ctx.accounts.system_program.to_account_info())
            .sysvar_instructions(&ctx.accounts.instructions_sysvar.to_account_info())
            .spl_token_program(Some(&ctx.accounts.token_program.to_account_info()))
            .token_standard(TokenStandard::NonFungible)
            .name(name)
            .symbol("FIZZLOOT".to_string())
            .uri(format!(
                "https://atomicfizzcaps.xyz/loot/{}.json",
                voucher.loot_id
            ))
            .seller_fee_basis_points(0)
            .creators(vec![Creator {
                address: ctx.accounts.loot_mint_authority.key(),
                verified: false,
                share: 100,
            }])
            .is_mutable(false)
            .primary_sale_happened(true)
            .print_supply(PrintSupply::Zero)
            .invoke_signed(&[&[LOOT_MINT_AUTHORITY_SEEDS, &[loot_auth_bump]]])?;

        msg!(
            "Loot #{} claimed by {} at lat_e6={} lng_e6={}",
            voucher.loot_id,
            player,
            voucher.lat_e6,
            voucher.lng_e6
        );

        Ok(())
    }

    // ============ FIZZ.FUN: TOKEN LAUNCHPAD ============

    /// Initialize Fizz.fun configuration.
    /// Signer must be this program's upgrade authority (ProgramData).
    /// One Ed25519 server key is stored per cluster. `claim_loot` reads only
    /// the slot for the cluster this binary was compiled for.
    pub fn fizz_init(
        ctx: Context<FizzInit>,
        server_key_localnet: Pubkey,
        server_key_devnet: Pubkey,
        server_key_mainnet: Pubkey,
    ) -> Result<()> {
        require!(
            server_key_localnet != Pubkey::default()
                && server_key_devnet != Pubkey::default()
                && server_key_mainnet != Pubkey::default(),
            ErrorCode::WrongVoucherSigner
        );
        require!(
            server_key_localnet != server_key_devnet
                && server_key_devnet != server_key_mainnet
                && server_key_localnet != server_key_mainnet,
            ErrorCode::WrongVoucherSigner
        );

        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.treasury = ctx.accounts.treasury.key();
        config.caps_mint = ctx.accounts.caps_mint.key();
        config.server_key_localnet = server_key_localnet;
        config.server_key_devnet = server_key_devnet;
        config.server_key_mainnet = server_key_mainnet;
        config.paused = false;
        config.total_tokens_launched = 0;
        config.total_volume_sol = 0;
        config.total_caps_burned = 0;
        config.admin_usdc_launches = 0;
        config.bump = ctx.bumps.config;

        msg!("Fizz.fun initialized! Treasury: {}", config.treasury);
        Ok(())
    }

    /// Create the CAPS mint at the `caps-mint` PDA. Decimals are 9.
    /// Signer must be this program's upgrade authority.
    pub fn initialize_caps(ctx: Context<InitializeCaps>) -> Result<()> {
        require!(ctx.accounts.caps_mint.decimals == 9, ErrorCode::InvalidCapsMint);
        require!(ctx.accounts.caps_mint.supply == 0, ErrorCode::InvalidCapsMint);
        require!(
            ctx.accounts.caps_mint.freeze_authority.is_none(),
            ErrorCode::InvalidCapsMint
        );
        msg!("CAPS mint {} decimals=9", ctx.accounts.caps_mint.key());
        Ok(())
    }

    /// Rotate the server key for the cluster this binary was compiled for.
    pub fn fizz_set_server_key(ctx: Context<FizzSetServerKey>, new_key: Pubkey) -> Result<()> {
        require!(new_key != Pubkey::default(), ErrorCode::WrongVoucherSigner);
        let config = &mut ctx.accounts.config;
        let old = config.server_key();
        require!(new_key != old, ErrorCode::WrongVoucherSigner);
        config.set_server_key(new_key);
        require!(
            config.server_key_localnet != config.server_key_devnet
                && config.server_key_devnet != config.server_key_mainnet
                && config.server_key_localnet != config.server_key_mainnet,
            ErrorCode::WrongVoucherSigner
        );
        emit!(ServerKeyRotated {
            old,
            new: new_key,
            cluster_tag: CLUSTER_TAG,
        });
        Ok(())
    }

    /// Pause or unpause `claim_loot`. Authority-gated.
    pub fn fizz_set_paused(ctx: Context<FizzSetPaused>, paused: bool) -> Result<()> {
        ctx.accounts.config.paused = paused;
        msg!("fizz claim_loot paused={paused}");
        Ok(())
    }

    /// Add an admin (only authority)
    pub fn fizz_add_admin(ctx: Context<FizzManageAdmin>, admin: Pubkey) -> Result<()> {
        let admin_record = &mut ctx.accounts.admin_record;
        admin_record.admin = admin;
        admin_record.added_at = Clock::get()?.unix_timestamp;
        admin_record.is_active = true;
        admin_record.bump = ctx.bumps.admin_record;
        
        msg!("Fizz.fun admin added: {}", admin);
        Ok(())
    }

    /// Launch a new token (requires 1000+ CAPS)
    /// Name/symbol/uri emitted in event for off-chain indexing (saves rent!)
    pub fn fizz_create_token(
        ctx: Context<FizzCreateToken>,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        // Validate inputs
        require!(name.len() <= 32, FizzError::NameTooLong);
        require!(symbol.len() <= 10, FizzError::SymbolTooLong);
        require!(uri.len() <= 200, FizzError::UriTooLong);

        // 1. Verify CAPS balance >= 1000
        let caps_balance = ctx.accounts.creator_caps_ata.amount;
        require!(caps_balance >= CAPS_TO_LAUNCH, FizzError::InsufficientCapsToLaunch);

        // 2. Calculate launch fee (veterans get discount)
        let launch_fee = if caps_balance >= CAPS_VETERAN_THRESHOLD {
            CAPS_VETERAN_FEE
        } else {
            CAPS_LAUNCH_FEE
        };

        // 3. Burn CAPS launch fee
        token::burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.caps_mint.to_account_info(),
                    from: ctx.accounts.creator_caps_ata.to_account_info(),
                    authority: ctx.accounts.creator.to_account_info(),
                },
            ),
            launch_fee,
        )?;

        // 4. Initialize bonding curve (minimal on-chain data for cheap rent)
        let curve_bump = {
            let curve = &mut ctx.accounts.bonding_curve;
            curve.creator = ctx.accounts.creator.key();
            curve.token_mint = ctx.accounts.token_mint.key();
            curve.sol_reserve = 0;
            curve.token_reserve = CURVE_SUPPLY;
            curve.graduated = false;
            curve.created_at = Clock::get()?.unix_timestamp;
            curve.launch_type = FizzLaunchType::CapsStandard;
            curve.bump = ctx.bumps.bonding_curve;
            curve.bump
        };

        // 5. Mint total supply to curve vault
        token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.token_mint.to_account_info(),
                    to: ctx.accounts.curve_token_vault.to_account_info(),
                    authority: ctx.accounts.bonding_curve.to_account_info(),
                },
                &[&[
                    FIZZ_CURVE_SEEDS,
                    ctx.accounts.token_mint.key().as_ref(),
                    &[curve_bump],
                ]],
            ),
            TOTAL_SUPPLY,
        )?;

        // 6. Update config
        let config = &mut ctx.accounts.config;
        config.total_tokens_launched += 1;
        config.total_caps_burned += launch_fee;

        emit!(FizzTokenCreated {
            mint: ctx.accounts.token_mint.key(),
            creator: ctx.accounts.creator.key(),
            name,
            symbol,
            launch_type: FizzLaunchType::CapsStandard,
            caps_burned: launch_fee,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Admin launch with USDC (pre-mainnet bootstrap)
    pub fn fizz_create_token_admin(
        ctx: Context<FizzCreateTokenAdmin>,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        require!(name.len() <= 32, FizzError::NameTooLong);
        require!(symbol.len() <= 10, FizzError::SymbolTooLong);
        require!(uri.len() <= 200, FizzError::UriTooLong);
        require!(ctx.accounts.admin_record.is_active, FizzError::AdminInactive);

        // Initialize bonding curve (minimal on-chain data, no CAPS burn for admin)
        let curve_bump = {
            let curve = &mut ctx.accounts.bonding_curve;
            curve.creator = ctx.accounts.creator.key();
            curve.token_mint = ctx.accounts.token_mint.key();
            curve.sol_reserve = 0;
            curve.token_reserve = CURVE_SUPPLY;
            curve.graduated = false;
            curve.created_at = Clock::get()?.unix_timestamp;
            curve.launch_type = FizzLaunchType::AdminUSDC; // Clearly marked!
            curve.bump = ctx.bumps.bonding_curve;
            curve.bump
        };

        // Mint total supply to curve vault
        token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.token_mint.to_account_info(),
                    to: ctx.accounts.curve_token_vault.to_account_info(),
                    authority: ctx.accounts.bonding_curve.to_account_info(),
                },
                &[&[
                    FIZZ_CURVE_SEEDS,
                    ctx.accounts.token_mint.key().as_ref(),
                    &[curve_bump],
                ]],
            ),
            TOTAL_SUPPLY,
        )?;

        // Update config
        let config = &mut ctx.accounts.config;
        config.total_tokens_launched += 1;
        config.admin_usdc_launches += 1;

        emit!(FizzTokenCreatedAdmin {
            mint: ctx.accounts.token_mint.key(),
            creator: ctx.accounts.creator.key(),
            name,
            symbol,
            launch_type: FizzLaunchType::AdminUSDC,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Buy tokens from bonding curve (NO CAPS REQUIRED - anyone can trade!)
    pub fn fizz_buy(ctx: Context<FizzBuyTokens>, sol_amount: u64, min_tokens_out: u64) -> Result<()> {
        require!(sol_amount > 0, FizzError::ZeroAmount);

        // Calculate fee (1%)
        let fee = sol_amount.checked_mul(FEE_BPS).unwrap().checked_div(10000).unwrap();
        let sol_after_fee = sol_amount.checked_sub(fee).unwrap();

        // Reads finish before the token CPI so the curve account can sign it.
        let (curve_bump, token_mint_key, tokens_out) = {
            let curve = &ctx.accounts.bonding_curve;
            require!(!curve.graduated, FizzError::TokenGraduated);

            // SEC-AUDIT-001 FIX: use u128 for intermediate AMM calculations.
            // virtual_sol (30e9) * token_reserve (800e15) = 2.4e28 which overflows
            // u64::MAX (1.84e19) by ~5 billion times.  The previous checked_mul
            // returned None → unwrap() panicked → every buy/sell crashed.
            let virtual_sol = (curve.sol_reserve as u128)
                .checked_add(VIRTUAL_SOL as u128)
                .ok_or(FizzError::ArithmeticOverflow)?;
            let k: u128 = virtual_sol
                .checked_mul(curve.token_reserve as u128)
                .ok_or(FizzError::ArithmeticOverflow)?;
            let new_sol = virtual_sol
                .checked_add(sol_after_fee as u128)
                .ok_or(FizzError::ArithmeticOverflow)?;
            let new_tokens = k.checked_div(new_sol).ok_or(FizzError::ArithmeticOverflow)?;
            let tokens_out_u128 = (curve.token_reserve as u128)
                .checked_sub(new_tokens)
                .ok_or(FizzError::ArithmeticOverflow)?;
            let tokens_out = u64::try_from(tokens_out_u128).map_err(|_| error!(FizzError::ArithmeticOverflow))?;

            require!(tokens_out >= min_tokens_out, FizzError::SlippageExceeded);
            require!(tokens_out <= curve.token_reserve, FizzError::InsufficientLiquidity);
            (curve.bump, curve.token_mint, tokens_out)
        };

        // Transfer SOL from buyer to curve vault
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.buyer.to_account_info(),
                    to: ctx.accounts.curve_sol_vault.to_account_info(),
                },
            ),
            sol_after_fee,
        )?;

        // Transfer fee to treasury
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.buyer.to_account_info(),
                    to: ctx.accounts.treasury.to_account_info(),
                },
            ),
            fee,
        )?;

        // Transfer tokens to buyer
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.curve_token_vault.to_account_info(),
                    to: ctx.accounts.buyer_token_ata.to_account_info(),
                    authority: ctx.accounts.bonding_curve.to_account_info(),
                },
                &[&[
                    FIZZ_CURVE_SEEDS,
                    token_mint_key.as_ref(),
                    &[curve_bump],
                ]],
            ),
            tokens_out,
        )?;

        // Update state
        let curve = &mut ctx.accounts.bonding_curve;
        curve.sol_reserve = curve.sol_reserve.checked_add(sol_after_fee).unwrap();
        curve.token_reserve = curve.token_reserve.checked_sub(tokens_out).unwrap();

        let config = &mut ctx.accounts.config;
        config.total_volume_sol = config.total_volume_sol.checked_add(sol_amount).unwrap();

        // Check graduation
        if curve.sol_reserve >= GRADUATION_SOL {
            emit!(FizzReadyToGraduate {
                mint: curve.token_mint,
                sol_raised: curve.sol_reserve,
            });
        }

        emit!(FizzTokenBought {
            mint: curve.token_mint,
            buyer: ctx.accounts.buyer.key(),
            sol_amount: sol_after_fee,
            tokens_received: tokens_out,
        });

        Ok(())
    }

    /// Sell tokens back to curve (NO CAPS REQUIRED)
    pub fn fizz_sell(ctx: Context<FizzSellTokens>, token_amount: u64, min_sol_out: u64) -> Result<()> {
        let curve = &mut ctx.accounts.bonding_curve;
        require!(!curve.graduated, FizzError::TokenGraduated);
        require!(token_amount > 0, FizzError::ZeroAmount);

        // SEC-AUDIT-001 FIX: use u128 for intermediate AMM calculations (same overflow).
        let virtual_sol = (curve.sol_reserve as u128)
            .checked_add(VIRTUAL_SOL as u128)
            .ok_or(FizzError::ArithmeticOverflow)?;
        let k: u128 = virtual_sol
            .checked_mul(curve.token_reserve as u128)
            .ok_or(FizzError::ArithmeticOverflow)?;
        let new_tokens = (curve.token_reserve as u128)
            .checked_add(token_amount as u128)
            .ok_or(FizzError::ArithmeticOverflow)?;
        let new_sol = k.checked_div(new_tokens).ok_or(FizzError::ArithmeticOverflow)?;
        let sol_out_gross_u128 = virtual_sol
            .checked_sub(new_sol)
            .ok_or(FizzError::ArithmeticOverflow)?;
        let sol_out_gross = std::cmp::min(
            u64::try_from(sol_out_gross_u128).map_err(|_| error!(FizzError::ArithmeticOverflow))?,
            curve.sol_reserve,
        );

        // Calculate fee
        let fee = sol_out_gross.checked_mul(FEE_BPS).unwrap().checked_div(10000).unwrap();
        let sol_out = sol_out_gross.checked_sub(fee).unwrap();

        require!(sol_out >= min_sol_out, FizzError::SlippageExceeded);

        // Transfer tokens to curve
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.seller_token_ata.to_account_info(),
                    to: ctx.accounts.curve_token_vault.to_account_info(),
                    authority: ctx.accounts.seller.to_account_info(),
                },
            ),
            token_amount,
        )?;

        // Transfer SOL to seller (from PDA)
        **ctx.accounts.curve_sol_vault.try_borrow_mut_lamports()? -= sol_out;
        **ctx.accounts.seller.try_borrow_mut_lamports()? += sol_out;

        // Transfer fee to treasury
        **ctx.accounts.curve_sol_vault.try_borrow_mut_lamports()? -= fee;
        **ctx.accounts.treasury.try_borrow_mut_lamports()? += fee;

        // Update state
        curve.sol_reserve = curve.sol_reserve.checked_sub(sol_out_gross).unwrap();
        curve.token_reserve = curve.token_reserve.checked_add(token_amount).unwrap();

        emit!(FizzTokenSold {
            mint: curve.token_mint,
            seller: ctx.accounts.seller.key(),
            tokens_sold: token_amount,
            sol_received: sol_out,
        });

        Ok(())
    }

    /// Graduate token to LP (when 85 SOL reached)
    pub fn fizz_graduate(ctx: Context<FizzGraduate>) -> Result<()> {
        let curve = &mut ctx.accounts.bonding_curve;
        require!(!curve.graduated, FizzError::AlreadyGraduated);
        require!(curve.sol_reserve >= GRADUATION_SOL, FizzError::NotReadyToGraduate);

        // Creator bonus (7%)
        let creator_bonus = curve.sol_reserve.checked_mul(7).unwrap().checked_div(100).unwrap();

        // Transfer bonus to creator
        **ctx.accounts.curve_sol_vault.try_borrow_mut_lamports()? -= creator_bonus;
        **ctx.accounts.creator.try_borrow_mut_lamports()? += creator_bonus;

        // Mark graduated
        curve.graduated = true;
        // SEC-AUDIT-003 FIX: graduated_at is now a valid field on FizzBondingCurve.
        curve.graduated_at = Some(Clock::get()?.unix_timestamp);

        emit!(FizzTokenGraduated {
            mint: curve.token_mint,
            creator: curve.creator,
            sol_raised: curve.sol_reserve,
            creator_bonus,
        });

        // SEC-AUDIT-003 FIX: removed curve.symbol reference — symbol is stored
        // off-chain (indexed from FizzTokenCreated events) and does not exist
        // as a field on FizzBondingCurve (would cause a compile error).
        msg!("🎓 Token {} graduated! Creator bonus: {} lamports", curve.token_mint, creator_bonus);
        Ok(())
    }
}

// ============ DATA STRUCTURES ============

/// Launch type for transparency (stored on-chain)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum FizzLaunchType {
    CapsStandard,  // Regular launch (100 CAPS burned)
    CapsVeteran,   // Veteran launch (50 CAPS burned)
    AdminUSDC,     // Admin bootstrap (USDC paid off-chain)
    AdminFree,     // Official tokens
}

/// Fizz.fun global config
#[account]
pub struct FizzConfig {
    pub authority: Pubkey,
    pub treasury: Pubkey,
    pub caps_mint: Pubkey,
    pub total_tokens_launched: u64,
    pub total_volume_sol: u64,
    pub total_caps_burned: u64,
    pub admin_usdc_launches: u64,
    /// Ed25519 voucher signer for the localnet build of this program.
    pub server_key_localnet: Pubkey,
    /// Ed25519 voucher signer for the devnet build.
    pub server_key_devnet: Pubkey,
    /// Ed25519 voucher signer for the mainnet build.
    pub server_key_mainnet: Pubkey,
    /// When true, `claim_loot` rejects every voucher.
    pub paused: bool,
    pub bump: u8,
}

impl FizzConfig {
    /// discriminator + fields. Six pubkeys, four u64s, paused, bump.
    pub const SPACE: usize = 8 + 32 * 6 + 8 * 4 + 1 + 1;

    /// Server key for the cluster this binary was compiled for.
    /// Callers never supply this key to `claim_loot`.
    pub fn server_key(&self) -> Pubkey {
        voucher::active_server_key(
            self.server_key_localnet,
            self.server_key_devnet,
            self.server_key_mainnet,
        )
    }

    pub fn set_server_key(&mut self, key: Pubkey) {
        match CLUSTER_TAG {
            1 => self.server_key_mainnet = key,
            2 => self.server_key_devnet = key,
            _ => self.server_key_localnet = key,
        }
    }
}

/// Admin record
#[account]
pub struct FizzAdminRecord {
    pub admin: Pubkey,
    pub added_at: i64,
    pub is_active: bool,
    pub bump: u8,
}

/// Bonding curve state - OPTIMIZED for minimal rent (~0.002 SOL)
/// Name, symbol, URI stored off-chain (indexed from events)
#[account]
pub struct FizzBondingCurve {
    pub creator: Pubkey,           // 32 bytes
    pub token_mint: Pubkey,        // 32 bytes
    pub sol_reserve: u64,          // 8 bytes
    pub token_reserve: u64,        // 8 bytes
    pub graduated: bool,           // 1 byte
    // SEC-AUDIT-003 FIX: added graduated_at (was referenced in fizz_graduate but
    // missing from the struct — caused compile error and deployment blocker).
    pub graduated_at: Option<i64>, // 9 bytes (1 discriminant + 8 data)
    pub created_at: i64,           // 8 bytes
    pub launch_type: FizzLaunchType, // 1 byte
    pub bump: u8,                  // 1 byte
    // TOTAL: 8 (discriminator) + 32 + 32 + 8 + 8 + 1 + 9 + 8 + 1 + 1 = 108 bytes
    // Rent: ~0.0018 SOL
}

// ============ ACCOUNT CONTEXTS ============

#[derive(Accounts)]
#[instruction(voucher: LootVoucherV1)]
pub struct ClaimLoot<'info> {
    #[account(mut)]
    pub player: Signer<'info>,

    #[account(seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump)]
    pub config: Account<'info, FizzConfig>,

    #[account(
        mut,
        seeds = [CAPS_MINT_SEEDS],
        bump,
        address = config.caps_mint @ ErrorCode::InvalidCapsMint,
        constraint = caps_mint.decimals == 9 @ ErrorCode::InvalidCapsMint,
    )]
    pub caps_mint: Account<'info, Mint>,

    // SEC-AUDIT-014: only the player's own CAPS ATA can be burned.
    #[account(
        mut,
        associated_token::mint = caps_mint,
        associated_token::authority = player,
    )]
    pub player_caps_ata: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = loot_mint.decimals == 0 @ ErrorCode::BadLootMint,
        constraint = loot_mint.supply == 0 @ ErrorCode::BadLootMint,
        constraint = loot_mint.mint_authority == COption::Some(loot_mint_authority.key()) @ ErrorCode::BadLootMint,
        // Metaplex CreateV1 refuses an NFT whose freeze authority is already None.
        // It must be the loot-mint PDA so this instruction can hand freeze to the edition.
        constraint = loot_mint.freeze_authority == COption::Some(loot_mint_authority.key()) @ ErrorCode::BadLootMint,
    )]
    pub loot_mint: Account<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = loot_mint,
        associated_token::authority = player,
    )]
    pub player_loot_ata: Account<'info, TokenAccount>,

    /// CHECK: PDA mint authority. Signs mint_to and metadata.
    #[account(seeds = [LOOT_MINT_AUTHORITY_SEEDS], bump)]
    pub loot_mint_authority: UncheckedAccount<'info>,

    /// CHECK: Metaplex metadata PDA for `loot_mint`.
    #[account(
        mut,
        seeds = [b"metadata", METADATA_PROGRAM_ID.as_ref(), loot_mint.key().as_ref()],
        seeds::program = METADATA_PROGRAM_ID,
        bump,
    )]
    pub loot_metadata: UncheckedAccount<'info>,

    /// CHECK: Metaplex master-edition PDA. CreateV1 allocates it.
    #[account(
        mut,
        seeds = [
            b"metadata",
            METADATA_PROGRAM_ID.as_ref(),
            loot_mint.key().as_ref(),
            b"edition",
        ],
        seeds::program = METADATA_PROGRAM_ID,
        bump,
    )]
    pub loot_master_edition: UncheckedAccount<'info>,

    #[account(
        init,
        payer = player,
        space = VoucherClaim::SIZE,
        seeds = [VOUCHER_CLAIM_SEED, voucher.voucher_id.as_ref()],
        bump,
    )]
    pub voucher_claim: Account<'info, VoucherClaim>,

    #[account(
        init,
        payer = player,
        space = LootIdClaim::SIZE,
        seeds = [LOOT_ID_CLAIM_SEED, voucher.loot_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub loot_id_claim: Account<'info, LootIdClaim>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,

    /// CHECK: pinned to the Metaplex token-metadata program.
    #[account(address = METADATA_PROGRAM_ID)]
    pub metadata_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    /// CHECK: instructions sysvar, address-pinned. Read only through the sysvar API.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct FizzInit<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: this program. Address-pinned so ProgramData is derived from it.
    #[account(address = crate::ID @ ErrorCode::NotUpgradeAuthority)]
    pub program: UncheckedAccount<'info>,

    /// Upgradeable-loader ProgramData for this program id.
    /// `authority` must be the current upgrade authority.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(authority.key()) @ ErrorCode::NotUpgradeAuthority,
    )]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = authority,
        space = FizzConfig::SPACE,
        seeds = [FIZZ_CONFIG_SEEDS],
        bump
    )]
    pub config: Account<'info, FizzConfig>,

    /// CHECK: Treasury wallet
    pub treasury: AccountInfo<'info>,

    #[account(
        seeds = [CAPS_MINT_SEEDS],
        bump,
        constraint = caps_mint.decimals == 9 @ ErrorCode::InvalidCapsMint,
    )]
    pub caps_mint: Account<'info, Mint>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeCaps<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: this program. Address-pinned so ProgramData is derived from it.
    #[account(address = crate::ID @ ErrorCode::NotUpgradeAuthority)]
    pub program: UncheckedAccount<'info>,

    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(authority.key()) @ ErrorCode::NotUpgradeAuthority,
    )]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = authority,
        seeds = [CAPS_MINT_SEEDS],
        bump,
        mint::decimals = 9,
        mint::authority = authority,
    )]
    pub caps_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FizzSetServerKey<'info> {
    #[account(mut, seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump, has_one = authority)]
    pub config: Account<'info, FizzConfig>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct FizzSetPaused<'info> {
    #[account(mut, seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump, has_one = authority)]
    pub config: Account<'info, FizzConfig>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(admin: Pubkey)]
pub struct FizzManageAdmin<'info> {
    #[account(mut, constraint = config.authority == authority.key() @ FizzError::NotAuthority)]
    pub authority: Signer<'info>,

    #[account(seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump)]
    pub config: Account<'info, FizzConfig>,

    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 1 + 1,
        seeds = [FIZZ_ADMIN_SEEDS, admin.as_ref()],
        bump
    )]
    pub admin_record: Account<'info, FizzAdminRecord>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(name: String, symbol: String, uri: String)]
pub struct FizzCreateToken<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(mut, seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump)]
    pub config: Account<'info, FizzConfig>,

    #[account(
        mut,
        associated_token::mint = caps_mint,
        associated_token::authority = creator,
    )]
    pub creator_caps_ata: Account<'info, TokenAccount>,

    #[account(mut, address = config.caps_mint)]
    pub caps_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = creator,
        mint::decimals = 9,
        mint::authority = bonding_curve,
    )]
    pub token_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = creator,
        space = 8 + 32 + 32 + 8 + 8 + 1 + 9 + 8 + 1 + 1, // 108 bytes = ~0.0018 SOL rent (SEC-AUDIT-003 fix: updated for graduated_at: Option<i64>)
        seeds = [FIZZ_CURVE_SEEDS, token_mint.key().as_ref()],
        bump
    )]
    pub bonding_curve: Account<'info, FizzBondingCurve>,

    #[account(
        init,
        payer = creator,
        associated_token::mint = token_mint,
        associated_token::authority = bonding_curve,
    )]
    pub curve_token_vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(name: String, symbol: String, uri: String)]
pub struct FizzCreateTokenAdmin<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    #[account(mut, seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump)]
    pub config: Account<'info, FizzConfig>,

    #[account(
        seeds = [FIZZ_ADMIN_SEEDS, creator.key().as_ref()],
        bump = admin_record.bump,
        constraint = admin_record.is_active @ FizzError::AdminInactive
    )]
    pub admin_record: Account<'info, FizzAdminRecord>,

    #[account(
        init,
        payer = creator,
        mint::decimals = 9,
        mint::authority = bonding_curve,
    )]
    pub token_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = creator,
        space = 8 + 32 + 32 + 8 + 8 + 1 + 9 + 8 + 1 + 1, // 108 bytes (SEC-AUDIT-003 fix: updated for graduated_at: Option<i64>)
        seeds = [FIZZ_CURVE_SEEDS, token_mint.key().as_ref()],
        bump
    )]
    pub bonding_curve: Account<'info, FizzBondingCurve>,

    #[account(
        init,
        payer = creator,
        associated_token::mint = token_mint,
        associated_token::authority = bonding_curve,
    )]
    pub curve_token_vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct FizzBuyTokens<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,

    #[account(mut, seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump)]
    pub config: Account<'info, FizzConfig>,

    #[account(
        mut,
        seeds = [FIZZ_CURVE_SEEDS, bonding_curve.token_mint.as_ref()],
        bump = bonding_curve.bump
    )]
    pub bonding_curve: Account<'info, FizzBondingCurve>,

    // SEC-AUDIT-004 FIX: constrain curve_token_vault to the ATA owned by bonding_curve
    // for this specific token_mint.  Without this constraint an attacker could supply
    // any token account (including ones they control) as the vault, enabling token theft.
    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = bonding_curve,
    )]
    pub curve_token_vault: Account<'info, TokenAccount>,

    /// CHECK: SOL vault PDA
    #[account(mut, seeds = [FIZZ_SOL_VAULT_SEEDS, bonding_curve.token_mint.as_ref()], bump)]
    pub curve_sol_vault: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = buyer,
    )]
    pub buyer_token_ata: Account<'info, TokenAccount>,

    pub token_mint: Account<'info, Mint>,

    /// CHECK: Treasury
    #[account(mut, address = config.treasury)]
    pub treasury: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FizzSellTokens<'info> {
    #[account(mut)]
    pub seller: Signer<'info>,

    // SEC-AUDIT-005 FIX: added config account so treasury can be constrained.
    // Previously config was absent here while FizzBuyTokens correctly required it,
    // allowing any wallet to be supplied as treasury and steal 100% of sell fees.
    #[account(mut, seeds = [FIZZ_CONFIG_SEEDS], bump = config.bump)]
    pub config: Account<'info, FizzConfig>,

    #[account(
        mut,
        seeds = [FIZZ_CURVE_SEEDS, bonding_curve.token_mint.as_ref()],
        bump = bonding_curve.bump
    )]
    pub bonding_curve: Account<'info, FizzBondingCurve>,

    // SEC-AUDIT-004 FIX: constrain curve_token_vault to the correct ATA for
    // this bonding curve's token mint to prevent wrong-vault substitution.
    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = bonding_curve,
    )]
    pub curve_token_vault: Account<'info, TokenAccount>,

    /// CHECK: SOL vault PDA
    #[account(mut, seeds = [FIZZ_SOL_VAULT_SEEDS, bonding_curve.token_mint.as_ref()], bump)]
    pub curve_sol_vault: AccountInfo<'info>,

    #[account(mut)]
    pub seller_token_ata: Account<'info, TokenAccount>,

    pub token_mint: Account<'info, Mint>,

    /// CHECK: Treasury — SEC-AUDIT-005 FIX: address constrained to config.treasury
    #[account(mut, address = config.treasury @ FizzError::InvalidTreasury)]
    pub treasury: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FizzGraduate<'info> {
    #[account(
        mut,
        seeds = [FIZZ_CURVE_SEEDS, bonding_curve.token_mint.as_ref()],
        bump = bonding_curve.bump
    )]
    pub bonding_curve: Account<'info, FizzBondingCurve>,

    /// CHECK: Creator gets bonus
    #[account(mut, address = bonding_curve.creator)]
    pub creator: AccountInfo<'info>,

    /// CHECK: SOL vault
    #[account(mut, seeds = [FIZZ_SOL_VAULT_SEEDS, bonding_curve.token_mint.as_ref()], bump)]
    pub curve_sol_vault: AccountInfo<'info>,

    #[account(mut)]
    pub curve_token_vault: Account<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
}

// ============ EVENTS ============

#[event]
pub struct FizzTokenCreated {
    pub mint: Pubkey,
    pub creator: Pubkey,
    pub name: String,
    pub symbol: String,
    pub launch_type: FizzLaunchType,
    pub caps_burned: u64,
    pub timestamp: i64,
}

#[event]
pub struct FizzTokenCreatedAdmin {
    pub mint: Pubkey,
    pub creator: Pubkey,
    pub name: String,
    pub symbol: String,
    pub launch_type: FizzLaunchType,
    pub timestamp: i64,
}

#[event]
pub struct FizzTokenBought {
    pub mint: Pubkey,
    pub buyer: Pubkey,
    pub sol_amount: u64,
    pub tokens_received: u64,
}

#[event]
pub struct FizzTokenSold {
    pub mint: Pubkey,
    pub seller: Pubkey,
    pub tokens_sold: u64,
    pub sol_received: u64,
}

#[event]
pub struct FizzReadyToGraduate {
    pub mint: Pubkey,
    pub sol_raised: u64,
}

#[event]
pub struct FizzTokenGraduated {
    pub mint: Pubkey,
    pub creator: Pubkey,
    pub sol_raised: u64,
    pub creator_bonus: u64,
}

#[event]
pub struct ServerKeyRotated {
    pub old: Pubkey,
    pub new: Pubkey,
    pub cluster_tag: u8,
}

// ============ ERRORS ============

#[error_code]
pub enum ErrorCode {
    #[msg("No Ed25519 Verify instruction found in transaction")]
    NoEd25519Ix,
    #[msg("Instruction is not from the Ed25519 program")]
    InvalidEd25519Program,
    #[msg("Invalid Ed25519 instruction data format")]
    InvalidEd25519Data,
    #[msg("Ed25519 pubkey does not match expected server key")]
    WrongPubkey,
    #[msg("Ed25519 signature does not match")]
    WrongSignature,
    #[msg("Ed25519 signed message does not match voucher")]
    WrongMessage,
    // SEC-AUDIT-008 FIX: loot voucher has expired (older than max_age seconds)
    #[msg("Loot voucher has expired")]
    VoucherExpired,
    #[msg("Voucher not yet valid")]
    VoucherNotYetValid,
    #[msg("Voucher TTL exceeds maximum")]
    VoucherTtlTooLong,
    #[msg("Voucher fields malformed")]
    VoucherBadShape,
    #[msg("Missing Ed25519 instruction")]
    MissingEd25519Ix,
    #[msg("Ed25519 instruction layout invalid")]
    Ed25519BadLayout,
    #[msg("Voucher signer is not the configured server key")]
    WrongVoucherSigner,
    #[msg("Voucher message does not match")]
    VoucherMessageMismatch,
    #[msg("claim_loot cannot be invoked via CPI")]
    CpiNotAllowed,
    #[msg("caps_mint does not match config")]
    InvalidCapsMint,
    #[msg("Loot mint is not a fresh 0-decimal mint owned by the PDA")]
    BadLootMint,
    #[msg("Program is paused")]
    ProgramPaused,
    #[msg("fizz_init signer is not the program upgrade authority")]
    NotUpgradeAuthority,
}

#[error_code]
pub enum FizzError {
    #[msg("Must hold at least 1000 CAPS to launch tokens")]
    InsufficientCapsToLaunch,
    #[msg("Token has already graduated")]
    TokenGraduated,
    #[msg("Token has already graduated")]
    AlreadyGraduated,
    #[msg("Token needs 85 SOL to graduate")]
    NotReadyToGraduate,
    #[msg("Slippage exceeded")]
    SlippageExceeded,
    #[msg("Insufficient liquidity")]
    InsufficientLiquidity,
    #[msg("Amount must be > 0")]
    ZeroAmount,
    #[msg("Not authorized")]
    NotAuthority,
    #[msg("Admin is inactive")]
    AdminInactive,
    #[msg("Name too long (max 32)")]
    NameTooLong,
    #[msg("Symbol too long (max 10)")]
    SymbolTooLong,
    #[msg("URI too long (max 200)")]
    UriTooLong,
    // SEC-AUDIT-001 FIX: arithmetic overflow in bonding curve u128 calculations
    #[msg("Arithmetic overflow in bonding curve calculation")]
    ArithmeticOverflow,
    // SEC-AUDIT-005 FIX: treasury address does not match config.treasury
    #[msg("Invalid treasury account")]
    InvalidTreasury,
}