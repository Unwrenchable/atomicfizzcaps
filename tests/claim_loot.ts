/**
 * Runs claim_loot on a local validator started by `anchor test`.
 * Metaplex is loaded from tests/fixtures/mpl_token_metadata.so (Anchor.toml genesis).
 * The program under test is the localnet build (cluster tag 3).
 */
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { createRequire } from "module";

const BN = createRequire(import.meta.url)("bn.js");
import {
  ComputeBudgetProgram,
  Ed25519Program,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SYSVAR_RENT_PUBKEY,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { assert } from "chai";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import nacl from "tweetnacl";
import { fileURLToPath } from "url";

const idl = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../target/idl/fizzcaps_onchain.json"), "utf8")
);

const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const METADATA_PROGRAM_ID = new PublicKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");
const UPGRADEABLE_LOADER = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const CLUSTER_TAG = 3; // localnet binary
const MINT_LEN = 82;

function u64le(n: number | bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

function i32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeInt32LE(n);
  return b;
}

function i64le(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt(n));
  return b;
}

function ata(owner: PublicKey, mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), mint.toBuffer()],
    ASSOCIATED_TOKEN_PROGRAM_ID
  )[0];
}

function initializeMintIx(
  mint: PublicKey,
  decimals: number,
  mintAuthority: PublicKey,
  freezeAuthority: PublicKey | null
): TransactionInstruction {
  const data = Buffer.alloc(freezeAuthority ? 67 : 35);
  data.writeUInt8(0, 0);
  data.writeUInt8(decimals, 1);
  mintAuthority.toBuffer().copy(data, 2);
  if (freezeAuthority) {
    data.writeUInt8(1, 34);
    freezeAuthority.toBuffer().copy(data, 35);
  } else {
    data.writeUInt8(0, 34);
  }
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: mint, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function mintToIx(mint: PublicKey, dest: PublicKey, authority: PublicKey, amount: bigint): TransactionInstruction {
  const data = Buffer.alloc(9);
  data.writeUInt8(7, 0);
  data.writeBigUInt64LE(amount, 1);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: mint, isSigner: false, isWritable: true },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function createAtaIx(payer: PublicKey, owner: PublicKey, mint: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: ata(owner, mint), isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: Buffer.alloc(0),
  });
}

function voucherMessage(args: {
  programId: PublicKey;
  player: PublicKey;
  voucherId: Buffer;
  lootId: number;
  latE6: number;
  lngE6: number;
  hint: string;
  issuedAt: number;
  expiresAt: number;
}): Buffer {
  const hintHash = createHash("sha256").update(Buffer.from(args.hint, "utf8")).digest();
  return Buffer.concat([
    Buffer.from("FIZZCAPS:LOOT_VOUCHER:v1", "utf8"),
    Buffer.from([CLUSTER_TAG]),
    args.programId.toBuffer(),
    args.player.toBuffer(),
    args.voucherId,
    u64le(args.lootId),
    i32le(args.latE6),
    i32le(args.lngE6),
    hintHash,
    i64le(args.issuedAt),
    i64le(args.expiresAt),
  ]);
}

describe("claim_loot", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = new Program(idl as anchor.Idl, provider);
  const player = provider.wallet.publicKey;
  const server = Keypair.generate();
  const devKey = Keypair.generate();
  const mainKey = Keypair.generate();

  const programId = program.programId;
  const [programData] = PublicKey.findProgramAddressSync([programId.toBuffer()], UPGRADEABLE_LOADER);
  const [capsMint] = PublicKey.findProgramAddressSync([Buffer.from("caps-mint")], programId);
  const [config] = PublicKey.findProgramAddressSync([Buffer.from("fizz-config")], programId);
  const [lootAuth] = PublicKey.findProgramAddressSync([Buffer.from("loot-mint-auth")], programId);
  const capsAta = ata(player, capsMint);

  before(async () => {
    await program.methods
      .initializeCaps()
      .accounts({
        authority: player,
        program: programId,
        programData,
        capsMint,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .fizzInit(server.publicKey, devKey.publicKey, mainKey.publicKey)
      .accounts({
        authority: player,
        program: programId,
        programData,
        config,
        treasury: player,
        capsMint,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const fund = new Transaction().add(
      createAtaIx(player, player, capsMint),
      mintToIx(capsMint, capsAta, player, 200n * 1_000_000_000n)
    );
    await provider.sendAndConfirm(fund);
    const caps = await provider.connection.getTokenAccountBalance(capsAta);
    assert.equal(caps.value.amount, String(200n * 1_000_000_000n));
  });

  async function prepareLoot(): Promise<{ mint: Keypair; ata: PublicKey }> {
    const mint = Keypair.generate();
    const lamports = await provider.connection.getMinimumBalanceForRentExemption(MINT_LEN);
    const tx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: player,
        newAccountPubkey: mint.publicKey,
        lamports,
        space: MINT_LEN,
        programId: TOKEN_PROGRAM_ID,
      }),
      initializeMintIx(mint.publicKey, 0, lootAuth, lootAuth),
      createAtaIx(player, player, mint.publicKey)
    );
    await provider.sendAndConfirm(tx, [mint]);
    return { mint, ata: ata(player, mint.publicKey) };
  }

  function claimAccounts(lootMint: PublicKey, lootAta: PublicKey, voucherId: Buffer, lootId: number) {
    const [voucherClaim] = PublicKey.findProgramAddressSync(
      [Buffer.from("voucher-claim"), voucherId],
      programId
    );
    const [lootIdClaim] = PublicKey.findProgramAddressSync(
      [Buffer.from("loot-id-claim"), u64le(lootId)],
      programId
    );
    const [metadata] = PublicKey.findProgramAddressSync(
      [Buffer.from("metadata"), METADATA_PROGRAM_ID.toBuffer(), lootMint.toBuffer()],
      METADATA_PROGRAM_ID
    );
    const [masterEdition] = PublicKey.findProgramAddressSync(
      [Buffer.from("metadata"), METADATA_PROGRAM_ID.toBuffer(), lootMint.toBuffer(), Buffer.from("edition")],
      METADATA_PROGRAM_ID
    );
    return {
      player,
      config,
      capsMint,
      playerCapsAta: capsAta,
      lootMint,
      playerLootAta: lootAta,
      lootMintAuthority: lootAuth,
      lootMetadata: metadata,
      lootMasterEdition: masterEdition,
      voucherClaim,
      lootIdClaim,
      tokenProgram: TOKEN_PROGRAM_ID,
      associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      metadataProgram: METADATA_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
    };
  }

  function voucherArg(voucherId: Buffer, lootId: number, now: number) {
    return {
      voucherId: Array.from(voucherId),
      lootId: new BN(lootId),
      latE6: 36_115_900,
      lngE6: -115_173_400,
      locationHint: "Vault 77",
      issuedAt: new BN(now),
      expiresAt: new BN(now + 300),
    };
  }

  function ed25519Ix(signer: Keypair, message: Buffer): TransactionInstruction {
    const signature = nacl.sign.detached(message, signer.secretKey);
    return Ed25519Program.createInstructionWithPublicKey({
      publicKey: signer.publicKey.toBytes(),
      message,
      signature,
    });
  }

  async function sendClaim(
    lootMint: PublicKey,
    lootAta: PublicKey,
    voucherId: Buffer,
    lootId: number,
    signer: Keypair | null
  ) {
    const now = Math.floor(Date.now() / 1000);
    const message = voucherMessage({
      programId,
      player,
      voucherId,
      lootId,
      latE6: 36_115_900,
      lngE6: -115_173_400,
      hint: "Vault 77",
      issuedAt: now,
      expiresAt: now + 300,
    });
    assert.equal(message.length, 169);
    const builder = program.methods
      .claimLoot(voucherArg(voucherId, lootId, now))
      .accounts(claimAccounts(lootMint, lootAta, voucherId, lootId));
    const ix = await builder.instruction();
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }));
    if (signer) tx.add(ed25519Ix(signer, message));
    tx.add(ix);
    return provider.sendAndConfirm(tx);
  }

  it("mints one loot token, burns 100 CAPS, and rejects replay, a wrong signer, and a missing Ed25519 instruction", async () => {
    const happy = await prepareLoot();
    const voucherId = Buffer.alloc(16, 0);
    voucherId[0] = 7;
    await sendClaim(happy.mint.publicKey, happy.ata, voucherId, 42, server);

    const lootBal = await provider.connection.getTokenAccountBalance(happy.ata);
    assert.equal(lootBal.value.amount, "1");
    const caps = await provider.connection.getTokenAccountBalance(capsAta);
    assert.equal(caps.value.amount, String(100n * 1_000_000_000n));

    let replayFailed = false;
    try {
      await sendClaim(happy.mint.publicKey, happy.ata, voucherId, 42, server);
    } catch (err) {
      replayFailed = true;
      const text = String(err);
      assert.match(text, /already in use/i);
    }
    assert.isTrue(replayFailed, "replay must fail");

    const wrongMint = await prepareLoot();
    const wrongId = Buffer.alloc(16, 0);
    wrongId[0] = 8;
    let wrongFailed = false;
    try {
      await sendClaim(wrongMint.mint.publicKey, wrongMint.ata, wrongId, 43, Keypair.generate());
    } catch (err) {
      wrongFailed = true;
      assert.match(String(err), /WrongVoucherSigner|not the configured server key/);
    }
    assert.isTrue(wrongFailed, "wrong signer must fail");

    const missingMint = await prepareLoot();
    const missingId = Buffer.alloc(16, 0);
    missingId[0] = 9;
    let missingFailed = false;
    try {
      await sendClaim(missingMint.mint.publicKey, missingMint.ata, missingId, 44, null);
    } catch (err) {
      missingFailed = true;
      assert.match(String(err), /MissingEd25519Ix|Missing Ed25519/);
    }
    assert.isTrue(missingFailed, "missing ed25519 must fail");
  });
});
