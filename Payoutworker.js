import { Pool } from "pg";
import { createHmac } from "node:crypto";
import * as bip39 from "bip39";
import {
  keyPairFromSeed,
  mnemonicToPrivateKey,
  mnemonicValidate,
} from "@ton/crypto";
import {
  Address,
  beginCell,
  toNano,
} from "@ton/core";
import {
  TonClient,
  WalletContractV4,
  WalletContractV5R1,
  SendMode,
  internal,
} from "@ton/ton";

const TRANSFER_OP = 0x0f8a7ea5;
const INTERNAL_TRANSFER_OP = 0x178d4519;
const MAINNET_GLOBAL_ID = -239;
const UINT64_MAX = (1n << 64n) - 1n;
const ADVISORY_LOCK_KEY = 90520260916;
const TON_BIP39_PATH = [44, 607, 0];
const HARDENED_OFFSET = 0x80000000;

function strEnv(name, fallback = "") {
  const value = process.env[name];
  return typeof value === "string" && value.trim().length
    ? value.trim()
    : fallback;
}

function intEnv(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isSafeInteger(value) ? value : fallback;
}

function boolEnv(name, fallback = false) {
  const value = process.env[name];
  if (value == null) return fallback;
  return String(value).trim().toLowerCase() === "true";
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function normalizeAddress(value) {
  return Address.parse(String(value)).toString({
    bounceable: false,
    testOnly: false,
  });
}

function sameAddress(a, b) {
  try {
    return normalizeAddress(a) === normalizeAddress(b);
  } catch {
    return false;
  }
}

function safeError(error) {
  return String(error?.message || error || "Unknown error").slice(0, 500);
}

function looksLikeUninitializedAccountError(error) {
  const text = safeError(error).toLowerCase();
  return (
    text.includes("not initialized") ||
    text.includes("not active") ||
    text.includes("uninitialized") ||
    text.includes("account state") ||
    text.includes("cannot run get method") ||
    text.includes("cannot find") ||
        text.includes("not found") ||
    text.includes("exit_code: -13")
  );
}

function deriveSlip10Ed25519(seed, pathSegments) {
  let digest = createHmac("sha512", Buffer.from("ed25519 seed", "utf8"))
    .update(seed)
    .digest();

  let key = digest.subarray(0, 32);
  let chainCode = digest.subarray(32);

  for (const segment of pathSegments) {
    if (!Number.isInteger(segment) || segment < 0 || segment >= HARDENED_OFFSET) {
      throw new Error("Invalid BIP39 derivation path segment");
    }

    const index = segment + HARDENED_OFFSET;
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index >>> 0, 0);

    const data = Buffer.concat([
      Buffer.from([0]),
      key,
      indexBuffer,
    ]);

    digest = createHmac("sha512", chainCode)
      .update(data)
      .digest();

    key = digest.subarray(0, 32);
    chainCode = digest.subarray(32);
  }

  return key;
}

async function mnemonicToSignerKeyPair(words) {
  const normalizedWords = words.map((word) =>
    String(word)
      .normalize("NFKD")
      .replace(/[\u200B-\u200D\uFEFF]/g, "")
      .trim()
      .toLowerCase(),
  );

  const tonValid = await mnemonicValidate(normalizedWords);

  if (tonValid) {
    return {
      keyPair: await mnemonicToPrivateKey(normalizedWords),
      mnemonicType: "ton",
    };
  }

  const phrase = normalizedWords.join(" ");
  const wordlist = bip39.wordlists.english;

  const invalidPositions = normalizedWords
    .map((word, index) =>
      wordlist.includes(word) ? null : index + 1,
    )
    .filter((value) => value !== null);

  if (invalidPositions.length) {
    throw new Error(
      `TREASURY_MNEMONIC contains invalid word(s) at position(s): ${invalidPositions.join(", ")}`,
    );
  }

  const checksumValid = bip39.validateMnemonic(
    phrase,
    wordlist,
  );

  const seed = bip39.mnemonicToSeedSync(phrase);
  const ed25519Seed = deriveSlip10Ed25519(
    seed,
    TON_BIP39_PATH,
  );

  return {
    keyPair: keyPairFromSeed(ed25519Seed),
    mnemonicType: checksumValid
      ? "bip39"
      : "bip39-address-verified",
  };
}
  

const DATABASE_URL = strEnv("DATABASE_URL");

const TREASURY_MNEMONIC = strEnv(
  "TREASURY_MNEMONIC",
);

const TREASURY_WALLET_ADDRESS = strEnv(
  "TREASURY_WALLET_ADDRESS",
  "UQAr2SdmjtiZmeNJiSFEslRjLv6YBn7BAaU7Dpd7KMi3Jf_q",
);

const USDT_JETTON_MASTER = strEnv(
  "USDT_JETTON_MASTER",
  "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs",
);

const TON_RPC_ENDPOINT = strEnv(
  "TON_RPC_ENDPOINT",
  "https://toncenter.com/api/v2/jsonRPC",
);

const TONCENTER_API_KEY = strEnv(
  "TONCENTER_API_KEY",
);

const AUTOMATIC_SETTLEMENT_ENABLED = boolEnv(
  "AUTOMATIC_SETTLEMENT_ENABLED",
  false,
);

const PAYOUT_LIVE_MODE = boolEnv(
  "PAYOUT_LIVE_MODE",
  false,
);

const PAYOUT_BATCH_SIZE = clamp(
  intEnv("PAYOUT_BATCH_SIZE", 16),
  1,
  255,
);

const PAYOUT_MAX_BATCHES_PER_RUN = clamp(
  intEnv("PAYOUT_MAX_BATCHES_PER_RUN", 5),
  1,
  100,
);

const PAYOUT_CONFIRM_WAIT_SECONDS = clamp(
  intEnv("PAYOUT_CONFIRM_WAIT_SECONDS", 45),
  0,
  180,
);

const PAYOUT_RECONCILE_GRACE_SECONDS = clamp(
  intEnv("PAYOUT_RECONCILE_GRACE_SECONDS", 900),
  60,
  86_400,
);

const PAYOUT_SCAN_TX_LIMIT = clamp(
  intEnv("PAYOUT_SCAN_TX_LIMIT", 100),
  5,
  100,
);

const JETTON_TRANSFER_TON = strEnv(
  "JETTON_TRANSFER_TON",
  "0.05",
);

const TREASURY_TON_RESERVE = strEnv(
  "TREASURY_TON_RESERVE",
  "0.20",
);

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL missing");
}

const JETTON_TRANSFER_TON_NANO =
  toNano(JETTON_TRANSFER_TON);

const TREASURY_TON_RESERVE_NANO =
  toNano(TREASURY_TON_RESERVE);

if (JETTON_TRANSFER_TON_NANO <= 0n) {
  throw new Error(
    "JETTON_TRANSFER_TON must be greater than zero",
  );
}

if (TREASURY_TON_RESERVE_NANO < 0n) {
  throw new Error(
    "TREASURY_TON_RESERVE cannot be negative",
  );
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
  max: 2,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 10_000,
});

const tonClient = new TonClient({
  endpoint: TON_RPC_ENDPOINT,
  ...(TONCENTER_API_KEY
    ? { apiKey: TONCENTER_API_KEY }
    : {}),
  timeout: 20_000,
});

function buildJettonTransferBody({
  queryId,
  amountMicro,
  destinationOwner,
  responseDestination,
}) {
  return beginCell()
    .storeUint(TRANSFER_OP, 32)
    .storeUint(queryId, 64)
    .storeCoins(amountMicro)
    .storeAddress(
      Address.parse(destinationOwner),
    )
    .storeAddress(
      Address.parse(responseDestination),
    )
    .storeBit(0)
    .storeCoins(1n)
    .storeBit(0)
    .endCell();
}

function parseInternalJettonTransfer(message) {
  try {
    if (
      !message ||
      message.info?.type !== "internal"
    ) {
      return null;
    }

    const slice =
      message.body.beginParse();

    if (slice.remainingBits < 96) {
      return null;
    }

    const op =
      slice.loadUint(32);

    if (op !== INTERNAL_TRANSFER_OP) {
      return null;
    }

    const queryId =
      slice.loadUintBig(64);

    const amountMicro =
      slice.loadCoins();

    const fromOwner =
      slice.loadAddress();

    const responseAddress =
      slice.loadAddress();

    return {
      queryId,
      amountMicro,
      fromOwner,
      responseAddress,
      sourceJettonWallet:
        message.info.src,
    };
  } catch {
    return null;
  }
}

function transactionSucceeded(tx) {
  const description =
    tx?.description;

  if (!description) {
    return false;
  }

  if (description.aborted === true) {
    return false;
  }

  const compute =
    description.computePhase;

  if (
    !compute ||
    compute.type !== "vm" ||
    compute.success !== true
  ) {
    return false;
  }

  const action =
    description.actionPhase;

  if (
    action &&
    action.success !== true
  ) {
    return false;
  }

  return true;
}

async function audit(
  client,
  eventType,
  phaseId,
  payload,
) {
  await client.query(
    `
      INSERT INTO audit_logs (
        event_type,
        actor_telegram_id,
        phase_id,
        payload
      )
      VALUES (
        $1,
        NULL,
        $2,
        $3::jsonb
      )
    `,
    [
      String(eventType).slice(
        0,
        120,
      ),
      phaseId ?? null,
      JSON.stringify(
        payload ?? null,
      ),
    ],
  );
}

async function ensureSchema(client) {
  const statements = [
    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      ton_query_id BIGINT
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      ton_wallet_seqno BIGINT
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      ton_valid_until BIGINT
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      ton_batch_id TEXT
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      recipient_jetton_wallet_address TEXT
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      ton_external_body_hash TEXT
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      settlement_attempts INTEGER
      NOT NULL
      DEFAULT 0
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      last_settlement_attempt_at
      TIMESTAMPTZ
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      broadcast_at TIMESTAMPTZ
    `,

    `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      confirmed_at TIMESTAMPTZ
    `,

    `
      CREATE INDEX
      IF NOT EXISTS
      idx_payouts_auto_settlement
      ON payouts(status, id)
    `,

    `
      CREATE INDEX
      IF NOT EXISTS
      idx_payouts_ton_batch
      ON payouts(ton_batch_id)
      WHERE ton_batch_id
      IS NOT NULL
    `,

    `
      CREATE UNIQUE INDEX
      IF NOT EXISTS
      idx_payouts_ton_query_id
      ON payouts(ton_query_id)
      WHERE ton_query_id
      IS NOT NULL
    `,
  ];

  for (const sql of statements) {
    await client.query(sql);
  }
}

async function resolveWalletSigner() {
  if (!TREASURY_MNEMONIC) {
    throw new Error(
      "TREASURY_MNEMONIC missing from payout worker environment",
    );
  }

  const words =
    TREASURY_MNEMONIC
      .split(/\s+/)
      .filter(Boolean);

  if (
    ![12, 24].includes(
      words.length,
    )
  ) {
    throw new Error(
      "TREASURY_MNEMONIC must contain 12 or 24 words",
    );
  }

  const {
    keyPair,
    mnemonicType,
  } =
    await mnemonicToSignerKeyPair(
      words,
    );

  const expected =
    normalizeAddress(
      TREASURY_WALLET_ADDRESS,
    );

  const candidates = [
    {
      version: "v5r1",
      maxMessages: 255,
      wallet:
        WalletContractV5R1.create({
          walletId: {
            networkGlobalId:
              MAINNET_GLOBAL_ID,
          },
          publicKey:
            keyPair.publicKey,
          workchain: 0,
        }),
    },

    {
      version: "v4r2",
      maxMessages: 4,
      wallet:
        WalletContractV4.create({
          workchain: 0,
          publicKey:
            keyPair.publicKey,
        }),
    },
  ];

  const matched =
    candidates.find(
      (item) =>
        normalizeAddress(
          item.wallet.address,
        ) === expected,
    );

  if (!matched) {
    throw new Error(
      `Treasury ${mnemonicType} mnemonic does not derive the configured treasury address as V5R1 or V4R2. Refusing to send.`,
    );
  }

  return {
    ...matched,
    keyPair,
    mnemonicType,
    openedWallet:
      tonClient.open(
        matched.wallet,
      ),
  };
}

async function getJettonWalletAddress(
  ownerAddress,
) {
  const result =
    await tonClient.runMethod(
      Address.parse(
        USDT_JETTON_MASTER,
      ),
      "get_wallet_address",
      [
        {
          type: "slice",
          cell:
            beginCell()
              .storeAddress(
                Address.parse(
                  String(ownerAddress),
                ),
              )
              .endCell(),
        },
      ],
    );

  return result.stack.readAddress();
}

async function getJettonWalletData(
  jettonWalletAddress,
) {
  const result =
    await tonClient.runMethod(
      Address.parse(
        String(jettonWalletAddress),
      ),
      "get_wallet_data",
    );

  return {
    balance:
      result.stack.readBigNumber(),

    owner:
      result.stack.readAddress(),

    master:
      result.stack.readAddress(),

    code:
      result.stack.readCell(),
  };
}

async function getTreasuryJettonWalletState(
  jettonWalletAddress,
) {
  try {
    const data =
      await getJettonWalletData(
        jettonWalletAddress,
      );

    if (
      !sameAddress(
        data.owner,
        TREASURY_WALLET_ADDRESS,
      )
    ) {
      throw new Error(
        "Treasury USDT jetton wallet owner mismatch",
      );
    }

    if (
      !sameAddress(
        data.master,
        USDT_JETTON_MASTER,
      )
    ) {
      throw new Error(
        "Treasury USDT jetton wallet master mismatch",
      );
    }

    return {
      initialized: true,
      balance: data.balance,
    };
  } catch (error) {
    if (
      looksLikeUninitializedAccountError(
        error,
      )
    ) {
      return {
        initialized: false,
        balance: 0n,
      };
    }

    throw error;
  }
}

async function verifyTreasuryJettonWallet() {
  const treasuryAddress =
    Address.parse(
      TREASURY_WALLET_ADDRESS,
    );

  const jettonWallet =
    await getJettonWalletAddress(
      treasuryAddress,
    );
  console.log(
    `Treasury USDT jetton wallet derived: ${normalizeAddress(jettonWallet)}`,
  );
  const state =
    await getTreasuryJettonWalletState(
      jettonWallet,
    );

  return {
    address: jettonWallet,
    balance: state.balance,
    initialized:
      state.initialized,
  };
}

async function loadBatchMembers(
  batchId,
) {
  const result =
    await pool.query(
      `
        SELECT *
        FROM payouts
        WHERE ton_batch_id = $1
        ORDER BY id ASC
      `,
      [batchId],
    );

  return result.rows;
}

function buildBatchTransfer({
  signer,
  rows,
  treasuryJettonWallet,
  seqno,
  validUntil,
}) {
  const attachedTon =
    JETTON_TRANSFER_TON_NANO;

  const messages =
    rows.map((row) => {
      const queryId =
        BigInt(
          row.ton_query_id,
        );

      const amountMicro =
        BigInt(
          row.usdt_amount_micro,
        );

      return internal({
        to:
          treasuryJettonWallet,

        value:
          attachedTon,

        bounce:
          true,

        body:
          buildJettonTransferBody({
            queryId,
            amountMicro,
            destinationOwner:
              row.ton_wallet_address,
            responseDestination:
              TREASURY_WALLET_ADDRESS,
          }),
      });
    });

  const transfer =
    signer.openedWallet
      .createTransfer({
        seqno,

        secretKey:
          signer
            .keyPair
            .secretKey,

        messages,

        sendMode:
          SendMode
            .PAY_GAS_SEPARATELY |
          SendMode
            .IGNORE_ERRORS,

        timeout:
          validUntil,
      });

  return {
    transfer,

    bodyHash:
      transfer
        .hash()
        .toString("hex"),
  };
}

async function waitForSeqno(
  openedWallet,
  previousSeqno,
) {
  const deadline =
    Date.now() +
    PAYOUT_CONFIRM_WAIT_SECONDS *
      1000;

  while (
    Date.now() < deadline
  ) {
    await new Promise(
      (resolve) =>
        setTimeout(
          resolve,
          3000,
        ),
    );

    const current =
      await openedWallet
        .getSeqno();

    if (
      current >
      previousSeqno
    ) {
      return current;
    }
  }

  return openedWallet.getSeqno();
}

async function findRecipientDelivery(
  row,
  treasuryJettonWallet,
) {
  if (
    !row
      .recipient_jetton_wallet_address
  ) {
    return {
      state: "missing",
    };
  }

  let transactions;

  try {
    transactions =
      await tonClient
        .getTransactions(
          Address.parse(
            row
              .recipient_jetton_wallet_address,
          ),
          {
            limit:
              PAYOUT_SCAN_TX_LIMIT,
          },
        );
  } catch (error) {
    if (
      looksLikeUninitializedAccountError(
        error,
      )
    ) {
      return {
        state: "missing",
      };
    }

    throw error;
  }

  const expectedQueryId =
    BigInt(
      row.ton_query_id,
    );

  const expectedAmount =
    BigInt(
      row.usdt_amount_micro,
    );

  let failedMatch = null;

  for (
    const tx of transactions
  ) {
    const parsed =
      parseInternalJettonTransfer(
        tx.inMessage,
      );

    if (!parsed) {
      continue;
    }

    if (
      parsed.queryId !==
      expectedQueryId
    ) {
      continue;
    }

    if (
      parsed.amountMicro !==
      expectedAmount
    ) {
      continue;
    }

    if (
      !sameAddress(
        parsed.fromOwner,
        TREASURY_WALLET_ADDRESS,
      )
    ) {
      continue;
    }

    if (
      !sameAddress(
        parsed.responseAddress,
        TREASURY_WALLET_ADDRESS,
      )
    ) {
      continue;
    }

    if (
      !sameAddress(
        parsed.sourceJettonWallet,
        treasuryJettonWallet,
      )
    ) {
      continue;
    }

    const txHash =
      tx
        .hash()
        .toString("hex");

    const txLt =
      String(tx.lt);

    if (
      transactionSucceeded(
        tx,
      )
    ) {
      const recipientData =
        await getJettonWalletData(
          row
            .recipient_jetton_wallet_address,
        );

      if (
        !sameAddress(
          recipientData.owner,
          row
            .ton_wallet_address,
        )
      ) {
        throw new Error(
          `Recipient jetton wallet owner mismatch for payout ${row.id}`,
        );
      }

      if (
        !sameAddress(
          recipientData.master,
          USDT_JETTON_MASTER,
        )
      ) {
        throw new Error(
          `Recipient jetton wallet master mismatch for payout ${row.id}`,
        );
      }

      return {
        state: "paid",

        txHash,

        settlementReference:
          `ton:${normalizeAddress(
            row
              .recipient_jetton_wallet_address,
          )}:${txLt}`,
      };
    }

    failedMatch = {
      state:
        "failed",

      txHash,

      settlementReference:
        `ton-failed:${normalizeAddress(
          row
            .recipient_jetton_wallet_address,
        )}:${txLt}`,
    };
  }

  return (
    failedMatch || {
      state:
        "missing",
    }
  );
}

async function markPaid(
  row,
  delivery,
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN",
    );

    const updated =
      (
        await client.query(
          `
            UPDATE payouts
            SET
              status = 'paid',
              ton_tx_hash = $2,
              settlement_reference = $3,
              telegram_transaction_id =
                COALESCE(
                  telegram_transaction_id,
                  $3
                ),
              failure_reason = NULL,
              paid_at =
                COALESCE(
                  paid_at,
                  NOW()
                ),
              confirmed_at =
                COALESCE(
                  confirmed_at,
                  NOW()
                )
            WHERE id = $1
              AND status <> 'paid'
            RETURNING *
          `,
          [
            row.id,
            delivery.txHash,
            delivery
              .settlementReference,
          ],
        )
      ).rows[0];

    if (updated) {
      await audit(
        client,
        "payout_auto_paid",
        row.phase_id,
        {
          payoutId:
            Number(row.id),

          winnerId:
            Number(
              row.winner_id,
            ),

          telegramUserId:
            Number(
              row.telegram_user_id,
            ),

          amountMicro:
            String(
              row
                .usdt_amount_micro,
            ),

          transactionHash:
            delivery.txHash,

          settlementReference:
            delivery
              .settlementReference,
        },
      );
    }

    await client.query(
      "COMMIT",
    );

    return Boolean(
      updated,
    );
  } catch (error) {
    await client
      .query("ROLLBACK")
      .catch(() => {});

    throw error;
  } finally {
    client.release();
  }
}

async function markFailed(
  row,
  reason,
  txHash = null,
  settlementReference = null,
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN",
    );

    const updated =
      (
        await client.query(
          `
            UPDATE payouts
            SET
              status = 'failed',
              failure_reason = $2,
              ton_tx_hash =
                COALESCE(
                  $3,
                  ton_tx_hash
                ),
              settlement_reference =
                COALESCE(
                  $4,
                  settlement_reference
                )
            WHERE id = $1
              AND status <> 'paid'
            RETURNING *
          `,
          [
            row.id,

            String(reason)
              .slice(
                0,
                500,
              ),

            txHash,

            settlementReference,
          ],
        )
      ).rows[0];

    if (updated) {
      await audit(
        client,
        "payout_auto_failed",
        row.phase_id,
        {
          payoutId:
            Number(row.id),

          reason:
            String(reason)
              .slice(
                0,
                500,
              ),

          transactionHash:
            txHash,

          settlementReference,
        },
      );
    }

    await client.query(
      "COMMIT",
    );

    return Boolean(
      updated,
    );
  } catch (error) {
    await client
      .query("ROLLBACK")
      .catch(() => {});

    throw error;
  } finally {
    client.release();
  }
}

async function resetExpiredBatch(
  batchId,
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN",
    );

    const rows =
      (
        await client.query(
          `
            UPDATE payouts
            SET
              status = 'pending',
              failure_reason = NULL,
              processing_at = NULL,
              ton_query_id = NULL,
              ton_wallet_seqno = NULL,
              ton_valid_until = NULL,
              ton_batch_id = NULL,
              recipient_jetton_wallet_address = NULL,
              ton_external_body_hash = NULL,
              broadcast_at = NULL
            WHERE ton_batch_id = $1
              AND status = 'processing'
            RETURNING
              id,
              phase_id
          `,
          [batchId],
        )
      ).rows;

    for (
      const row of rows
    ) {
      await audit(
        client,
        "payout_auto_reset_expired",
        row.phase_id,
        {
          payoutId:
            Number(row.id),

          batchId,
        },
      );
    }

    await client.query(
      "COMMIT",
    );

    return rows.length;
  } catch (error) {
    await client
      .query("ROLLBACK")
      .catch(() => {});

    throw error;
  } finally {
    client.release();
  }
}

async function reconcileBatch({
  signer,
  batchId,
  treasuryJettonWallet,
}) {
  const rows =
    await loadBatchMembers(
      batchId,
    );

  if (!rows.length) {
    return {
      unresolved: 0,
      paid: 0,
      failed: 0,
    };
  }

  let paid = 0;
  let failed = 0;
  let unresolved = 0;

  for (
    const row of rows
  ) {
    if (
      row.status === "paid"
    ) {
      paid++;
      continue;
    }

    if (
      ![
        "processing",
        "failed",
      ].includes(
        row.status,
      )
    ) {
      continue;
    }

    const delivery =
      await findRecipientDelivery(
        row,
        treasuryJettonWallet,
      );

    if (
      delivery.state ===
      "paid"
    ) {
      if (
        await markPaid(
          row,
          delivery,
        )
      ) {
        paid++;
      }

      continue;
    }

    if (
      delivery.state ===
      "failed"
    ) {
      await markFailed(
        row,
        "Recipient USDT jetton transaction failed on-chain. Automatic retry is blocked to prevent duplicate payment.",
        delivery.txHash,
        delivery
          .settlementReference,
      );

      failed++;
      continue;
    }

    if (
      row.status ===
      "processing"
    ) {
      unresolved++;
    }
  }

  const processingRows =
    (
      await loadBatchMembers(
        batchId,
      )
    ).filter(
      (row) =>
        row.status ===
        "processing",
    );

  if (
    !processingRows.length
  ) {
    return {
      unresolved: 0,
      paid,
      failed,
    };
  }

  const assignedSeqnos =
    new Set(
      processingRows.map(
        (row) =>
          String(
            row
              .ton_wallet_seqno,
          ),
      ),
    );

  const validUntils =
    new Set(
      processingRows.map(
        (row) =>
          String(
            row
              .ton_valid_until,
          ),
      ),
    );

  const storedHashes =
    new Set(
      processingRows.map(
        (row) =>
          String(
            row
              .ton_external_body_hash ||
              "",
          ),
      ),
    );

  if (
    assignedSeqnos.size !== 1 ||
    validUntils.size !== 1 ||
    storedHashes.size !== 1
  ) {
    throw new Error(
      `Batch ${batchId} has inconsistent seqno, valid-until, or body-hash metadata`,
    );
  }

  const assignedSeqno =
    Number(
      processingRows[0]
        .ton_wallet_seqno,
    );

  const validUntil =
    Number(
      processingRows[0]
        .ton_valid_until,
    );

  const expectedHash =
    String(
      processingRows[0]
        .ton_external_body_hash ||
        "",
    );

  if (
    !Number.isSafeInteger(
      assignedSeqno,
    ) ||
    assignedSeqno < 0 ||
    !Number.isSafeInteger(
      validUntil,
    ) ||
    validUntil <= 0 ||
    !/^[a-f0-9]{64}$/i.test(
      expectedHash,
    )
  ) {
    throw new Error(
      `Batch ${batchId} has invalid settlement metadata`,
    );
  }

  const currentSeqno =
    await signer
      .openedWallet
      .getSeqno();

  const now =
    Math.floor(
      Date.now() / 1000,
    );

  if (
    currentSeqno <
    assignedSeqno
  ) {
    throw new Error(
      "Treasury wallet seqno moved backwards; refusing settlement",
    );
  }

  if (
    currentSeqno ===
    assignedSeqno
  ) {
    if (
      now > validUntil
    ) {
      await resetExpiredBatch(
        batchId,
      );

      return {
        unresolved: 0,
        paid,
        failed,
        reset: true,
      };
    }

    const allRows =
      await loadBatchMembers(
        batchId,
      );

    if (
      allRows.some(
        (row) =>
          row.status !==
          "processing",
      )
    ) {
      throw new Error(
        `Batch ${batchId} changed status before broadcast. Refusing to rebroadcast automatically.`,
      );
    }

    const {
      transfer,
      bodyHash,
    } =
      buildBatchTransfer({
        signer,
        rows: allRows,
        treasuryJettonWallet,
        seqno:
          assignedSeqno,
        validUntil,
      });

    if (
      expectedHash !==
      bodyHash
    ) {
      throw new Error(
        `Stored batch ${batchId} does not reproduce the same signed transfer. Refusing to rebroadcast.`,
      );
    }

    if (
      AUTOMATIC_SETTLEMENT_ENABLED &&
      PAYOUT_LIVE_MODE
    ) {
      await signer
        .openedWallet
        .send(
          transfer,
        );

      await pool.query(
        `
          UPDATE payouts
          SET
            settlement_attempts =
              settlement_attempts + 1,
            last_settlement_attempt_at =
              NOW(),
            broadcast_at =
              COALESCE(
                broadcast_at,
                NOW()
              )
          WHERE ton_batch_id = $1
            AND status =
              'processing'
        `,
        [batchId],
      );
    }

    return {
      unresolved:
        processingRows.length,
      paid,
      failed,
      rebroadcast: true,
    };
  }

  const oldestBroadcast =
    processingRows
      .map(
        (row) =>
          row.broadcast_at ||
          row.processing_at,
      )
      .filter(Boolean)
      .map(
        (value) =>
          new Date(
            value,
          ).getTime(),
      )
      .sort(
        (a, b) =>
          a - b,
      )[0];

  const graceExpired =
    oldestBroadcast &&
    Date.now() -
      oldestBroadcast >
      PAYOUT_RECONCILE_GRACE_SECONDS *
        1000;

  if (graceExpired) {
    for (
      const row
      of processingRows
    ) {
      await markFailed(
        row,
        "Treasury seqno advanced but recipient delivery was not confirmed within the reconciliation window. Automatic retry is blocked to prevent duplicate payment.",
      );

      failed++;
    }

    unresolved = 0;
  }

  return {
    unresolved,
    paid,
    failed,
  };
}

async function reconcileExisting({
  signer,
  treasuryJettonWallet,
}) {
  const batches =
    (
      await pool.query(
        `
          SELECT
            ton_batch_id,
            MIN(
              processing_at
            ) AS
              oldest_processing_at
          FROM payouts
          WHERE
            ton_batch_id
            IS NOT NULL
            AND status IN (
              'processing',
              'failed'
            )
          GROUP BY
            ton_batch_id
          ORDER BY
            MIN(
              processing_at
            )
            ASC NULLS FIRST,
            ton_batch_id ASC
          LIMIT 100
        `,
      )
    ).rows;

  let unresolved = 0;

  for (
    const item of batches
  ) {
    const result =
      await reconcileBatch({
        signer,

        batchId:
          item.ton_batch_id,

        treasuryJettonWallet,
      });

    unresolved +=
      Number(
        result.unresolved ||
        0,
      );
  }

  return unresolved;
}

async function prepareNewBatch({
  signer,
  treasuryJettonWallet,
  treasuryUsdtBalance,
}) {
  const maxBatch =
    Math.min(
      PAYOUT_BATCH_SIZE,
      signer.maxMessages,
    );

  const candidates =
    (
      await pool.query(
        `
          SELECT *
          FROM payouts
          WHERE
            status = 'pending'
            AND settlement_asset =
              'USDT_TON'
            AND ton_wallet_address
              IS NOT NULL
            AND usdt_amount_micro
              IS NOT NULL
            AND usdt_amount_micro
              > 0
          ORDER BY
            phase_id ASC,
            id ASC
          LIMIT $1
        `,
        [maxBatch],
      )
    ).rows;

  if (
    !candidates.length
  ) {
    return null;
  }

  const resolved = [];
  let totalMicro = 0n;

  for (
    const row
    of candidates
  ) {
    let destination;

    try {
      destination =
        normalizeAddress(
          row
            .ton_wallet_address,
        );
    } catch {
      await markFailed(
        row,
        "Invalid verified TON payout address",
      );

      continue;
    }

    const queryId =
      BigInt(row.id);

    if (
      queryId < 0n ||
      queryId >
        UINT64_MAX
    ) {
      await markFailed(
        row,
        "Payout id cannot be represented as TON uint64 query_id",
      );

      continue;
    }

    const recipientJettonWallet =
      await getJettonWalletAddress(
        destination,
      );

    const amountMicro =
      BigInt(
        row
          .usdt_amount_micro,
      );

    resolved.push({
      ...row,

      ton_wallet_address:
        destination,

      ton_query_id:
        queryId.toString(),

      recipient_jetton_wallet_address:
        normalizeAddress(
          recipientJettonWallet,
        ),
    });

    totalMicro +=
      amountMicro;
  }

  if (!resolved.length) {
    return null;
  }

  if (
    treasuryUsdtBalance <
    totalMicro
  ) {
    console.warn(
      `Auto payout paused: treasury USDT balance ${treasuryUsdtBalance} < batch ${totalMicro}`,
    );

    return null;
  }

  const requiredTon =
    JETTON_TRANSFER_TON_NANO *
      BigInt(
        resolved.length,
      ) +
    TREASURY_TON_RESERVE_NANO;

  const walletTonBalance =
    await tonClient
      .getBalance(
        signer
          .wallet
          .address,
      );

  if (
    walletTonBalance <
    requiredTon
  ) {
    console.warn(
      `Auto payout paused: treasury TON balance ${walletTonBalance} < required ${requiredTon}`,
    );

    return null;
  }

  const seqno =
    await signer
      .openedWallet
      .getSeqno();

  const validUntil =
    Math.floor(
      Date.now() / 1000,
    ) + 300;

  const batchId =
    `pz-${seqno}-${Date.now()}`;

  const rowsForTransfer =
    resolved.map(
      (row) => ({
        ...row,

        ton_wallet_seqno:
          seqno,

        ton_valid_until:
          validUntil,

        ton_batch_id:
          batchId,
      }),
    );

  const {
    transfer,
    bodyHash,
  } =
    buildBatchTransfer({
      signer,

      rows:
        rowsForTransfer,

      treasuryJettonWallet,

      seqno,

      validUntil,
    });

  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN",
    );

    for (
      const row
      of rowsForTransfer
    ) {
      const updated =
        (
          await client.query(
            `
              UPDATE payouts
              SET
                status =
                  'processing',
                processing_at =
                  NOW(),
                failure_reason =
                  NULL,
                ton_query_id =
                  $2,
                ton_wallet_seqno =
                  $3,
                ton_valid_until =
                  $4,
                ton_batch_id =
                  $5,
                recipient_jetton_wallet_address =
                  $6,
                ton_external_body_hash =
                  $7
              WHERE id = $1
                AND status =
                  'pending'
              RETURNING id
            `,
            [
              row.id,

              row
                .ton_query_id,

              seqno,

              validUntil,

              batchId,

              row
                .recipient_jetton_wallet_address,

              bodyHash,
            ],
          )
        ).rows[0];

      if (!updated) {
        throw new Error(
          `Payout ${row.id} changed while batch was being prepared`,
        );
      }

      await audit(
        client,
        "payout_auto_processing",
        row.phase_id,
        {
          payoutId:
            Number(row.id),

          batchId,

          queryId:
            row
              .ton_query_id,

          walletSeqno:
            seqno,

          validUntil,

          recipient:
            row
              .ton_wallet_address,

          recipientJettonWallet:
            row
              .recipient_jetton_wallet_address,

          amountMicro:
            String(
              row
                .usdt_amount_micro,
            ),
        },
      );
    }

    await client.query(
      "COMMIT",
    );
  } catch (error) {
    await client
      .query("ROLLBACK")
      .catch(() => {});

    throw error;
  } finally {
    client.release();
  }

  return {
    batchId,
    seqno,
    validUntil,
    transfer,
    bodyHash,

    count:
      rowsForTransfer
        .length,

    totalMicro,
  };
}

async function broadcastNewBatch(
  signer,
  batch,
) {
  if (
    !AUTOMATIC_SETTLEMENT_ENABLED ||
    !PAYOUT_LIVE_MODE
  ) {
    console.log(
      `Payout batch ${batch.batchId} prepared but not broadcast because live settlement is disabled.`,
    );

    return false;
  }

  await signer
    .openedWallet
    .send(
      batch.transfer,
    );

  await pool.query(
    `
      UPDATE payouts
      SET
        settlement_attempts =
          settlement_attempts + 1,
        last_settlement_attempt_at =
          NOW(),
        broadcast_at =
          COALESCE(
            broadcast_at,
            NOW()
          )
      WHERE ton_batch_id = $1
        AND status =
          'processing'
    `,
    [batch.batchId],
  );

  console.log(
    `Broadcast payout batch ${batch.batchId}: ${batch.count} payouts, ${batch.totalMicro} micro-USDT`,
  );

  return true;
}

async function run() {
  const lockClient =
    await pool.connect();

  let locked = false;

  try {
    await ensureSchema(
      lockClient,
    );

    locked =
      Boolean(
        (
          await lockClient
            .query(
              `
                SELECT
                  pg_try_advisory_lock(
                    $1
                  ) AS locked
              `,
              [
                ADVISORY_LOCK_KEY,
              ],
            )
        ).rows[0]?.locked,
      );

    if (!locked) {
      console.log(
        "Another payout worker is active; exiting safely.",
      );

      return;
    }

    console.log(
      `Project Z payout worker: enabled=${AUTOMATIC_SETTLEMENT_ENABLED} live=${PAYOUT_LIVE_MODE}`,
    );

    if (
      !AUTOMATIC_SETTLEMENT_ENABLED
    ) {
      console.log(
        "Auto payout is disabled. No signer is loaded and no on-chain transaction will be sent.",
      );

      return;
    }

    const signer =
      await resolveWalletSigner();

    console.log(
      `Treasury signer verified: ${signer.version} ${signer.mnemonicType} ${normalizeAddress(
        signer.wallet.address,
      )}`,
    );

    const treasuryJetton =
      await verifyTreasuryJettonWallet();

    const treasuryJettonWallet =
      treasuryJetton.address;

    if (
      treasuryJetton
        .initialized
    ) {
      console.log(
        `Treasury USDT jetton wallet verified: ${normalizeAddress(
          treasuryJettonWallet,
        )}`,
      );
    } else {
      console.log(
        `Treasury USDT jetton wallet is not initialized yet: ${normalizeAddress(
          treasuryJettonWallet,
        )}. Balance is treated as zero until funded.`,
      );
    }

    const unresolved =
      await reconcileExisting({
        signer,
        treasuryJettonWallet,
      });

    if (
      unresolved > 0
    ) {
      console.log(
        `Settlement paused: ${unresolved} earlier payout(s) still await safe reconciliation.`,
      );

      return;
    }

    if (
      !PAYOUT_LIVE_MODE
    ) {
      console.log(
        "Payout preflight passed. Live mode is OFF, so no new payout batch will be prepared or broadcast.",
      );

      return;
    }

    for (
      let batchIndex = 0;
      batchIndex <
      PAYOUT_MAX_BATCHES_PER_RUN;
      batchIndex++
    ) {
      const treasuryState =
        await getTreasuryJettonWalletState(
          treasuryJettonWallet,
        );

      const batch =
        await prepareNewBatch({
          signer,
          treasuryJettonWallet,

          treasuryUsdtBalance:
            treasuryState
              .balance,
        });

      if (!batch) {
        break;
      }

      await broadcastNewBatch(
        signer,
        batch,
      );

      const currentSeqno =
        await waitForSeqno(
          signer
            .openedWallet,
          batch.seqno,
        );

      if (
        currentSeqno <=
        batch.seqno
      ) {
        console.log(
          `Batch ${batch.batchId} is not confirmed by wallet seqno yet; leaving it for safe reconciliation.`,
        );

        break;
      }

      const result =
        await reconcileBatch({
          signer,

          batchId:
            batch.batchId,

          treasuryJettonWallet,
        });

      if (
        result.unresolved >
        0
      ) {
        console.log(
          `Batch ${batch.batchId} still has ${result.unresolved} unconfirmed payout(s); stopping before a new batch.`,
        );

        break;
      }
    }
  } finally {
    if (locked) {
      await lockClient
        .query(
          `
            SELECT
              pg_advisory_unlock(
                $1
              )
          `,
          [
            ADVISORY_LOCK_KEY,
          ],
        )
        .catch(
          () => {},
        );
    }

    lockClient.release();
  }
}

run()
  .catch((error) => {
    console.error(
      "Project Z payout worker failed:",
      safeError(error),
    );

    process.exitCode = 1;
  })
  .finally(async () => {
    await pool
      .end()
      .catch(() => {});
  });
