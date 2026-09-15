import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Pool } from 'pg';
import crypto from 'crypto';
import { mnemonicToPrivateKey } from '@ton/crypto';

const app = express();
app.set('trust proxy', 1);

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 10000);

const BOT_TOKEN =
  process.env.BOT_TOKEN || '';

const DATABASE_URL =
  process.env.DATABASE_URL || '';

const WEBHOOK_SECRET =
  process.env.TELEGRAM_WEBHOOK_SECRET || '';

const APP_URL =
  process.env.APP_URL || '';

const ENTRY_STARS =
  Number(
    process.env.ENTRY_STARS ||
      100
  );

const STAR_USD_RATE =
  Number(
    process.env.STAR_USD_RATE ||
      0.00141
  );

const ENTRY_USD_DISPLAY =
  Number(
    process.env.ENTRY_USD_DISPLAY ||
      2
  );

const PAYMENTS_ENABLED =
  process.env.PAYMENTS_ENABLED ===
  'true';

const ADMIN_SECRET =
  process.env.ADMIN_SECRET || '';

const BOT_USERNAME =
  process.env.BOT_USERNAME || '';

const MOSCOW_TIME_ZONE =
  process.env.MOSCOW_TIME_ZONE ||
  'Europe/Moscow';

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  'https://g5v4jvv5hs-web.github.io';

const TON_PROOF_DOMAIN =
  process.env.TON_PROOF_DOMAIN ||
  (() => {
    try {
      return new URL(
        FRONTEND_ORIGIN
      ).host;
    } catch {
      return '';
    }
  })();

/* =========================================================
   TREASURY
========================================================= */

const TREASURY_MNEMONIC =
  process.env.TREASURY_MNEMONIC ||
  '';

const TREASURY_WALLET_ADDRESS =
  process.env.TREASURY_WALLET_ADDRESS ||
  'UQAr2SdmjtiZmeNJiSFEslRjLv6YBn7BAaU7Dpd7KMi3Jf_q';

const USDT_JETTON_MASTER =
  process.env.USDT_JETTON_MASTER ||
  'EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs';

let treasuryState = {
  configured: Boolean(
    TREASURY_MNEMONIC &&
      TREASURY_WALLET_ADDRESS
  ),

  verified:
    false,

  version:
    null,

  address:
    TREASURY_WALLET_ADDRESS ||
    null
};

/* =========================================================
   REQUIRED ENV
========================================================= */

const requiredEnv = [
  'BOT_TOKEN',
  'DATABASE_URL',
  'TELEGRAM_WEBHOOK_SECRET',
  'APP_URL',
  'ENTRY_STARS'
];

const missingEnv =
  requiredEnv.filter(
    (key) =>
      !process.env[key]
  );

const paymentsReady =
  PAYMENTS_ENABLED &&
  missingEnv.length === 0 &&
  Number.isInteger(
    ENTRY_STARS
  ) &&
  ENTRY_STARS > 0;

/* =========================================================
   DATABASE
========================================================= */

const pool =
  new Pool({
    connectionString:
      DATABASE_URL,

    ssl:
      process.env.NODE_ENV ===
      'production'
        ? {
            rejectUnauthorized:
              false
          }
        : false,

    max:
      20,

    idleTimeoutMillis:
      30000,

    connectionTimeoutMillis:
      10000
  });

/* =========================================================
   SECURITY / CORS
========================================================= */

function originOf(value) {
  try {
    return new URL(
      value
    ).origin;
  } catch {
    return null;
  }
}

const allowedOrigins =
  new Set(
    [
      originOf(
        APP_URL
      ),

      originOf(
        FRONTEND_ORIGIN
      ),

      'https://g5v4jvv5hs-web.github.io'
    ].filter(
      Boolean
    )
  );

app.use(
  helmet({
    contentSecurityPolicy:
      false
  })
);

app.use(
  cors({
    origin(
      origin,
      callback
    ) {
      if (!origin) {
        return callback(
          null,
          true
        );
      }

      return callback(
        null,
        allowedOrigins.has(
          origin
        )
      );
    },

    methods: [
      'GET',
      'POST',
      'OPTIONS'
    ],

    allowedHeaders: [
      'Content-Type',
      'X-Telegram-Init-Data',
      'X-Admin-Secret'
    ]
  })
);

app.use(
  express.json({
    limit:
      '64kb'
  })
);

app.use(
  '/api/',
  rateLimit({
    windowMs:
      60 *
      1000,

    max:
      120,

    standardHeaders:
      true,

    legacyHeaders:
      false
  })
);

/* =========================================================
   HELPERS
========================================================= */

function safeJson(
  value
) {
  try {
    return JSON.stringify(
      value ??
        null
    );
  } catch {
    return null;
  }
}

function getMoscowDateString(
  date =
    new Date()
) {
  return new Intl
    .DateTimeFormat(
      'en-CA',
      {
        timeZone:
          MOSCOW_TIME_ZONE,

        year:
          'numeric',

        month:
          '2-digit',

        day:
          '2-digit'
      }
    )
    .format(
      date
    );
}

function toDateOnlyString(
  value
) {
  if (!value) {
    return null;
  }

  if (
    typeof value ===
    'string'
  ) {
    return value.slice(
      0,
      10
    );
  }

  if (
    value instanceof
    Date
  ) {
    return getMoscowDateString(
      value
    );
  }

  return String(
    value
  ).slice(
    0,
    10
  );
}

function timingSafeStringEqual(
  a,
  b
) {
  if (
    typeof a !==
      'string' ||
    typeof b !==
      'string'
  ) {
    return false;
  }

  const aa =
    Buffer.from(
      a
    );

  const bb =
    Buffer.from(
      b
    );

  return (
    aa.length ===
      bb.length &&
    crypto.timingSafeEqual(
      aa,
      bb
    )
  );
}

function sha256(
  buffer
) {
  return crypto
    .createHash(
      'sha256'
    )
    .update(
      buffer
    )
    .digest();
}

async function audit(
  client,
  eventType,
  actorTelegramId =
    null,
  phaseId =
    null,
  payload =
    null
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
      $2,
      $3,
      $4
    )
    `,
    [
      eventType,
      actorTelegramId,
      phaseId,
      safeJson(
        payload
      )
    ]
  );
}

/* =========================================================
   TREASURY VERIFY
   DOES NOT SEND MONEY
========================================================= */
/* =========================================================
   TREASURY VERIFY
   DOES NOT SEND MONEY
========================================================= */

async function verifyTreasuryWallet() {
  treasuryState = {
    configured:
      Boolean(
        TREASURY_MNEMONIC &&
          TREASURY_WALLET_ADDRESS
      ),

    verified:
      false,

    version:
      null,

    address:
      TREASURY_WALLET_ADDRESS ||
      null
  };

  if (
    !treasuryState
      .configured
  ) {
    console.log(
      'Treasury verification skipped: configuration incomplete.'
    );

    return false;
  }

  try {
    const words =
      TREASURY_MNEMONIC
        .trim()
        .split(
          /\s+/
        )
        .filter(
          Boolean
        );

    if (
      ![12, 24].includes(
        words.length
      )
    ) {
      throw new Error(
        `Expected 12 or 24 mnemonic words, received ${words.length}`
      );
    }

    const keyPair =
      await mnemonicToPrivateKey(
        words
      );

    const {
      Address,
      WalletContractV4,
      WalletContractV5R1
    } =
      await import(
        '@ton/ton'
      );

    const expected =
      Address.parse(
        TREASURY_WALLET_ADDRESS
      );

    const candidates =
      [];

    try {
      const wallet =
        WalletContractV5R1.create({
          workchain:
            0,

          publicKey:
            keyPair.publicKey,

          walletId: {
            networkGlobalId:
              -239
          }
        });

      candidates.push({
        version:
          'V5R1',

        address:
          wallet.address
      });
    } catch (
      error
    ) {
      console.log(
        'V5R1 treasury derivation unavailable:',
        error.message
      );
    }

    try {
      const wallet =
        WalletContractV4.create({
          workchain:
            0,

          publicKey:
            keyPair.publicKey
        });

      candidates.push({
        version:
          'V4R2',

        address:
          wallet.address
      });
    } catch (
      error
    ) {
      console.log(
        'V4R2 treasury derivation unavailable:',
        error.message
      );
    }

    const match =
      candidates.find(
        (
          candidate
        ) =>
          candidate
            .address
            .equals(
              expected
            )
      );

    if (!match) {
      console.error(
        'Treasury verification FAILED: mnemonic does not match configured wallet.'
      );

      for (
        const candidate
        of candidates
      ) {
        console.log(
          `Treasury candidate ${candidate.version}: ${candidate.address.toString()}`
        );
      }

      return false;
    }

    treasuryState = {
      configured:
        true,

      verified:
        true,

      version:
        match.version,

      address:
        match.address.toString()
    };

    console.log(
      'Treasury wallet VERIFIED ✅'
    );

    console.log(
      `Treasury wallet version: ${match.version}`
    );

    console.log(
      `Treasury wallet address: ${match.address.toString()}`
    );

    console.log(
      'Automatic on-chain settlement: DISABLED'
    );

    return true;
  } catch (
    error
  ) {
    console.error(
      'Treasury verification error:',
      error.message
    );

    return false;
  }
}
/* =========================================================
   TELEGRAM INIT DATA
========================================================= */

function verifyInitData(
  initData
) {
  if (
    !initData ||
    typeof initData !==
      'string' ||
    !BOT_TOKEN
  ) {
    return null;
  }

  try {
    const params =
      new URLSearchParams(
        initData
      );

    const receivedHash =
      params.get(
        'hash'
      );

    if (
      !receivedHash ||
      !/^[a-fA-F0-9]{64}$/.test(
        receivedHash
      )
    ) {
      return null;
    }

    params.delete(
      'hash'
    );

    const dataCheckString =
      [
        ...params.entries()
      ]
        .sort(
          ([a], [b]) =>
            a.localeCompare(
              b
            )
        )
        .map(
          (
            [
              key,
              value
            ]
          ) =>
            `${key}=${value}`
        )
        .join(
          '\n'
        );

    const secretKey =
      crypto
        .createHmac(
          'sha256',
          'WebAppData'
        )
        .update(
          BOT_TOKEN
        )
        .digest();

    const calculatedHash =
      crypto
        .createHmac(
          'sha256',
          secretKey
        )
        .update(
          dataCheckString
        )
        .digest(
          'hex'
        );

    if (
      !timingSafeStringEqual(
        receivedHash
          .toLowerCase(),
        calculatedHash
      )
    ) {
      return null;
    }

    const authDate =
      Number(
        params.get(
          'auth_date'
        ) ||
          0
      );

    if (
      !Number.isSafeInteger(
        authDate
      ) ||
      authDate <=
        0
    ) {
      return null;
    }

    const age =
      Math.floor(
        Date.now() /
          1000
      ) -
      authDate;

    if (
      age <
        -60 ||
      age >
        86400
    ) {
      return null;
    }

    const rawUser =
      params.get(
        'user'
      );

    if (!rawUser) {
      return null;
    }

    const user =
      JSON.parse(
        rawUser
      );

    if (
      !user ||
      !Number.isSafeInteger(
        user.id
      ) ||
      user.id <=
        0
    ) {
      return null;
    }

    return user;
  } catch {
    return null;
  }
}

function getInitData(
  req
) {
  return (
    req.headers[
      'x-telegram-init-data'
    ] ||
    req.body
      ?.initData ||
    ''
  );
}

/* =========================================================
   TELEGRAM API
========================================================= */

async function telegramApi(
  method,
  body = {}
) {
  if (!BOT_TOKEN) {
    throw new Error(
      'BOT_TOKEN missing'
    );
  }

  const response =
    await fetch(
      `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
      {
        method:
          'POST',

        headers: {
          'Content-Type':
            'application/json'
        },

        body:
          JSON.stringify(
            body
          ),

        signal:
          AbortSignal.timeout(
            10000
          )
      }
    );

  const data =
    await response.json();

  if (
    !response.ok ||
    !data.ok
  ) {
    throw new Error(
      data.description ||
        `Telegram ${method} failed`
    );
  }

  return data.result;
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {
  const client =
    await pool.connect();

  try {
    await client.query(
      'BEGIN'
    );

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,

        telegram_id BIGINT NOT NULL UNIQUE,

        username TEXT,

        first_name TEXT,

        last_name TEXT,

        language_code TEXT,

        is_premium BOOLEAN DEFAULT FALSE,

        ton_wallet_address TEXT,

        ton_wallet_public_key TEXT,

        ton_wallet_chain INTEGER,

        ton_wallet_verified_at TIMESTAMPTZ,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS ton_proof_challenges (
        id BIGSERIAL PRIMARY KEY,

        telegram_user_id BIGINT NOT NULL,

        nonce TEXT NOT NULL UNIQUE,

        domain TEXT NOT NULL,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        expires_at TIMESTAMPTZ NOT NULL,

        used_at TIMESTAMPTZ
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS phases (
        id BIGSERIAL PRIMARY KEY,

        phase_date DATE NOT NULL UNIQUE,

        status TEXT NOT NULL DEFAULT 'open',

        total_stars NUMERIC(30,0) NOT NULL DEFAULT 0,

        winner_pool_stars NUMERIC(30,0) NOT NULL DEFAULT 0,

        charity_stars NUMERIC(30,0) NOT NULL DEFAULT 0,

        operations_stars NUMERIC(30,0) NOT NULL DEFAULT 0,

        winner_count INTEGER NOT NULL DEFAULT 0,

        first_verified_entry_id BIGINT,

        finalized_at TIMESTAMPTZ,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS invoices (
        id BIGSERIAL PRIMARY KEY,

        invoice_token TEXT NOT NULL UNIQUE,

        telegram_user_id BIGINT NOT NULL,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        stars_amount NUMERIC(30,0) NOT NULL,

        payload TEXT NOT NULL UNIQUE,

        status TEXT NOT NULL DEFAULT 'created',

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        expires_at TIMESTAMPTZ NOT NULL
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id BIGSERIAL PRIMARY KEY,

        telegram_payment_charge_id TEXT NOT NULL UNIQUE,

        telegram_user_id BIGINT NOT NULL,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        stars_amount NUMERIC(30,0) NOT NULL,

        currency TEXT NOT NULL,

        invoice_payload TEXT NOT NULL,

        status TEXT NOT NULL,

        refund_attempts INTEGER NOT NULL DEFAULT 0,

        refund_last_error TEXT,

        last_refund_attempt_at TIMESTAMPTZ,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payment_reconciliations (
        id BIGSERIAL PRIMARY KEY,

        telegram_payment_charge_id TEXT UNIQUE,

        telegram_user_id BIGINT,

        invoice_payload TEXT,

        currency TEXT,

        stars_amount NUMERIC(30,0),

        reason TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'needs_review',

        raw_payload JSONB,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS entries (
        id BIGSERIAL PRIMARY KEY,

        telegram_user_id BIGINT NOT NULL,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        payment_id BIGINT
          REFERENCES payments(id),

        is_free BOOLEAN NOT NULL DEFAULT FALSE,

        is_first_payer BOOLEAN NOT NULL DEFAULT FALSE,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          telegram_user_id,
          phase_id
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS referral_links (
        id BIGSERIAL PRIMARY KEY,

        referrer_id BIGINT NOT NULL,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        code TEXT NOT NULL UNIQUE,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          referrer_id,
          phase_id
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS referral_attachments (
        id BIGSERIAL PRIMARY KEY,

        referred_user_id BIGINT NOT NULL,

        referrer_id BIGINT NOT NULL,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        referral_link_id BIGINT
          REFERENCES referral_links(id),

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          referred_user_id,
          phase_id
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS referral_conversions (
        id BIGSERIAL PRIMARY KEY,

        referred_user_id BIGINT NOT NULL,

        referrer_id BIGINT NOT NULL,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        payment_id BIGINT NOT NULL
          REFERENCES payments(id),

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          referred_user_id,
          phase_id
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS free_entry_grants (
        id BIGSERIAL PRIMARY KEY,

        telegram_user_id BIGINT NOT NULL,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        reason TEXT NOT NULL,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          telegram_user_id,
          phase_id
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS winners (
        id BIGSERIAL PRIMARY KEY,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        entry_id BIGINT NOT NULL UNIQUE,

        telegram_user_id BIGINT NOT NULL,

        rank INTEGER NOT NULL,

        prize_stars NUMERIC(30,0) NOT NULL,

        is_first_payer BOOLEAN NOT NULL DEFAULT FALSE,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          phase_id,
          rank
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payouts (
        id BIGSERIAL PRIMARY KEY,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id)
          ON DELETE CASCADE,

        winner_id BIGINT NOT NULL
          REFERENCES winners(id)
          ON DELETE CASCADE,

        telegram_user_id BIGINT NOT NULL,

        amount_stars NUMERIC(30,0) NOT NULL
          CHECK (
            amount_stars > 0
          ),

        prize_usd NUMERIC(20,6),

        usdt_amount_micro BIGINT,

        settlement_asset TEXT NOT NULL DEFAULT 'USDT_TON',

        status TEXT NOT NULL DEFAULT 'pending',

        ton_wallet_address TEXT,

        ton_tx_hash TEXT,

        settlement_reference TEXT,

        failure_reason TEXT,

        processing_at TIMESTAMPTZ,

        paid_at TIMESTAMPTZ,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          winner_id
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS allocations (
        id BIGSERIAL PRIMARY KEY,

        phase_id BIGINT NOT NULL
          REFERENCES phases(id),

        type TEXT NOT NULL,

        stars_amount NUMERIC(30,0) NOT NULL,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE (
          phase_id,
          type
        )
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,

        event_type TEXT NOT NULL,

        actor_telegram_id BIGINT,

        phase_id BIGINT
          REFERENCES phases(id),

        payload JSONB,

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const migrations = [
      `
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS
      refund_attempts INTEGER NOT NULL DEFAULT 0
      `,

      `
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS
      refund_last_error TEXT
      `,

      `
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS
      last_refund_attempt_at TIMESTAMPTZ
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      prize_usd NUMERIC(20,6)
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      usdt_amount_micro BIGINT
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      settlement_asset TEXT NOT NULL DEFAULT 'USDT_TON'
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      settlement_reference TEXT
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      ton_wallet_address TEXT
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      ton_tx_hash TEXT
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      failure_reason TEXT
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      processing_at TIMESTAMPTZ
      `,

      `
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS
      paid_at TIMESTAMPTZ
      `
    ];

    for (
      const ddl
      of migrations
    ) {
      await client.query(
        ddl
      );
    }

    const indexes = [
      `
      CREATE INDEX IF NOT EXISTS
      idx_entries_phase
      ON entries(
        phase_id
      )
      `,

      `
      CREATE INDEX IF NOT EXISTS
      idx_payments_phase
      ON payments(
        phase_id
      )
      `,

      `
      CREATE INDEX IF NOT EXISTS
      idx_payouts_status
      ON payouts(
        status
      )
      `,

      `
      CREATE INDEX IF NOT EXISTS
      idx_referral_conversions
      ON referral_conversions(
        referrer_id,
        phase_id
      )
      `,

      `
      CREATE INDEX IF NOT EXISTS
      idx_ton_challenges
      ON ton_proof_challenges(
        telegram_user_id
      )
      `
    ];

    for (
      const sql
      of indexes
    ) {
      await client.query(
        sql
      );
    }

    await client.query(
      'COMMIT'
    );

    console.log(
      'Database initialized successfully.'
    );
  } catch (
    error
  ) {
    try {
      await client.query(
        'ROLLBACK'
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   PHASES / USERS
========================================================= */

async function getCurrentPhase(
  client,
  create =
    true
) {
  const phaseDate =
    getMoscowDateString();

  let result =
    await client.query(
      `
      SELECT *
      FROM phases
      WHERE
        phase_date =
          $1
      `,
      [
        phaseDate
      ]
    );

  if (
    result.rows.length
  ) {
    return result.rows[0];
  }

  if (!create) {
    return null;
  }

  await client.query(
    `
    INSERT INTO phases (
      phase_date,
      status
    )
    VALUES (
      $1,
      'open'
    )
    ON CONFLICT (
      phase_date
    )
    DO NOTHING
    `,
    [
      phaseDate
    ]
  );

  result =
    await client.query(
      `
      SELECT *
      FROM phases
      WHERE
        phase_date =
          $1
      `,
      [
        phaseDate
      ]
    );

  return result.rows[0];
}

async function ensureUser(
  client,
  telegramUser
) {
  await client.query(
    `
    INSERT INTO users (
      telegram_id,
      username,
      first_name,
      last_name,
      language_code,
      is_premium,
      updated_at
    )
    VALUES (
      $1,
      $2,
      $3,
      $4,
      $5,
      $6,
      NOW()
    )

    ON CONFLICT (
      telegram_id
    )

    DO UPDATE SET
      username =
        EXCLUDED.username,

      first_name =
        EXCLUDED.first_name,

      last_name =
        EXCLUDED.last_name,

      language_code =
        EXCLUDED.language_code,

      is_premium =
        EXCLUDED.is_premium,

      updated_at =
        NOW()
    `,
    [
      telegramUser.id,

      telegramUser.username ||
        null,

      telegramUser.first_name ||
        null,

      telegramUser.last_name ||
        null,

      telegramUser.language_code ||
        null,

      Boolean(
        telegramUser.is_premium
      )
    ]
  );
}

/* =========================================================
   WINNER COUNT
========================================================= */

function getWinnerCountFromUsd(
  poolUsd
) {
  const usd =
    Number(
      poolUsd
    );

  if (
    !Number.isFinite(
      usd
    ) ||
    usd <
      100
  ) {
    return 0;
  }

  if (usd < 300) return 10;
  if (usd < 600) return 20;
  if (usd < 1200) return 30;
  if (usd < 2000) return 40;
  if (usd < 4000) return 50;
  if (usd < 8000) return 80;
  if (usd < 12000) return 100;
  if (usd < 15000) return 120;
  if (usd < 25000) return 185;
  if (usd < 35000) return 250;
  if (usd < 50000) return 350;
  if (usd < 70000) return 550;
  if (usd < 130000) return 1000;
  if (usd < 170000) return 1300;
  if (usd < 250000) return 2000;
  if (usd < 400000) return 3000;
  if (usd < 650000) return 50000;
  if (usd < 1000000) return 10000;
  if (usd < 2000000) return 30000;
  if (usd < 4000000) return 50000;
  if (usd < 10000000) return 100000;

  return 100000;
}

function secureShuffle(
  items
) {
  const copy =
    [
      ...items
    ];

  for (
    let i =
      copy.length -
      1;

    i >
      0;

    i--
  ) {
    const j =
      crypto.randomInt(
        0,
        i +
          1
      );

    [
      copy[i],
      copy[j]
    ] = [
      copy[j],
      copy[i]
    ];
  }

  return copy;
}

/* =========================================================
   REFERRAL
========================================================= */

function makeReferralCode(
  userId,
  phaseDate
) {
  return (
    `ref_${userId}_` +
    `${String(
      phaseDate
    ).replaceAll(
      '-',
      ''
    )}_` +
    crypto
      .randomBytes(
        8
      )
      .toString(
        'hex'
      )
  );
}

async function getOrCreateReferralLink(
  client,
  userId,
  phase
) {
  const existing =
    await client.query(
      `
      SELECT *
      FROM referral_links

      WHERE
        referrer_id =
          $1

        AND phase_id =
          $2
      `,
      [
        userId,
        phase.id
      ]
    );

  if (
    existing.rows.length
  ) {
    return existing.rows[0];
  }

  const code =
    makeReferralCode(
      userId,
      toDateOnlyString(
        phase.phase_date
      )
    );

  const result =
    await client.query(
      `
      INSERT INTO referral_links (
        referrer_id,
        phase_id,
        code
      )
      VALUES (
        $1,
        $2,
        $3
      )

      ON CONFLICT (
        referrer_id,
        phase_id
      )

      DO UPDATE SET
        code =
          referral_links.code

      RETURNING *
      `,
      [
        userId,
        phase.id,
        code
      ]
    );

  return result.rows[0];
}

/* =========================================================
   TELEGRAM STARS INVOICE
========================================================= */

async function createEntryInvoice(
  userId,
  phaseId
) {
  const nonce =
    crypto
      .randomBytes(
        16
      )
      .toString(
        'hex'
      );

  const payload =
    `pz_entry:${phaseId}:${userId}:${nonce}`;

  const link =
    await telegramApi(
      'createInvoiceLink',
      {
        title:
          'Project Z Entry',

        description:
          'Daily Project Z entry',

        payload,

        currency:
          'XTR',

        prices: [
          {
            label:
              'Project Z Entry',

            amount:
              ENTRY_STARS
          }
        ]
      }
    );

  return {
    link,
    payload
  };
}

/* =========================================================
   TON PROOF
========================================================= */

function createTonProofNonce() {
  return crypto
    .randomBytes(
      32
    )
    .toString(
      'hex'
    );
}

function normalizeTonAddress(
  value
) {
  return (
    typeof value ===
      'string' &&
    value.trim()
      ? value.trim()
      : null
  );
}

function buildTonProofDigest(
  address,
  proof
) {
  const workchain =
    Buffer.alloc(
      4
    );

  workchain.writeInt32BE(
    address.workChain,
    0
  );

  const domainBytes =
    Buffer.from(
      proof.domain.value,
      'utf8'
    );

  if (
    proof.domain
      .lengthBytes !==
    domainBytes.length
  ) {
    throw new Error(
      'TON Proof domain length mismatch'
    );
  }

  const domainLength =
    Buffer.alloc(
      4
    );

  domainLength.writeUInt32LE(
    domainBytes.length,
    0
  );

  const timestamp =
    Buffer.alloc(
      8
    );

  timestamp.writeBigUInt64LE(
    BigInt(
      proof.timestamp
    ),
    0
  );

  const message =
    Buffer.concat([
      Buffer.from(
        'ton-proof-item-v2/',
        'utf8'
      ),

      workchain,

      Buffer.from(
        address.hash
      ),

      domainLength,

      domainBytes,

      timestamp,

      Buffer.from(
        proof.payload,
        'utf8'
      )
    ]);

  return sha256(
    Buffer.concat([
      Buffer.from([
        0xff,
        0xff
      ]),

      Buffer.from(
        'ton-connect',
        'utf8'
      ),

      sha256(
        message
      )
    ])
  );
}

async function extractTonWalletPublicKey(
  stateInit
) {
  const ton =
    await import(
      '@ton/ton'
    );

  if (
    !stateInit
      ?.code ||
    !stateInit
      ?.data
  ) {
    return null;
  }

  const definitions = [
    [
      'WalletContractV1R1',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV1R2',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV1R3',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV2R1',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV2R2',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV3R1',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV3R2',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV4',

      (
        slice
      ) => {
        slice.loadUint(
          32
        );

        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ],

    [
      'WalletContractV5R1',

      (
        slice
      ) => {
        slice.loadBoolean();

        slice.loadUint(
          32
        );

        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      }
    ]
  ];

  for (
    const [
      name,
      loader
    ]
    of definitions
  ) {
    const Contract =
      ton[name];

    if (
      !Contract
        ?.create
    ) {
      continue;
    }

    try {
      const instance =
        Contract.create({
          workchain:
            0,

          publicKey:
            Buffer.alloc(
              32
            )
        });

      if (
        instance.init
          ?.code
          ?.equals(
            stateInit.code
          )
      ) {
        const key =
          loader(
            stateInit
              .data
              .beginParse()
          );

        if (
          Buffer.isBuffer(
            key
          ) &&
          key.length ===
            32
        ) {
          return key;
        }
      }
    } catch {}
  }

  return null;
}

/* =========================================================
   TON NONCE
========================================================= */

app.post(
  '/api/tonconnect/nonce',

  async (
    req,
    res
  ) => {
    const user =
      verifyInitData(
        getInitData(
          req
        )
      );

    if (!user) {
      return res
        .status(
          401
        )
        .json({
          ok:
            false,

          error:
            'Invalid Telegram initData'
        });
    }

    if (
      !TON_PROOF_DOMAIN
    ) {
      return res
        .status(
          503
        )
        .json({
          ok:
            false,

          error:
            'TON proof domain is not configured'
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      await ensureUser(
        client,
        user
      );

      await client.query(
        `
        SELECT
          telegram_id

        FROM
          users

        WHERE
          telegram_id =
            $1

        FOR UPDATE
        `,
        [
          user.id
        ]
      );

      const nonce =
        createTonProofNonce();

      const expiresAt =
        new Date(
          Date.now() +
            10 *
              60 *
              1000
        );

      await client.query(
        `
        UPDATE
          ton_proof_challenges

        SET
          used_at =
            NOW()

        WHERE
          telegram_user_id =
            $1

          AND used_at
            IS NULL
        `,
        [
          user.id
        ]
      );

      await client.query(
        `
        INSERT INTO ton_proof_challenges (
          telegram_user_id,
          nonce,
          domain,
          expires_at
        )
        VALUES (
          $1,
          $2,
          $3,
          $4
        )
        `,
        [
          user.id,
          nonce,
          TON_PROOF_DOMAIN,
          expiresAt
        ]
      );

      await audit(
        client,

        'ton_proof_challenge_created',

        user.id,

        null,

        {
          domain:
            TON_PROOF_DOMAIN,

          expiresAt:
            expiresAt.toISOString()
        }
      );

      await client.query(
        'COMMIT'
      );

      return res.json({
        ok:
          true,

        nonce,

        domain:
          TON_PROOF_DOMAIN,

        expiresAt:
          expiresAt.toISOString()
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'TON nonce error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          ok:
            false,

          error:
            'Failed to create TON Proof challenge'
        });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   TON VERIFY
========================================================= */

app.post(
  '/api/tonconnect/verify',

  async (
    req,
    res
  ) => {
    const user =
      verifyInitData(
        getInitData(
          req
        )
      );

    if (!user) {
      return res
        .status(
          401
        )
        .json({
          ok:
            false,

          error:
            'Invalid Telegram initData'
        });
    }

    const proof =
      req.body
        ?.proof;

    const addressString =
      normalizeTonAddress(
        req.body
          ?.address
      );

    const walletStateInit =
      req.body
        ?.walletStateInit;

    const network =
      String(
        req.body
          ?.network ??
          ''
      );

    if (
      !proof ||
      !addressString ||
      !walletStateInit
    ) {
      return res
        .status(
          400
        )
        .json({
          ok:
            false,

          error:
            'Missing TON Proof data'
        });
    }

    if (
      network !==
      '-239'
    ) {
      return res
        .status(
          400
        )
        .json({
          ok:
            false,

          error:
            'Only TON mainnet wallets are accepted'
        });
    }

    if (
      !proof.domain ||
      typeof proof
        .domain
        .value !==
        'string' ||
      !Number.isSafeInteger(
        proof
          .domain
          .lengthBytes
      ) ||
      proof
        .domain
        .lengthBytes <
        0 ||
      typeof proof
        .payload !==
        'string' ||
      typeof proof
        .signature !==
        'string'
    ) {
      return res
        .status(
          400
        )
        .json({
          ok:
            false,

          error:
            'Invalid TON Proof structure'
        });
    }

    let proofTimestamp;

    try {
      proofTimestamp =
        BigInt(
          proof.timestamp
        );
    } catch {
      return res
        .status(
          400
        )
        .json({
          ok:
            false,

          error:
            'Invalid TON Proof timestamp'
        });
    }

    const now =
      BigInt(
        Math.floor(
          Date.now() /
            1000
        )
      );

    if (
      proofTimestamp >
        now +
          60n ||
      now -
        proofTimestamp >
        15n *
          60n
    ) {
      return res
        .status(
          401
        )
        .json({
          ok:
            false,

          error:
            'TON Proof expired'
        });
    }

    if (
      !TON_PROOF_DOMAIN ||
      proof.domain.value !==
        TON_PROOF_DOMAIN
    ) {
      return res
        .status(
          401
        )
        .json({
          ok:
            false,

          error:
            'TON Proof domain mismatch'
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      await ensureUser(
        client,
        user
      );

      const challengeResult =
        await client.query(
          `
          SELECT
            id,
            nonce,
            domain,
            expires_at,
            used_at

          FROM
            ton_proof_challenges

          WHERE
            telegram_user_id =
              $1

            AND nonce =
              $2

            AND domain =
              $3

          ORDER BY
            id DESC

          LIMIT 1

          FOR UPDATE
          `,
          [
            user.id,
            proof.payload,
            TON_PROOF_DOMAIN
          ]
        );

      if (
        !challengeResult
          .rows
          .length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            401
          )
          .json({
            ok:
              false,

            error:
              'Invalid or unknown TON Proof nonce'
          });
      }

      const challenge =
        challengeResult
          .rows[0];

      if (
        challenge.used_at ||
        new Date(
          challenge.expires_at
        ).getTime() <=
          Date.now()
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            401
          )
          .json({
            ok:
              false,

            error:
              'TON Proof nonce expired or already used'
          });
      }

      const {
        Address,
        Cell,
        contractAddress,
        loadStateInit
      } =
        await import(
          '@ton/ton'
        );

      const wantedAddress =
        Address.parse(
          addressString
        );

      if (
        wantedAddress
          .workChain !==
        0
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            400
          )
          .json({
            ok:
              false,

            error:
              'Only basechain TON wallets are accepted'
          });
      }

      const stateInitCell =
        Cell.fromBase64(
          walletStateInit
        );

      const stateInit =
        loadStateInit(
          stateInitCell
            .beginParse()
        );

      const derivedAddress =
        contractAddress(
          wantedAddress
            .workChain,

          stateInit
        );

      if (
        !derivedAddress
          .equals(
            wantedAddress
          )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            401
          )
          .json({
            ok:
              false,

            error:
              'walletStateInit does not match wallet address'
          });
      }

      const publicKey =
        await extractTonWalletPublicKey(
          stateInit
        );

      if (!publicKey) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            400
          )
          .json({
            ok:
              false,

            error:
              'Unsupported TON wallet contract'
          });
      }

      const digest =
        buildTonProofDigest(
          wantedAddress,

          {
            ...proof,

            timestamp:
              proofTimestamp.toString()
          }
        );

      const signature =
        Buffer.from(
          proof.signature,
          'base64'
        );

      if (
        signature.length !==
        64
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            401
          )
          .json({
            ok:
              false,

            error:
              'Invalid TON Proof signature'
          });
      }

      const spki =
        Buffer.concat([
          Buffer.from(
            '302a300506032b6570032100',
            'hex'
          ),

          publicKey
        ]);

      const valid =
        crypto.verify(
          null,

          digest,

          {
            key:
              spki,

            format:
              'der',

            type:
              'spki'
          },

          signature
        );

      if (!valid) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            401
          )
          .json({
            ok:
              false,

            error:
              'TON Proof signature verification failed'
          });
      }

      const consumed =
        await client.query(
          `
          UPDATE
            ton_proof_challenges

          SET
            used_at =
              NOW()

          WHERE
            id =
              $1

            AND used_at
              IS NULL

            AND expires_at >
              NOW()

          RETURNING
            id
          `,
          [
            challenge.id
          ]
        );

      if (
        !consumed
          .rows
          .length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            409
          )
          .json({
            ok:
              false,

            error:
              'TON Proof challenge already consumed'
          });
      }

      const canonicalAddress =
        wantedAddress.toString();

      await client.query(
        `
        UPDATE
          users

        SET
          ton_wallet_address =
            $1,

          ton_wallet_public_key =
            $2,

          ton_wallet_chain =
            $3,

          ton_wallet_verified_at =
            NOW(),

          updated_at =
            NOW()

        WHERE
          telegram_id =
            $4
        `,
        [
          canonicalAddress,

          publicKey.toString(
            'hex'
          ),

          -239,

          user.id
        ]
      );

      await client.query(
        `
        UPDATE
          payouts

        SET
          ton_wallet_address =
            $1,

          status =
            CASE

              WHEN status =
                'waiting_wallet'

              THEN
                'pending'

              ELSE
                status

            END

        WHERE
          telegram_user_id =
            $2

          AND (
            ton_wallet_address
              IS NULL

            OR
            ton_wallet_address =
              ''
          )
        `,
        [
          canonicalAddress,
          user.id
        ]
      );

      await audit(
        client,

        'ton_wallet_verified',

        user.id,

        null,

        {
          walletAddress:
            canonicalAddress,

          network:
            -239
        }
      );

      await client.query(
        'COMMIT'
      );

      return res.json({
        ok:
          true,

        verified:
          true,

        walletAddress:
          canonicalAddress,

        network:
          -239
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'TON Proof verification error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          ok:
            false,

          error:
            'TON Proof verification failed'
        });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  '/health',

  async (
    _req,
    res
  ) => {
    let databaseOk =
      false;

    try {
      await pool.query(
        'SELECT 1'
      );

      databaseOk =
        true;
    } catch {}

    return res
      .status(
        databaseOk
          ? 200
          : 503
      )
      .json({
        ok:
          databaseOk,

        project:
          'Project Z',

        paymentsReady,

        database:
          databaseOk,

        missingEnv,

        frontendOrigin:
          FRONTEND_ORIGIN,

        tonProofDomain:
          TON_PROOF_DOMAIN,

        treasuryConfigured:
          treasuryState
            .configured,

        treasuryVerified:
          treasuryState
            .verified,

        treasuryWalletVersion:
          treasuryState
            .version,

        treasuryAddress:
          treasuryState
            .address,

        settlementAsset:
          'USDT_TON',

        automaticSettlementEnabled:
          false,

        usdtJettonMaster:
          USDT_JETTON_MASTER,

        entryStars:
          ENTRY_STARS,

        entryUsdDisplay:
          ENTRY_USD_DISPLAY,

        starUsdRate:
          STAR_USD_RATE,

        moscowDate:
          getMoscowDateString(),

        time:
          new Date()
            .toISOString()
      });
  }
);

app.get(
  '/',

  (
    _req,
    res
  ) => {
    return res.json({
      name:
        'Project Z',

      status:
        'running',

      paymentsReady,

      treasuryVerified:
        treasuryState
          .verified,

      automaticSettlementEnabled:
        false,

      moscowDate:
        getMoscowDateString()
    });
  }
);

/* =========================================================
   STATS
========================================================= */

app.get(
  '/api/stats',

  async (
    _req,
    res
  ) => {
    const client =
      await pool.connect();

    try {
      const phase =
        await getCurrentPhase(
          client
        );

      const totalStars =
        Number(
          phase.total_stars ||
            0
        );

      const poolStars =
        Math.floor(
          totalStars *
            0.70
        );

      const poolUsd =
        poolStars *
        STAR_USD_RATE;

      const countResult =
        await client.query(
          `
          SELECT
            COUNT(*)::int
              AS count

          FROM
            entries

          WHERE
            phase_id =
              $1
          `,
          [
            phase.id
          ]
        );

      const participantResult =
        await client.query(
          `
          SELECT
            u.username,

            u.first_name,

            u.last_name,

            e.created_at,

            e.is_first_payer,

            e.is_free

          FROM
            entries e

          JOIN
            users u

          ON
            u.telegram_id =
              e.telegram_user_id

          WHERE
            e.phase_id =
              $1

          ORDER BY
            e.id DESC

          LIMIT
            20
          `,
          [
            phase.id
          ]
        );

      return res.json({
        phaseDate:
          toDateOnlyString(
            phase.phase_date
          ),

        status:
          phase.status,

        totalStars,

        poolStars,

        poolUsd:
          Number(
            poolUsd.toFixed(
              4
            )
          ),

        participants:
          Number(
            countResult
              .rows[0]
              .count
          ),

        participantList:
          participantResult
            .rows
            .map(
              (
                row
              ) => {
                const fullName =
                  [
                    row.first_name,

                    row.last_name
                  ]
                    .filter(
                      Boolean
                    )
                    .join(
                      ' '
                    )
                    .trim();

                return {
                  username:
                    row.username ||
                    null,

                  displayName:
                    row.username ||
                    fullName ||
                    'Participant',

                  createdAt:
                    row.created_at,

                  isFirstPayer:
                    Boolean(
                      row.is_first_payer
                    ),

                  isFree:
                    Boolean(
                      row.is_free
                    )
                };
              }
            ),

        winnerCount:
          getWinnerCountFromUsd(
            poolUsd
          ),

        firstPayerGuaranteed:
          true,

        entryStars:
          ENTRY_STARS,

        entryUsdDisplay:
          ENTRY_USD_DISPLAY,

        paymentsEnabled:
          paymentsReady
      });
    } catch (
      error
    ) {
      console.error(
        'stats error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          error:
            'db_error'
        });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   USER STATUS
========================================================= */

app.post(
  '/api/user-status',

  async (
    req,
    res
  ) => {
    const user =
      verifyInitData(
        getInitData(
          req
        )
      );

    if (!user) {
      return res
        .status(
          401
        )
        .json({
          error:
            'invalid_init_data'
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      await ensureUser(
        client,
        user
      );

      const phase =
        await getCurrentPhase(
          client
        );

      const entry =
        await client.query(
          `
          SELECT *
          FROM entries

          WHERE
            telegram_user_id =
              $1

            AND phase_id =
              $2
          `,
          [
            user.id,
            phase.id
          ]
        );

      const conversions =
        await client.query(
          `
          SELECT
            COUNT(*)::int
              AS count

          FROM
            referral_conversions

          WHERE
            referrer_id =
              $1

            AND phase_id =
              $2
          `,
          [
            user.id,
            phase.id
          ]
        );

      const grant =
        await client.query(
          `
          SELECT
            id

          FROM
            free_entry_grants

          WHERE
            telegram_user_id =
              $1

            AND phase_id =
              $2
          `,
          [
            user.id,
            phase.id
          ]
        );

      const wallet =
        await client.query(
          `
          SELECT
            ton_wallet_address,

            ton_wallet_verified_at

          FROM
            users

          WHERE
            telegram_id =
              $1
          `,
          [
            user.id
          ]
        );

      const referralLink =
        await getOrCreateReferralLink(
          client,
          user.id,
          phase
        );

      await client.query(
        'COMMIT'
      );

      const referralCount =
        Number(
          conversions
            .rows[0]
            .count
        );

      return res.json({
        phaseDate:
          toDateOnlyString(
            phase.phase_date
          ),

        hasEntry:
          entry.rows.length >
          0,

        isFree:
          Boolean(
            entry.rows[0]
              ?.is_free
          ),

        isFirstPayer:
          Boolean(
            entry.rows[0]
              ?.is_first_payer
          ),

        referralProgress:
          Math.min(
            referralCount,
            2
          ),

        qualifyingReferrals:
          referralCount,

        freeUnlocked:
          grant.rows.length >
            0 ||
          referralCount >=
            2,

        referralCode:
          referralLink.code,

        referralLink:
          BOT_USERNAME
            ? `https://t.me/${BOT_USERNAME}?startapp=${encodeURIComponent(
                referralLink.code
              )}`
            : null,

        walletVerified:
          Boolean(
            wallet.rows[0]
              ?.ton_wallet_verified_at
          ),

        walletAddress:
          wallet.rows[0]
            ?.ton_wallet_address ||
          null
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'user-status error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          error:
            'db_error'
        });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ATTACH REFERRAL
========================================================= */

app.post(
  '/api/attach-referral',

  async (
    req,
    res
  ) => {
    const user =
      verifyInitData(
        getInitData(
          req
        )
      );

    if (!user) {
      return res
        .status(
          401
        )
        .json({
          error:
            'invalid_init_data'
        });
    }

    const code =
      String(
        req.body
          ?.code ||
          ''
      ).trim();

    if (
      !/^ref_\d+_\d{8}_[a-f0-9]{16}$/.test(
        code
      )
    ) {
      return res
        .status(
          400
        )
        .json({
          error:
            'bad_referral_code'
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      await ensureUser(
        client,
        user
      );

      const phase =
        await getCurrentPhase(
          client
        );

      const link =
        await client.query(
          `
          SELECT
            rl.*

          FROM
            referral_links rl

          JOIN
            phases p

          ON
            p.id =
              rl.phase_id

          WHERE
            rl.code =
              $1

            AND rl.phase_id =
              $2

            AND p.phase_date =
              $3

            AND p.status =
              'open'

          FOR UPDATE OF
            rl
          `,
          [
            code,
            phase.id,
            getMoscowDateString()
          ]
        );

      if (
        !link.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            400
          )
          .json({
            error:
              'expired_or_invalid_referral'
          });
      }

      const referral =
        link.rows[0];

      if (
        Number(
          referral.referrer_id
        ) ===
        Number(
          user.id
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            400
          )
          .json({
            error:
              'self_referral'
          });
      }

      await client.query(
        `
        INSERT INTO referral_attachments (
          referred_user_id,
          referrer_id,
          phase_id,
          referral_link_id
        )

        VALUES (
          $1,
          $2,
          $3,
          $4
        )

        ON CONFLICT (
          referred_user_id,
          phase_id
        )

        DO NOTHING
        `,
        [
          user.id,
          referral.referrer_id,
          phase.id,
          referral.id
        ]
      );

      await audit(
        client,

        'referral_attached',

        user.id,

        phase.id,

        {
          referrerId:
            referral.referrer_id,

          code
        }
      );

      await client.query(
        'COMMIT'
      );

      return res.json({
        ok:
          true,

        phaseDate:
          toDateOnlyString(
            phase.phase_date
          )
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'referral attach error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          error:
            'referral_attach_failed'
        });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   CREATE ENTRY INVOICE
========================================================= */

app.post(
  '/api/create-entry-invoice',

  async (
    req,
    res
  ) => {
    if (
      !paymentsReady
    ) {
      return res
        .status(
          503
        )
        .json({
          error:
            'payments_disabled'
        });
    }

    const user =
      verifyInitData(
        getInitData(
          req
        )
      );

    if (!user) {
      return res
        .status(
          401
        )
        .json({
          error:
            'invalid_init_data'
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      await ensureUser(
        client,
        user
      );

      const phase =
        await getCurrentPhase(
          client
        );

      if (
        phase.status !==
          'open' ||
        toDateOnlyString(
          phase.phase_date
        ) !==
          getMoscowDateString()
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            400
          )
          .json({
            error:
              'phase_closed'
          });
      }

      const existing =
        await client.query(
          `
          SELECT
            id

          FROM
            entries

          WHERE
            telegram_user_id =
              $1

            AND phase_id =
              $2

          FOR UPDATE
          `,
          [
            user.id,
            phase.id
          ]
        );

      if (
        existing.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            400
          )
          .json({
            error:
              'already_entered'
          });
      }

      const referralCount =
        await client.query(
          `
          SELECT
            COUNT(*)::int
              AS count

          FROM
            referral_conversions

          WHERE
            referrer_id =
              $1

            AND phase_id =
              $2
          `,
          [
            user.id,
            phase.id
          ]
        );

      if (
        Number(
          referralCount
            .rows[0]
            .count
        ) >=
        2
      ) {
        await client.query(
          `
          INSERT INTO free_entry_grants (
            telegram_user_id,
            phase_id,
            reason
          )

          VALUES (
            $1,
            $2,
            'two_successful_referrals'
          )

          ON CONFLICT (
            telegram_user_id,
            phase_id
          )

          DO NOTHING
          `,
          [
            user.id,
            phase.id
          ]
        );

        await client.query(
          'COMMIT'
        );

        return res.json({
          freeEntry:
            true,

          reason:
            'two_successful_referrals'
        });
      }

      const invoice =
        await createEntryInvoice(
          user.id,
          phase.id
        );

      const expiresAt =
        new Date(
          Date.now() +
            15 *
              60 *
              1000
        );

      await client.query(
        `
        INSERT INTO invoices (
          invoice_token,
          telegram_user_id,
          phase_id,
          stars_amount,
          payload,
          status,
          expires_at
        )

        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          'created',
          $6
        )
        `,
        [
          invoice.link,
          user.id,
          phase.id,
          ENTRY_STARS,
          invoice.payload,
          expiresAt
        ]
      );

      await audit(
        client,

        'invoice_created',

        user.id,

        phase.id,

        {
          payload:
            invoice.payload,

          stars:
            ENTRY_STARS
        }
      );

      await client.query(
        'COMMIT'
      );

      return res.json({
        freeEntry:
          false,

        invoiceLink:
          invoice.link,

        entryStars:
          ENTRY_STARS,

        entryUsdDisplay:
          ENTRY_USD_DISPLAY
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'invoice error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          error:
            'invoice_failed'
        });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   CLAIM FREE ENTRY
========================================================= */

app.post(
  '/api/claim-free-entry',

  async (
    req,
    res
  ) => {
    const user =
      verifyInitData(
        getInitData(
          req
        )
      );

    if (!user) {
      return res
        .status(
          401
        )
        .json({
          error:
            'invalid_init_data'
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      await ensureUser(
        client,
        user
      );

      const phase =
        await getCurrentPhase(
          client
        );

      if (
        phase.status !==
          'open' ||
        toDateOnlyString(
          phase.phase_date
        ) !==
          getMoscowDateString()
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            400
          )
          .json({
            error:
              'phase_closed'
          });
      }

      const existing =
        await client.query(
          `
          SELECT *
          FROM entries

          WHERE
            telegram_user_id =
              $1

            AND phase_id =
              $2

          FOR UPDATE
          `,
          [
            user.id,
            phase.id
          ]
        );

      if (
        existing.rows.length
      ) {
        await client.query(
          'COMMIT'
        );

        return res.json({
          ok:
            true,

          alreadyEntered:
            true,

          isFree:
            Boolean(
              existing.rows[0]
                .is_free
            )
        });
      }

      const conversions =
        await client.query(
          `
          SELECT
            COUNT(*)::int
              AS count

          FROM
            referral_conversions

          WHERE
            referrer_id =
              $1

            AND phase_id =
              $2
          `,
          [
            user.id,
            phase.id
          ]
        );

      if (
        Number(
          conversions
            .rows[0]
            .count
        ) <
        2
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(
            403
          )
          .json({
            error:
              'two_successful_referrals_required'
          });
      }

      await client.query(
        `
        INSERT INTO free_entry_grants (
          telegram_user_id,
          phase_id,
          reason
        )

        VALUES (
          $1,
          $2,
          'two_successful_referrals'
        )

        ON CONFLICT (
          telegram_user_id,
          phase_id
        )

        DO NOTHING
        `,
        [
          user.id,
          phase.id
        ]
      );

      const entry =
        await client.query(
          `
          INSERT INTO entries (
            telegram_user_id,
            phase_id,
            payment_id,
            is_free,
            is_first_payer
          )

          VALUES (
            $1,
            $2,
            NULL,
            TRUE,
            FALSE
          )

          ON CONFLICT (
            telegram_user_id,
            phase_id
          )

          DO NOTHING

          RETURNING
            id
          `,
          [
            user.id,
            phase.id
          ]
        );

      await audit(
        client,

        'free_entry_created',

        user.id,

        phase.id,

        {
          entryId:
            entry.rows[0]
              ?.id ||
            null
        }
      );

      await client.query(
        'COMMIT'
      );

      return res.json({
        ok:
          true,

        freeEntry:
          true
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'free entry error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          error:
            'free_entry_failed'
        });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   REFUNDS
========================================================= */

async function tryRefundPayment({
  paymentId =
    null,

  userId,

  chargeId,

  reconciliationId =
    null
}) {
  try {
    await telegramApi(
      'refundStarPayment',

      {
        user_id:
          userId,

        telegram_payment_charge_id:
          chargeId
      }
    );

    if (
      paymentId
    ) {
      await pool.query(
        `
        UPDATE payments

        SET
          status =
            'refunded',

          refund_attempts =
            refund_attempts +
            1,

          last_refund_attempt_at =
            NOW(),

          refund_last_error =
            NULL

        WHERE
          id =
            $1
        `,
        [
          paymentId
        ]
      );
    }

    if (
      reconciliationId
    ) {
      await pool.query(
        `
        UPDATE payment_reconciliations

        SET
          status =
            'refunded',

          updated_at =
            NOW()

        WHERE
          id =
            $1
        `,
        [
          reconciliationId
        ]
      );
    }

    return true;
  } catch (
    error
  ) {
    if (
      paymentId
    ) {
      await pool.query(
        `
        UPDATE payments

        SET
          status =
            'refund_failed',

          refund_attempts =
            refund_attempts +
            1,

          last_refund_attempt_at =
            NOW(),

          refund_last_error =
            $2

        WHERE
          id =
            $1
        `,
        [
          paymentId,
          error.message
        ]
      );
    }

    if (
      reconciliationId
    ) {
      await pool.query(
        `
        UPDATE payment_reconciliations

        SET
          status =
            'refund_failed',

          updated_at =
            NOW()

        WHERE
          id =
            $1
        `,
        [
          reconciliationId
        ]
      );
    }

    console.error(
      'refundStarPayment failed:',
      error.message
    );

    return false;
  }
}

async function retryFailedRefunds() {
  const result =
    await pool.query(
      `
      SELECT
        id,
        telegram_payment_charge_id,
        telegram_user_id

      FROM
        payments

      WHERE
        status IN (
          'refund_pending',
          'refund_failed'
        )

        AND refund_attempts <
          5

        AND (
          last_refund_attempt_at
            IS NULL

          OR
          last_refund_attempt_at <
            NOW() -
            INTERVAL '5 minutes'
        )

      ORDER BY
        id

      LIMIT
        20
      `
    );

  for (
    const payment
    of result.rows
  ) {
    await tryRefundPayment({
      paymentId:
        payment.id,

      userId:
        Number(
          payment.telegram_user_id
        ),

      chargeId:
        payment.telegram_payment_charge_id
    });
  }
}

/* =========================================================
   TELEGRAM WEBHOOK
========================================================= */

app.post(
  '/telegram/webhook',

  async (
    req,
    res
  ) => {
    const secret =
      req.headers[
        'x-telegram-bot-api-secret-token'
      ];

    if (
      !WEBHOOK_SECRET ||
      !timingSafeStringEqual(
        String(
          secret ||
            ''
        ),

        WEBHOOK_SECRET
      )
    ) {
      return res
        .status(
          403
        )
        .json({
          error:
            'forbidden'
        });
    }

    const update =
      req.body;

    if (!update) {
      return res.sendStatus(
        200
      );
    }

    /* PRE CHECKOUT */

    if (
      update
        .pre_checkout_query
    ) {
      const q =
        update.pre_checkout_query;

      try {
        if (
          !paymentsReady ||
          q.currency !==
            'XTR'
        ) {
          await telegramApi(
            'answerPreCheckoutQuery',

            {
              pre_checkout_query_id:
                q.id,

              ok:
                false,

              error_message:
                'Invalid or disabled payment.'
            }
          );

          return res.sendStatus(
            200
          );
        }

        const invoice =
          await pool.query(
            `
            SELECT
              i.*,

              p.phase_date,

              p.status
                AS phase_status

            FROM
              invoices i

            JOIN
              phases p

            ON
              p.id =
                i.phase_id

            WHERE
              i.payload =
                $1

              AND i.status =
                'created'

              AND i.expires_at >
                NOW()
            `,
            [
              q.invoice_payload
            ]
          );

        const inv =
          invoice.rows[0];

        const valid =
          Boolean(
            inv
          ) &&
          Number(
            inv.stars_amount
          ) ===
            Number(
              q.total_amount
            ) &&
          Number(
            inv.telegram_user_id
          ) ===
            Number(
              q.from.id
            ) &&
          inv.phase_status ===
            'open' &&
          toDateOnlyString(
            inv.phase_date
          ) ===
            getMoscowDateString();

        await telegramApi(
          'answerPreCheckoutQuery',

          {
            pre_checkout_query_id:
              q.id,

            ok:
              valid,

            ...(
              valid
                ? {}
                : {
                    error_message:
                      'Invoice expired or invalid for today.'
                  }
            )
          }
        );

        return res.sendStatus(
          200
        );
      } catch (
        error
      ) {
        console.error(
          'pre_checkout error:',
          error
        );

        try {
          await telegramApi(
            'answerPreCheckoutQuery',

            {
              pre_checkout_query_id:
                q.id,

              ok:
                false,

              error_message:
                'Temporary payment error.'
            }
          );
        } catch {}

        return res.sendStatus(
          200
        );
      }
    }

    /* SUCCESSFUL PAYMENT */

    if (
      update.message
        ?.successful_payment
    ) {
      const payment =
        update.message
          .successful_payment;

      const from =
        update.message
          .from;

      if (
        !from?.id
      ) {
        return res.sendStatus(
          200
        );
      }

      const chargeId =
        String(
          payment.telegram_payment_charge_id ||
            ''
        );

      const payload =
        String(
          payment.invoice_payload ||
            ''
        );

      if (
        !chargeId ||
        !payload
      ) {
        return res.sendStatus(
          200
        );
      }

      const client =
        await pool.connect();

      let refundJob =
        null;

      try {
        await client.query(
          'BEGIN'
        );

        const duplicate =
          await client.query(
            `
            SELECT
              id

            FROM
              payments

            WHERE
              telegram_payment_charge_id =
                $1
            `,
            [
              chargeId
            ]
          );

        if (
          duplicate.rows.length
        ) {
          await client.query(
            'COMMIT'
          );

          return res.sendStatus(
            200
          );
        }

        const invoiceResult =
          await client.query(
            `
            SELECT *
            FROM invoices

            WHERE
              payload =
                $1

            FOR UPDATE
            `,
            [
              payload
            ]
          );

        const inv =
          invoiceResult.rows[0];

        if (!inv) {
          const reconciliation =
            await client.query(
              `
              INSERT INTO payment_reconciliations (
                telegram_payment_charge_id,
                telegram_user_id,
                invoice_payload,
                currency,
                stars_amount,
                reason,
                status,
                raw_payload
              )

              VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                'unknown_invoice',
                'refund_pending',
                $6
              )

              ON CONFLICT (
                telegram_payment_charge_id
              )

              DO UPDATE SET
                updated_at =
                  NOW()

              RETURNING
                id
              `,
              [
                chargeId,

                from.id,

                payload,

                payment.currency,

                payment.total_amount,

                safeJson(
                  payment
                )
              ]
            );

          await client.query(
            'COMMIT'
          );

          refundJob = {
            reconciliationId:
              reconciliation
                .rows[0]
                .id,

            userId:
              from.id,

            chargeId
          };
        } else {
          const phaseResult =
            await client.query(
              `
              SELECT *
              FROM phases

              WHERE
                id =
                  $1

              FOR UPDATE
              `,
              [
                inv.phase_id
              ]
            );

          const phase =
            phaseResult.rows[0];

          if (!phase) {
            await client.query(
              'ROLLBACK'
            );

            return res.sendStatus(
              200
            );
          }

          await ensureUser(
            client,
            from
          );

          const amountMatches =
            payment.currency ===
              'XTR' &&
            Number(
              inv.stars_amount
            ) ===
              Number(
                payment.total_amount
              );

          const currentOpen =
            phase.status ===
              'open' &&
            toDateOnlyString(
              phase.phase_date
            ) ===
              getMoscowDateString();

          const initialStatus =
            amountMatches &&
            currentOpen
              ? 'succeeded'
              : 'refund_pending';

          const paymentResult =
            await client.query(
              `
              INSERT INTO payments (
                telegram_payment_charge_id,
                telegram_user_id,
                phase_id,
                stars_amount,
                currency,
                invoice_payload,
                status
              )

              VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7
              )

              RETURNING
                id
              `,
              [
                chargeId,

                from.id,

                phase.id,

                payment.total_amount,

                payment.currency,

                payload,

                initialStatus
              ]
            );

          const paymentId =
            paymentResult
              .rows[0]
              .id;

          if (
            !amountMatches ||
            !currentOpen
          ) {
            await client.query(
              `
              UPDATE invoices

              SET
                status =
                  $1

              WHERE
                id =
                  $2
              `,
              [
                amountMatches
                  ? 'paid_after_phase_close'
                  : 'paid_invalid_amount',

                inv.id
              ]
            );

            await audit(
              client,

              amountMatches
                ? 'payment_received_after_phase_close'
                : 'payment_amount_mismatch',

              from.id,

              phase.id,

              {
                chargeId,

                expected:
                  Number(
                    inv.stars_amount
                  ),

                received:
                  Number(
                    payment.total_amount
                  ),

                currency:
                  payment.currency
              }
            );

            await client.query(
              'COMMIT'
            );

            refundJob = {
              paymentId,

              userId:
                from.id,

              chargeId
            };
          } else {
            const existingEntry =
              await client.query(
                `
                SELECT
                  id

                FROM
                  entries

                WHERE
                  telegram_user_id =
                    $1

                  AND phase_id =
                    $2

                FOR UPDATE
                `,
                [
                  from.id,
                  phase.id
                ]
              );

            if (
              existingEntry
                .rows
                .length
            ) {
              await client.query(
                `
                UPDATE payments

                SET
                  status =
                    'refund_pending'

                WHERE
                  id =
                    $1
                `,
                [
                  paymentId
                ]
              );

              await client.query(
                `
                UPDATE invoices

                SET
                  status =
                    'paid_duplicate_entry'

                WHERE
                  id =
                    $1
                `,
                [
                  inv.id
                ]
              );

              await audit(
                client,

                'duplicate_paid_entry',

                from.id,

                phase.id,

                {
                  chargeId
                }
              );

              await client.query(
                'COMMIT'
              );

              refundJob = {
                paymentId,

                userId:
                  from.id,

                chargeId
              };
            } else {
              const isFirstPayer =
                !phase.first_verified_entry_id;

              const entryResult =
                await client.query(
                  `
                  INSERT INTO entries (
                    telegram_user_id,
                    phase_id,
                    payment_id,
                    is_free,
                    is_first_payer
                  )

                  VALUES (
                    $1,
                    $2,
                    $3,
                    FALSE,
                    $4
                  )

                  RETURNING
                    id
                  `,
                  [
                    from.id,

                    phase.id,

                    paymentId,

                    isFirstPayer
                  ]
                );

              const entryId =
                entryResult
                  .rows[0]
                  .id;

              await client.query(
                `
                UPDATE phases

                SET
                  total_stars =
                    total_stars +
                    $1,

                  first_verified_entry_id =
                    CASE

                      WHEN
                        first_verified_entry_id
                          IS NULL

                      THEN
                        $2

                      ELSE
                        first_verified_entry_id

                    END,

                  updated_at =
                    NOW()

                WHERE
                  id =
                    $3
                `,
                [
                  payment.total_amount,

                  entryId,

                  phase.id
                ]
              );

              await client.query(
                `
                UPDATE invoices

                SET
                  status =
                    'paid'

                WHERE
                  id =
                    $1
                `,
                [
                  inv.id
                ]
              );

              const attachment =
                await client.query(
                  `
                  SELECT *

                  FROM
                    referral_attachments

                  WHERE
                    referred_user_id =
                      $1

                    AND phase_id =
                      $2

                  FOR UPDATE
                  `,
                  [
                    from.id,

                    phase.id
                  ]
                );

              if (
                attachment
                  .rows
                  .length
              ) {
                const referrerId =
                  attachment
                    .rows[0]
                    .referrer_id;

                if (
                  Number(
                    referrerId
                  ) !==
                  Number(
                    from.id
                  )
                ) {
                  await client.query(
                    `
                    INSERT INTO referral_conversions (
                      referred_user_id,
                      referrer_id,
                      phase_id,
                      payment_id
                    )

                    VALUES (
                      $1,
                      $2,
                      $3,
                      $4
                    )

                    ON CONFLICT (
                      referred_user_id,
                      phase_id
                    )

                    DO NOTHING
                    `,
                    [
                      from.id,

                      referrerId,

                      phase.id,

                      paymentId
                    ]
                  );

                  const count =
                    await client.query(
                      `
                      SELECT
                        COUNT(*)::int
                          AS count

                      FROM
                        referral_conversions

                      WHERE
                        referrer_id =
                          $1

                        AND phase_id =
                          $2
                      `,
                      [
                        referrerId,

                        phase.id
                      ]
                    );

                  if (
                    Number(
                      count
                        .rows[0]
                        .count
                    ) >=
                    2
                  ) {
                    await client.query(
                      `
                      INSERT INTO free_entry_grants (
                        telegram_user_id,
                        phase_id,
                        reason
                      )

                      VALUES (
                        $1,
                        $2,
                        'two_successful_referrals'
                      )

                      ON CONFLICT (
                        telegram_user_id,
                        phase_id
                      )

                      DO NOTHING
                      `,
                      [
                        referrerId,

                        phase.id
                      ]
                    );
                  }
                }
              }

              await audit(
                client,

                'payment_succeeded',

                from.id,

                phase.id,

                {
                  chargeId,

                  entryId,

                  stars:
                    Number(
                      payment.total_amount
                    ),

                  firstPayer:
                    isFirstPayer
                }
              );

              await client.query(
                'COMMIT'
              );
            }
          }
        }
      } catch (
        error
      ) {
        try {
          await client.query(
            'ROLLBACK'
          );
        } catch {}

        console.error(
          'successful payment error:',
          error
        );

        return res.sendStatus(
          200
        );
      } finally {
        client.release();
      }

      if (
        refundJob
      ) {
        tryRefundPayment(
          refundJob
        ).catch(
          console.error
        );
      }

      return res.sendStatus(
        200
      );
    }

    return res.sendStatus(
      200
    );
  }
);

/* =========================================================
   FINALIZATION
========================================================= */

async function finalizePhaseByDate(
  phaseDate,
  force =
    false,
  actorTelegramId =
    null
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      'BEGIN'
    );

    const phaseResult =
      await client.query(
        `
        SELECT *
        FROM phases

        WHERE
          phase_date =
            $1

        FOR UPDATE
        `,
        [
          phaseDate
        ]
      );

    if (
      !phaseResult
        .rows
        .length
    ) {
      await client.query(
        'ROLLBACK'
      );

      return {
        status:
          404,

        body: {
          error:
            'phase_not_found'
        }
      };
    }

    const phase =
      phaseResult
        .rows[0];

    if (
      phase.status ===
      'finalized'
    ) {
      await client.query(
        'COMMIT'
      );

      return {
        status:
          200,

        body: {
          alreadyFinalized:
            true,

          phaseDate:
            toDateOnlyString(
              phase.phase_date
            )
        }
      };
    }

    const today =
      getMoscowDateString();

    if (
      toDateOnlyString(
        phase.phase_date
      ) >=
        today &&
      !force
    ) {
      await client.query(
        'ROLLBACK'
      );

      return {
        status:
          400,

        body: {
          error:
            'phase_not_yet_ended'
        }
      };
    }

    await client.query(
      `
      UPDATE phases

      SET
        status =
          'finalizing',

        updated_at =
          NOW()

      WHERE
        id =
          $1
      `,
      [
        phase.id
      ]
    );

    const totalStars =
      Number(
        phase.total_stars ||
          0
      );

    if (
      !Number.isSafeInteger(
        totalStars
      ) ||
      totalStars <
        0
    ) {
      throw new Error(
        'invalid_total_stars'
      );
    }

    const publicPoolStars =
      Math.floor(
        totalStars *
          0.70
      );

    const publicPoolUsd =
      publicPoolStars *
      STAR_USD_RATE;

    const configuredWinnerCount =
      getWinnerCountFromUsd(
        publicPoolUsd
      );

    const winnerPool =
      Math.floor(
        totalStars *
          0.69
      );

    const charity =
      Math.floor(
        totalStars *
          0.01
      );

    const operations =
      totalStars -
      winnerPool -
      charity;

    const entriesResult =
      await client.query(
        `
        SELECT
          e.id,

          e.telegram_user_id,

          e.is_first_payer,

          u.ton_wallet_address,

          u.ton_wallet_verified_at

        FROM
          entries e

        LEFT JOIN
          users u

        ON
          u.telegram_id =
            e.telegram_user_id

        WHERE
          e.phase_id =
            $1

        ORDER BY
          e.id
        `,
        [
          phase.id
        ]
      );

    const entries =
      entriesResult.rows;

    let winnerCount =
      0;

    if (
      entries.length >
        0 &&
      winnerPool >
        0
    ) {
      winnerCount =
        Math.min(
          Math.max(
            1,
            configuredWinnerCount
          ),

          entries.length,

          winnerPool
        );
    }

    if (
      winnerCount <=
      0
    ) {
      const adjustedOperations =
        operations +
        winnerPool;

      await client.query(
        `
        UPDATE phases

        SET
          status =
            'finalized',

          winner_pool_stars =
            0,

          charity_stars =
            $1,

          operations_stars =
            $2,

          winner_count =
            0,

          finalized_at =
            NOW(),

          updated_at =
            NOW()

        WHERE
          id =
            $3
        `,
        [
          charity,

          adjustedOperations,

          phase.id
        ]
      );

      await client.query(
        `
        INSERT INTO allocations (
          phase_id,
          type,
          stars_amount
        )

        VALUES
          (
            $1,
            'winners',
            0
          ),

          (
            $1,
            'charity',
            $2
          ),

          (
            $1,
            'operations',
            $3
          )

        ON CONFLICT (
          phase_id,
          type
        )

        DO UPDATE SET
          stars_amount =
            EXCLUDED.stars_amount
        `,
        [
          phase.id,

          charity,

          adjustedOperations
        ]
      );

      await audit(
        client,

        'phase_finalized',

        actorTelegramId,

        phase.id,

        {
          winners:
            0,

          totalStars,

          publicPoolStars,

          publicPoolUsd
        }
      );

      await client.query(
        'COMMIT'
      );

      return {
        status:
          200,

        body: {
          finalized:
            true,

          winners:
            0,

          totalStars,

          publicPoolStars,

          publicPoolUsd
        }
      };
    }

    const firstPayer =
      entries.find(
        (
          entry
        ) =>
          entry.is_first_payer
      ) ||
      entries.find(
        (
          entry
        ) =>
          String(
            entry.id
          ) ===
          String(
            phase.first_verified_entry_id
          )
      );

    const selected =
      [];

    if (
      firstPayer
    ) {
      selected.push(
        firstPayer
      );
    }

    const remaining =
      secureShuffle(
        entries.filter(
          (
            entry
          ) =>
            !firstPayer ||
            String(
              entry.id
            ) !==
              String(
                firstPayer.id
              )
        )
      );

    while (
      selected.length <
        winnerCount &&
      remaining.length
    ) {
      selected.push(
        remaining.shift()
      );
    }

    const basePrizePerWinner =
      Math.floor(
        winnerPool /
          winnerCount
      );

    const winnerRemainder =
      winnerPool -
      basePrizePerWinner *
        winnerCount;

    for (
      let index =
        0;

      index <
        selected.length;

      index++
    ) {
      const entry =
        selected[index];

      const rank =
        index +
        1;

      const prizeStars =
        basePrizePerWinner +
        (
          rank <=
          winnerRemainder
            ? 1
            : 0
        );

      const prizeUsd =
        prizeStars *
        STAR_USD_RATE;

      const usdtAmountMicro =
        Math.max(
          1,

          Math.round(
            prizeUsd *
              1000000
          )
        );

      const winnerResult =
        await client.query(
          `
          INSERT INTO winners (
            phase_id,
            entry_id,
            telegram_user_id,
            rank,
            prize_stars,
            is_first_payer
          )

          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
          )

          ON CONFLICT (
            entry_id
          )

          DO UPDATE SET
            rank =
              EXCLUDED.rank,

            prize_stars =
              EXCLUDED.prize_stars,

            is_first_payer =
              EXCLUDED.is_first_payer

          RETURNING
            id
          `,
          [
            phase.id,

            entry.id,

            entry.telegram_user_id,

            rank,

            prizeStars,

            Boolean(
              entry.is_first_payer
            )
          ]
        );

      const winner =
        winnerResult
          .rows[0];

      const walletVerified =
        Boolean(
          entry.ton_wallet_verified_at &&
          entry.ton_wallet_address
        );

      await client.query(
        `
        INSERT INTO payouts (
          phase_id,
          winner_id,
          telegram_user_id,
          amount_stars,
          prize_usd,
          usdt_amount_micro,
          settlement_asset,
          status,
          ton_wallet_address
        )

        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          'USDT_TON',
          $7,
          $8
        )

        ON CONFLICT (
          winner_id
        )

        DO UPDATE SET
          amount_stars =
            EXCLUDED.amount_stars,

          prize_usd =
            EXCLUDED.prize_usd,

          usdt_amount_micro =
            EXCLUDED.usdt_amount_micro,

          settlement_asset =
            'USDT_TON',

          ton_wallet_address =
            COALESCE(
              payouts.ton_wallet_address,
              EXCLUDED.ton_wallet_address
            ),

          status =
            CASE

              WHEN payouts.status
                IN (
                  'paid',
                  'processing',
                  'submitted'
                )

              THEN
                payouts.status

              WHEN
                EXCLUDED.ton_wallet_address
                  IS NULL

              THEN
                'waiting_wallet'

              ELSE
                'pending'

            END
        `,
        [
          phase.id,

          winner.id,

          entry.telegram_user_id,

          prizeStars,

          prizeUsd.toFixed(
            6
          ),

          usdtAmountMicro,

          walletVerified
            ? 'pending'
            : 'waiting_wallet',

          walletVerified
            ? entry.ton_wallet_address
            : null
        ]
      );
    }

    await client.query(
      `
      UPDATE phases

      SET
        status =
          'finalized',

        winner_pool_stars =
          $1,

        charity_stars =
          $2,

        operations_stars =
          $3,

        winner_count =
          $4,

        finalized_at =
          NOW(),

        updated_at =
          NOW()

      WHERE
        id =
          $5
      `,
      [
        winnerPool,

        charity,

        operations,

        winnerCount,

        phase.id
      ]
    );

    await client.query(
      `
      INSERT INTO allocations (
        phase_id,
        type,
        stars_amount
      )

      VALUES
        (
          $1,
          'winners',
          $2
        ),

        (
          $1,
          'charity',
          $3
        ),

        (
          $1,
          'operations',
          $4
        )

      ON CONFLICT (
        phase_id,
        type
      )

      DO UPDATE SET
        stars_amount =
          EXCLUDED.stars_amount
      `,
      [
        phase.id,

        winnerPool,

        charity,

        operations
      ]
    );

    await audit(
      client,

      'phase_finalized',

      actorTelegramId,

      phase.id,

      {
        totalStars,

        publicPoolStars,

        publicPoolUsd,

        configuredWinnerCount,

        actualWinnerCount:
          winnerCount,

        firstPayerGuaranteed:
          Boolean(
            firstPayer
          ),

        settlementAsset:
          'USDT_TON',

        automaticSettlementEnabled:
          false
      }
    );

    await client.query(
      'COMMIT'
    );

    return {
      status:
        200,

      body: {
        finalized:
          true,

        phaseDate:
          toDateOnlyString(
            phase.phase_date
          ),

        totalStars,

        publicPoolStars,

        publicPoolUsd,

        winners:
          winnerCount,

        firstPayerGuaranteed:
          Boolean(
            firstPayer
          ),

        winnerPoolStars:
          winnerPool,

        charityStars:
          charity,

        operationsStars:
          operations,

        payoutsCreated:
          winnerCount,

        settlementAsset:
          'USDT_TON',

        automaticSettlementEnabled:
          false
      }
    };
  } catch (
    error
  ) {
    try {
      await client.query(
        'ROLLBACK'
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   ADMIN
========================================================= */

function verifyAdmin(
  req
) {
  const supplied =
    req.headers[
      'x-admin-secret'
    ] ||
    req.body
      ?.adminSecret ||
    '';

  return (
    Boolean(
      ADMIN_SECRET
    ) &&
    timingSafeStringEqual(
      String(
        supplied
      ),

      ADMIN_SECRET
    )
  );
}

app.post(
  '/api/admin/finalize-phase',

  async (
    req,
    res
  ) => {
    if (
      !verifyAdmin(
        req
      )
    ) {
      return res
        .status(
          403
        )
        .json({
          error:
            'forbidden'
        });
    }

    const requestedPhaseDate =
      req.body
        ?.phaseDate
        ? String(
            req.body.phaseDate
          ).slice(
            0,
            10
          )
        : getMoscowDateString();

    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(
        requestedPhaseDate
      )
    ) {
      return res
        .status(
          400
        )
        .json({
          error:
            'invalid_phase_date'
        });
    }

    try {
      const result =
        await finalizePhaseByDate(
          requestedPhaseDate,

          Boolean(
            req.body
              ?.force
          )
        );

      return res
        .status(
          result.status
        )
        .json(
          result.body
        );
    } catch (
      error
    ) {
      console.error(
        'finalize error:',
        error
      );

      return res
        .status(
          500
        )
        .json({
          error:
            'finalize_failed'
        });
    }
  }
);

app.get(
  '/api/admin/payouts',

  async (
    req,
    res
  ) => {
    if (
      !verifyAdmin(
        req
      )
    ) {
      return res
        .status(
          403
        )
        .json({
          error:
            'forbidden'
        });
    }

    const result =
      await pool.query(
        `
        SELECT
          p.*,

          w.rank,

          ph.phase_date,

          u.username,

          u.first_name,

          u.last_name

        FROM
          payouts p

        JOIN
          winners w

        ON
          w.id =
            p.winner_id

        JOIN
          phases ph

        ON
          ph.id =
            p.phase_id

        LEFT JOIN
          users u

        ON
          u.telegram_id =
            p.telegram_user_id

        ORDER BY
          p.id DESC

        LIMIT
          500
        `
      );

    return res.json({
      settlementAsset:
        'USDT_TON',

      automaticSettlementEnabled:
        false,

      treasuryVerified:
        treasuryState
          .verified,

      payouts:
        result.rows
    });
  }
);

app.get(
  '/api/admin/star-balance',

  async (
    req,
    res
  ) => {
    if (
      !verifyAdmin(
        req
      )
    ) {
      return res
        .status(
          403
        )
        .json({
          error:
            'forbidden'
        });
    }

    try {
      const balance =
        await telegramApi(
          'getMyStarBalance'
        );

      return res.json({
        ok:
          true,

        balance
      });
    } catch (
      error
    ) {
      return res
        .status(
          502
        )
        .json({
          ok:
            false,

          error:
            error.message
        });
    }
  }
);

/* =========================================================
   PUBLIC WINNERS
========================================================= */

app.get(
  '/api/winners',

  async (
    req,
    res
  ) => {
    const phaseDate =
      String(
        req.query
          .phaseDate ||
          getMoscowDateString()
      ).slice(
        0,
        10
      );

    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(
        phaseDate
      )
    ) {
      return res
        .status(
          400
        )
        .json({
          error:
            'invalid_phase_date'
        });
    }

    const phase =
      await pool.query(
        `
        SELECT *
        FROM phases

        WHERE
          phase_date =
            $1
        `,
        [
          phaseDate
        ]
      );

    if (
      !phase.rows.length
    ) {
      return res.json({
        phaseDate,

        finalized:
          false,

        winnerCount:
          0,

        winners:
          []
      });
    }

    const result =
      await pool.query(
        `
        SELECT
          w.rank,

          w.prize_stars,

          w.is_first_payer,

          u.username,

          u.first_name,

          u.last_name,

          p.status
            AS payout_status,

          p.prize_usd,

          p.usdt_amount_micro,

          p.ton_wallet_address,

          p.ton_tx_hash

        FROM
          winners w

        LEFT JOIN
          users u

        ON
          u.telegram_id =
            w.telegram_user_id

        LEFT JOIN
          payouts p

        ON
          p.winner_id =
            w.id

        WHERE
          w.phase_id =
            $1

        ORDER BY
          w.rank
        `,
        [
          phase.rows[0]
            .id
        ]
      );

    return res.json({
      phaseDate,

      finalized:
        phase.rows[0]
          .status ===
        'finalized',

      winnerCount:
        Number(
          phase.rows[0]
            .winner_count ||
            0
        ),

      settlementAsset:
        'USDT_TON',

      winners:
        result.rows.map(
          (
            winner
          ) => {
            const fullName =
              [
                winner.first_name,

                winner.last_name
              ]
                .filter(
                  Boolean
                )
                .join(
                  ' '
                )
                .trim();

            return {
              rank:
                Number(
                  winner.rank
                ),

              username:
                winner.username ||
                null,

              displayName:
                winner.username ||
                fullName ||
                'Winner',

              prizeStars:
                Number(
                  winner.prize_stars
                ),

              prizeUsd:
                Number(
                  winner.prize_usd ||
                    0
                ),

              prizeUsdt:
                Number(
                  winner.usdt_amount_micro ||
                    0
                ) /
                1000000,

              isFirstPayer:
                Boolean(
                  winner.is_first_payer
                ),

              payoutStatus:
                winner.payout_status ||
                'pending',

              walletConnected:
                Boolean(
                  winner.ton_wallet_address
                ),

              tonTxHash:
                winner.ton_tx_hash ||
                null
            };
          }
        )
    });
  }
);

/* =========================================================
   WORKERS
========================================================= */

async function autoFinalizeExpiredPhases() {
  const today =
    getMoscowDateString();

  const result =
    await pool.query(
      `
      SELECT
        phase_date

      FROM
        phases

      WHERE
        phase_date <
          $1

        AND status IN (
          'open',
          'finalizing'
        )

      ORDER BY
        phase_date ASC

      LIMIT
        31
      `,
      [
        today
      ]
    );

  for (
    const row
    of result.rows
  ) {
    const phaseDate =
      toDateOnlyString(
        row.phase_date
      );

    try {
      const finalized =
        await finalizePhaseByDate(
          phaseDate,
          false
        );

      console.log(
        'Auto-finalize:',
        phaseDate,
        finalized.status,
        finalized.body
      );
    } catch (
      error
    ) {
      console.error(
        'Auto-finalize failed:',
        phaseDate,
        error
      );
    }
  }
}

async function monitorPayoutQueue() {
  const result =
    await pool.query(
      `
      SELECT
        p.id,

        p.telegram_user_id,

        p.amount_stars,

        p.prize_usd,

        p.usdt_amount_micro,

        p.status,

        p.ton_wallet_address,

        w.rank

      FROM
        payouts p

      JOIN
        winners w

      ON
        w.id =
          p.winner_id

      WHERE
        p.status IN (
          'pending',
          'waiting_wallet'
        )

      ORDER BY
        p.id ASC

      LIMIT
        50
      `
    );

  for (
    const payout
    of result.rows
  ) {
    if (
      !payout
        .ton_wallet_address
    ) {
      console.log(
        'Payout waiting for verified wallet:',
        {
          payoutId:
            payout.id,

          telegramUserId:
            payout.telegram_user_id
        }
      );
    } else {
      console.log(
        'Payout ready for settlement:',
        {
          payoutId:
            payout.id,

          wallet:
            payout.ton_wallet_address,

          usdt:
            Number(
              payout.usdt_amount_micro ||
                0
            ) /
            1000000,

          rank:
            payout.rank
        }
      );
    }
  }
}

function startWorkers() {
  monitorPayoutQueue()
    .catch(
      console.error
    );

  retryFailedRefunds()
    .catch(
      console.error
    );

  autoFinalizeExpiredPhases()
    .catch(
      console.error
    );

  setInterval(
    () => {
      monitorPayoutQueue()
        .catch(
          console.error
        );
    },

    30 *
      1000
  );

  setInterval(
    () => {
      retryFailedRefunds()
        .catch(
          console.error
        );
    },

    5 *
      60 *
      1000
  );

  setInterval(
    () => {
      autoFinalizeExpiredPhases()
        .catch(
          console.error
        );
    },

    60 *
      1000
  );

  console.log(
    'Background workers started.'
  );
}

/* =========================================================
   TELEGRAM WEBHOOK CONFIG
========================================================= */

async function configureTelegramWebhook() {
  if (
    !BOT_TOKEN ||
    !WEBHOOK_SECRET ||
    !APP_URL
  ) {
    console.log(
      'Webhook setup skipped: missing Telegram configuration.'
    );

    return;
  }

  const webhookUrl =
    `${APP_URL.replace(
      /\/$/,
      ''
    )}/telegram/webhook`;

  try {
    const result =
      await telegramApi(
        'setWebhook',

        {
          url:
            webhookUrl,

          secret_token:
            WEBHOOK_SECRET,

          allowed_updates: [
            'message',
            'pre_checkout_query'
          ],

          drop_pending_updates:
            false
        }
      );

    console.log(
      'Telegram webhook configured:',
      result
    );
  } catch (
    error
  ) {
    console.error(
      'Webhook configuration failed:',
      error.message
    );
  }
}

/* =========================================================
   START
========================================================= */

async function start() {
  try {
    await verifyTreasuryWallet();

    await initializeDatabase();

    startWorkers();

    app.listen(
      PORT,
      '0.0.0.0',

      async () => {
        console.log(
          `Project Z running on 0.0.0.0:${PORT}`
        );

        console.log(
          `Moscow phase date: ${getMoscowDateString()}`
        );

        console.log(
          `Payments ready: ${paymentsReady}`
        );

        console.log(
          `Allowed frontend origin: ${FRONTEND_ORIGIN}`
        );

        console.log(
          `TON Proof domain: ${TON_PROOF_DOMAIN}`
        );

        console.log(
          `Treasury configured: ${treasuryState.configured}`
        );

        console.log(
          `Treasury verified: ${treasuryState.verified}`
        );

        console.log(
          'Settlement asset: USDT on TON'
        );

        console.log(
          'Automatic on-chain settlement: DISABLED'
        );

        if (
          missingEnv.length
        ) {
          console.log(
            'Missing environment variables:',
            missingEnv.join(
              ', '
            )
          );
        }

        await configureTelegramWebhook();
      }
    );
  } catch (
    error
  ) {
    console.error(
      'FATAL STARTUP ERROR:',
      error
    );

    process.exit(
      1
    );
  }
}

/* =========================================================
   ERRORS
========================================================= */

app.use(
  (
    error,
    _req,
    res,
    _next
  ) => {
    console.error(
      'Unhandled Express error:',
      error
    );

    if (
      res.headersSent
    ) {
      return;
    }

    return res
      .status(
        500
      )
      .json({
        error:
          'internal_error'
      });
  }
);

process.on(
  'unhandledRejection',

  (
    error
  ) => {
    console.error(
      'Unhandled rejection:',
      error
    );
  }
);

process.on(
  'uncaughtException',

  (
    error
  ) => {
    console.error(
      'Uncaught exception:',
      error
    );

    process.exit(
      1
    );
  }
);

start();
