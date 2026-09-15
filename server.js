import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Pool } from "pg";
import crypto from "crypto";
import nacl from "tweetnacl";
import {
  Address,
  Cell,
  contractAddress,
  loadStateInit,
} from "@ton/core";
import {
  WalletContractV1R1,
  WalletContractV1R2,
  WalletContractV1R3,
  WalletContractV2R1,
  WalletContractV2R2,
  WalletContractV3R1,
  WalletContractV3R2,
  WalletContractV4,
  WalletContractV5R1,
} from "@ton/ton";

const app = express();
app.set("trust proxy", 1);

/* =========================================================
   CONFIG
========================================================= */

const PORT = intEnv("PORT", 10000);
const NODE_ENV = process.env.NODE_ENV || "production";

const BOT_TOKEN = strEnv("BOT_TOKEN");
const DATABASE_URL = strEnv("DATABASE_URL");
const TELEGRAM_WEBHOOK_SECRET = strEnv("TELEGRAM_WEBHOOK_SECRET");
const APP_URL = strEnv(
  "APP_URL",
  "https://project-z-zryq.onrender.com"
);

const FRONTEND_ORIGIN = strEnv(
  "FRONTEND_ORIGIN",
  "https://g5v4jvv5hs-web.github.io"
);

const BOT_USERNAME = strEnv(
  "BOT_USERNAME",
  "denddkilibot"
).replace(/^@/, "");

const ADMIN_SECRET = strEnv("ADMIN_SECRET");

const MOSCOW_TIME_ZONE = strEnv(
  "MOSCOW_TIME_ZONE",
  "Europe/Moscow"
);

const PAYMENTS_ENABLED = boolEnv(
  "PAYMENTS_ENABLED",
  true
);

const ENTRY_STARS = intEnv(
  "ENTRY_STARS",
  100
);

const STAR_USD_RATE = floatEnv(
  "STAR_USD_RATE",
  0.013
);

const ENTRY_USD_DISPLAY = floatEnv(
  "ENTRY_USD_DISPLAY",
  1.99
);

const WINNER_SHARE = floatEnv(
  "WINNER_SHARE",
  0.69
);

const CHARITY_SHARE = floatEnv(
  "CHARITY_SHARE",
  0.01
);

const OPERATIONS_SHARE = floatEnv(
  "OPERATIONS_SHARE",
  0.30
);

const TON_NETWORK = strEnv(
  "TON_NETWORK",
  "-239"
);

const TON_PROOF_DOMAIN = strEnv(
  "TON_PROOF_DOMAIN",
  safeHost(FRONTEND_ORIGIN) ||
    "g5v4jvv5hs-web.github.io"
);

const TON_PROOF_TTL_SECONDS = intEnv(
  "TON_PROOF_TTL_SECONDS",
  900
);

const TREASURY_WALLET_ADDRESS = strEnv(
  "TREASURY_WALLET_ADDRESS",
  "UQAr2SdmjtiZmeNJiSFEslRjLv6YBn7BAaU7Dpd7KMi3Jf_q"
);

const USDT_JETTON_MASTER = strEnv(
  "USDT_JETTON_MASTER",
  "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
);

const AUTOMATIC_SETTLEMENT_ENABLED =
  false;

const REQUIRED_ENV = [
  "BOT_TOKEN",
  "DATABASE_URL",
  "TELEGRAM_WEBHOOK_SECRET",
  "APP_URL",
  "ADMIN_SECRET",
];

const missingEnv =
  REQUIRED_ENV.filter(
    (key) =>
      !process.env[key]
  );

if (
  Math.abs(
    WINNER_SHARE +
      CHARITY_SHARE +
      OPERATIONS_SHARE -
      1
  ) >
  1e-9
) {
  throw new Error(
    "WINNER_SHARE + CHARITY_SHARE + OPERATIONS_SHARE must equal 1"
  );
}

if (
  !Number.isInteger(
    ENTRY_STARS
  ) ||
  ENTRY_STARS <=
    0
) {
  throw new Error(
    "ENTRY_STARS must be a positive integer"
  );
}

if (
  !(
    STAR_USD_RATE >
    0
  )
) {
  throw new Error(
    "STAR_USD_RATE must be greater than zero"
  );
}

/* =========================================================
   DATABASE
========================================================= */

const pool =
  new Pool({
    connectionString:
      DATABASE_URL,

    ssl:
      NODE_ENV ===
      "production"
        ? {
            rejectUnauthorized:
              false,
          }
        : false,

    max:
      20,

    idleTimeoutMillis:
      30_000,

    connectionTimeoutMillis:
      10_000,
  });

/* =========================================================
   SECURITY / HTTP
========================================================= */

const allowedOrigins =
  new Set(
    [
      safeOrigin(
        APP_URL
      ),

      safeOrigin(
        FRONTEND_ORIGIN
      ),

      "https://g5v4jvv5hs-web.github.io",
    ].filter(
      Boolean
    )
  );

app.use(
  helmet({
    contentSecurityPolicy:
      false,

    crossOriginResourcePolicy: {
      policy:
        "cross-origin",
    },
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
      "GET",
      "POST",
      "OPTIONS",
    ],

    allowedHeaders: [
      "Content-Type",
      "X-Telegram-Init-Data",
      "X-Admin-Secret",
    ],
  })
);

app.use(
  express.json({
    limit:
      "64kb",
  })
);

app.use(
  "/api/",
  rateLimit({
    windowMs:
      60_000,

    max:
      180,

    standardHeaders:
      true,

    legacyHeaders:
      false,
  })
);

const paymentLimiter =
  rateLimit({
    windowMs:
      60_000,

    max:
      12,

    standardHeaders:
      true,

    legacyHeaders:
      false,
  });

const proofLimiter =
  rateLimit({
    windowMs:
      60_000,

    max:
      30,

    standardHeaders:
      true,

    legacyHeaders:
      false,
  });

/* =========================================================
   ENV / GENERIC HELPERS
========================================================= */

function strEnv(
  name,
  fallback = ""
) {
  const value =
    process.env[
      name
    ];

  return (
    typeof value ===
      "string" &&
    value.length
      ? value
      : fallback
  );
}

function intEnv(
  name,
  fallback
) {
  const n =
    Number(
      process.env[
        name
      ]
    );

  return Number.isInteger(
    n
  )
    ? n
    : fallback;
}

function floatEnv(
  name,
  fallback
) {
  const n =
    Number(
      process.env[
        name
      ]
    );

  return Number.isFinite(
    n
  )
    ? n
    : fallback;
}

function boolEnv(
  name,
  fallback = false
) {
  const value =
    process.env[
      name
    ];

  if (
    value ==
    null
  ) {
    return fallback;
  }

  return (
    String(
      value
    ).toLowerCase() ===
    "true"
  );
}

function safeOrigin(
  value
) {
  try {
    return new URL(
      value
    ).origin;
  } catch {
    return null;
  }
}

function safeHost(
  value
) {
  try {
    return new URL(
      value
    ).host;
  } catch {
    return null;
  }
}

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

function sha256Buffer(
  value
) {
  return crypto
    .createHash(
      "sha256"
    )
    .update(
      value
    )
    .digest();
}

function sha256Hex(
  value
) {
  return crypto
    .createHash(
      "sha256"
    )
    .update(
      value
    )
    .digest(
      "hex"
    );
}

function randomToken(
  bytes = 32
) {
  return crypto
    .randomBytes(
      bytes
    )
    .toString(
      "base64url"
    );
}

function timingSafeEqualText(
  a,
  b
) {
  if (
    typeof a !==
      "string" ||
    typeof b !==
      "string"
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

function getMoscowDateString(
  date =
    new Date()
) {
  const parts =
    new Intl.DateTimeFormat(
      "en-CA",
      {
        timeZone:
          MOSCOW_TIME_ZONE,

        year:
          "numeric",

        month:
          "2-digit",

        day:
          "2-digit",
      }
    ).formatToParts(
      date
    );

  const bag =
    Object.fromEntries(
      parts
        .filter(
          (part) =>
            part.type !==
            "literal"
        )
        .map(
          (part) => [
            part.type,
            part.value,
          ]
        )
    );

  return `${bag.year}-${bag.month}-${bag.day}`;
}

function toDateOnlyString(
  value
) {
  if (!value) {
    return null;
  }

  if (
    typeof value ===
    "string"
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
    const parts =
      new Intl.DateTimeFormat(
        "en-CA",
        {
          timeZone:
            "UTC",

          year:
            "numeric",

          month:
            "2-digit",

          day:
            "2-digit",
        }
      ).formatToParts(
        value
      );

    const bag =
      Object.fromEntries(
        parts
          .filter(
            (part) =>
              part.type !==
              "literal"
          )
          .map(
            (part) => [
              part.type,
              part.value,
            ]
          )
      );

    return `${bag.year}-${bag.month}-${bag.day}`;
  }

  return String(
    value
  ).slice(
    0,
    10
  );
}

function isPastMoscowDate(
  phaseDate
) {
  return (
    toDateOnlyString(
      phaseDate
    ) <
    getMoscowDateString()
  );
}

function displayNameFromTelegramUser(
  user
) {
  const name =
    [
      user
        ?.first_name,

      user
        ?.last_name,
    ]
      .filter(
        Boolean
      )
      .join(
        " "
      )
      .trim();

  if (name) {
    return name.slice(
      0,
      120
    );
  }

  if (
    user
      ?.username
  ) {
    return `@${String(
      user.username
    ).slice(
      0,
      120
    )}`;
  }

  return `User ${
    user
      ?.id ??
    ""
  }`.trim();
}

function grossUsdFromStars(
  stars
) {
  return (
    Number(
      stars ||
        0
    ) *
    STAR_USD_RATE
  );
}

function money6(
  value
) {
  return (
    Math.round(
      Number(
        value ||
          0
      ) *
        1_000_000
    ) /
    1_000_000
  );
}

/* =========================================================
   BUSINESS RULES
========================================================= */

function winnerCountForGrossUsd(
  usd
) {
  if (
    !Number.isFinite(
      usd
    ) ||
    usd <
      100
  ) {
    return 0;
  }

  if (
    usd <
    300
  ) {
    return 10;
  }

  if (
    usd <
    600
  ) {
    return 20;
  }

  if (
    usd <
    1200
  ) {
    return 30;
  }

  if (
    usd <
    2000
  ) {
    return 40;
  }

  if (
    usd <
    4000
  ) {
    return 50;
  }

  if (
    usd <
    8000
  ) {
    return 80;
  }

  if (
    usd <
    12000
  ) {
    return 100;
  }

  if (
    usd <
    15000
  ) {
    return 120;
  }

  if (
    usd <
    25000
  ) {
    return 185;
  }

  if (
    usd <
    35000
  ) {
    return 250;
  }

  if (
    usd <
    50000
  ) {
    return 350;
  }

  if (
    usd <
    70000
  ) {
    return 550;
  }

  if (
    usd <
    130000
  ) {
    return 1000;
  }

  if (
    usd <
    170000
  ) {
    return 1300;
  }

  if (
    usd <
    250000
  ) {
    return 2000;
  }

  if (
    usd <
    400000
  ) {
    return 3000;
  }

  if (
    usd <
    650000
  ) {
    return 50000;
  }

  if (
    usd <
    1000000
  ) {
    return 10000;
  }

  if (
    usd <
    2000000
  ) {
    return 30000;
  }

  if (
    usd <
    4000000
  ) {
    return 50000;
  }

  if (
    usd <
    10000000
  ) {
    return 100000;
  }

  return 100000;
}
/* =========================================================
   TELEGRAM MINI APP INIT DATA
========================================================= */

function verifyInitData(
  initData
) {
  if (
    !initData ||
    typeof initData !==
      "string" ||
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
        "hash"
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
      "hash"
    );

    const dataCheckString =
      [
        ...params.entries(),
      ]
        .sort(
          (
            [a],
            [b]
          ) =>
            a.localeCompare(
              b
            )
        )
        .map(
          (
            [
              key,
              value,
            ]
          ) =>
            `${key}=${value}`
        )
        .join(
          "\n"
        );

    const secretKey =
      crypto
        .createHmac(
          "sha256",
          "WebAppData"
        )
        .update(
          BOT_TOKEN
        )
        .digest();

    const calculatedHash =
      crypto
        .createHmac(
          "sha256",
          secretKey
        )
        .update(
          dataCheckString
        )
        .digest(
          "hex"
        );

    if (
      !timingSafeEqualText(
        receivedHash.toLowerCase(),
        calculatedHash
      )
    ) {
      return null;
    }

    const authDate =
      Number(
        params.get(
          "auth_date"
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

    const now =
      Math.floor(
        Date.now() /
          1000
      );

    const age =
      now -
      authDate;

    if (
      age <
        -60 ||
      age >
        86_400
    ) {
      return null;
    }

    const rawUser =
      params.get(
        "user"
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

    return {
      user,

      authDate,

      queryId:
        params.get(
          "query_id"
        ) ||
        null,

      startParam:
        params.get(
          "start_param"
        ) ||
        null,
    };
  } catch {
    return null;
  }
}

function getInitData(
  req
) {
  return (
    req.headers[
      "x-telegram-init-data"
    ] ||
    req.body
      ?.initData ||
    ""
  );
}

function requireTelegramUser(
  req,
  res
) {
  const verified =
    verifyInitData(
      getInitData(
        req
      )
    );

  if (!verified) {
    res
      .status(
        401
      )
      .json({
        error:
          "Invalid or expired Telegram authorization.",
      });

    return null;
  }

  return verified;
}

/* =========================================================
   TELEGRAM BOT API
========================================================= */

async function telegramApi(
  method,
  body = {}
) {
  if (!BOT_TOKEN) {
    throw new Error(
      "BOT_TOKEN missing"
    );
  }

  const response =
    await fetch(
      `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
      {
        method:
          "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body:
          JSON.stringify(
            body
          ),

        signal:
          AbortSignal.timeout(
            12_000
          ),
      }
    );

  const data =
    await response
      .json()
      .catch(
        () => ({})
      );

  if (
    !response.ok ||
    data.ok !==
      true
  ) {
    throw new Error(
      `Telegram ${method} failed: ${
        data.description ||
        response.status
      }`
    );
  }

  return data.result;
}

async function ensureWebhook() {
  if (
    !APP_URL ||
    !BOT_TOKEN ||
    !TELEGRAM_WEBHOOK_SECRET
  ) {
    return false;
  }

  const webhookUrl =
    `${APP_URL.replace(
      /\/+$/,
      ""
    )}/telegram/webhook`;

  try {
    await telegramApi(
      "setWebhook",
      {
        url:
          webhookUrl,

        secret_token:
          TELEGRAM_WEBHOOK_SECRET,

        allowed_updates: [
          "message",
          "pre_checkout_query",
        ],

        drop_pending_updates:
          false,
      }
    );

    console.log(
      "Telegram webhook configured: true"
    );

    return true;
  } catch (
    error
  ) {
    console.error(
      "Telegram webhook configuration failed:",
      error.message
    );

    return false;
  }
}

/* =========================================================
   DATABASE SCHEMA
========================================================= */

async function initDb() {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
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
        display_name TEXT,
        ton_wallet_address TEXT,
        ton_wallet_public_key TEXT,
        ton_wallet_chain INTEGER,
        ton_wallet_verified_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS phases (
        id BIGSERIAL PRIMARY KEY,
        phase_date DATE NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'open',
        total_stars NUMERIC NOT NULL DEFAULT 0,
        winner_pool_stars NUMERIC NOT NULL DEFAULT 0,
        charity_stars NUMERIC NOT NULL DEFAULT 0,
        operations_stars NUMERIC NOT NULL DEFAULT 0,
        winner_count INTEGER NOT NULL DEFAULT 0,
        first_verified_entry_id BIGINT,
        entry_count BIGINT NOT NULL DEFAULT 0,
        paid_entry_count BIGINT NOT NULL DEFAULT 0,
        free_entry_count BIGINT NOT NULL DEFAULT 0,
        gross_usd NUMERIC(20,6) NOT NULL DEFAULT 0,
        winner_pool_usd NUMERIC(20,6) NOT NULL DEFAULT 0,
        charity_usd NUMERIC(20,6) NOT NULL DEFAULT 0,
        operations_usd NUMERIC(20,6) NOT NULL DEFAULT 0,
        draw_commit_hash TEXT,
        draw_seed_secret TEXT,
        draw_reveal TEXT,
        finalized_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS invoices (
        id BIGSERIAL PRIMARY KEY,
        invoice_token TEXT NOT NULL UNIQUE,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        stars_amount NUMERIC NOT NULL,
        currency TEXT NOT NULL DEFAULT 'XTR',
        payload TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'created',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        paid_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS payments (
        id BIGSERIAL PRIMARY KEY,
        telegram_payment_charge_id TEXT NOT NULL UNIQUE,
        provider_payment_charge_id TEXT,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        stars_amount NUMERIC NOT NULL,
        currency TEXT NOT NULL,
        invoice_payload TEXT NOT NULL,
        status TEXT NOT NULL,
        raw_payment JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        refund_attempts INTEGER NOT NULL DEFAULT 0,
        refund_last_error TEXT,
        last_refund_attempt_at TIMESTAMPTZ,
        refunded_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS payment_reconciliations (
        id BIGSERIAL PRIMARY KEY,
        telegram_payment_charge_id TEXT UNIQUE,
        telegram_user_id BIGINT,
        invoice_payload TEXT,
        currency TEXT,
        stars_amount NUMERIC,
        reason TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'needs_review',
        raw_payload JSONB,
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS entries (
        id BIGSERIAL PRIMARY KEY,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        payment_id BIGINT REFERENCES payments(id),
        source TEXT NOT NULL DEFAULT 'paid',
        is_free BOOLEAN NOT NULL DEFAULT FALSE,
        is_first_payer BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (telegram_user_id, phase_id)
      );

      CREATE TABLE IF NOT EXISTS referral_links (
        id BIGSERIAL PRIMARY KEY,
        referrer_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        code TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (referrer_id, phase_id)
      );

      CREATE TABLE IF NOT EXISTS referral_attachments (
        id BIGSERIAL PRIMARY KEY,
        referred_user_id BIGINT NOT NULL,
        referrer_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        referral_link_id BIGINT REFERENCES referral_links(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (referred_user_id, phase_id)
      );

      CREATE TABLE IF NOT EXISTS referral_conversions (
        id BIGSERIAL PRIMARY KEY,
        referred_user_id BIGINT NOT NULL,
        referrer_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        payment_id BIGINT NOT NULL REFERENCES payments(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (referred_user_id, phase_id)
      );

      CREATE TABLE IF NOT EXISTS free_entry_grants (
        id BIGSERIAL PRIMARY KEY,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        reason TEXT NOT NULL,
        required_referrals INTEGER NOT NULL DEFAULT 2,
        status TEXT NOT NULL DEFAULT 'available',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        claimed_at TIMESTAMPTZ,
        UNIQUE (telegram_user_id, phase_id)
      );

      CREATE TABLE IF NOT EXISTS winners (
        id BIGSERIAL PRIMARY KEY,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        entry_id BIGINT NOT NULL UNIQUE REFERENCES entries(id),
        telegram_user_id BIGINT NOT NULL,
        rank INTEGER NOT NULL,
        prize_stars NUMERIC NOT NULL,
        is_first_payer BOOLEAN NOT NULL DEFAULT FALSE,
        prize_usd NUMERIC(20,6) NOT NULL DEFAULT 0,
        prize_stars_equiv NUMERIC(20,6) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (phase_id, rank)
      );

      CREATE TABLE IF NOT EXISTS payouts (
        id BIGSERIAL PRIMARY KEY,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        winner_id BIGINT NOT NULL UNIQUE REFERENCES winners(id),
        telegram_user_id BIGINT NOT NULL,
        amount_stars INTEGER NOT NULL CHECK (amount_stars > 0),
        prize_usd NUMERIC(20,6),
        usdt_amount_micro BIGINT,
        settlement_asset TEXT NOT NULL DEFAULT 'USDT_TON',
        ton_wallet_address TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        telegram_transaction_id TEXT,
        ton_tx_hash TEXT,
        settlement_reference TEXT,
        failure_reason TEXT,
        processing_at TIMESTAMPTZ,
        paid_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS ton_proof_challenges (
        id BIGSERIAL PRIMARY KEY,
        telegram_user_id BIGINT NOT NULL,
        nonce TEXT NOT NULL UNIQUE,
        domain TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS allocations (
        id BIGSERIAL PRIMARY KEY,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        type TEXT NOT NULL,
        stars_amount NUMERIC NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (phase_id, type)
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        event_type TEXT NOT NULL,
        actor_telegram_id BIGINT,
        phase_id BIGINT REFERENCES phases(id),
        payload JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    const alters = [
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS ton_wallet_address TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS ton_wallet_verified_at TIMESTAMPTZ`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,

      `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'XTR'`,
      `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ`,

      `ALTER TABLE payments ADD COLUMN IF NOT EXISTS provider_payment_charge_id TEXT`,
      `ALTER TABLE payments ADD COLUMN IF NOT EXISTS raw_payment JSONB`,
      `ALTER TABLE payments ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ`,

      `ALTER TABLE payment_reconciliations ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE payment_reconciliations ADD COLUMN IF NOT EXISTS last_error TEXT`,

      `ALTER TABLE free_entry_grants ADD COLUMN IF NOT EXISTS required_referrals INTEGER NOT NULL DEFAULT 2`,
      `ALTER TABLE free_entry_grants ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'available'`,
      `ALTER TABLE free_entry_grants ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ`,

      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS entry_count BIGINT NOT NULL DEFAULT 0`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS paid_entry_count BIGINT NOT NULL DEFAULT 0`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS free_entry_count BIGINT NOT NULL DEFAULT 0`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS gross_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS winner_pool_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS charity_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS operations_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS draw_commit_hash TEXT`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS draw_seed_secret TEXT`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS draw_reveal TEXT`,
      `ALTER TABLE phases ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ`,

      `ALTER TABLE entries ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'paid'`,

      `ALTER TABLE winners ADD COLUMN IF NOT EXISTS prize_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,
      `ALTER TABLE winners ADD COLUMN IF NOT EXISTS prize_stars_equiv NUMERIC(20,6) NOT NULL DEFAULT 0`,

      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS usdt_amount_micro BIGINT NOT NULL DEFAULT 0`,
      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS settlement_asset TEXT NOT NULL DEFAULT 'USDT_TON'`,
      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS ton_wallet_address TEXT`,
      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS ton_tx_hash TEXT`,
      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS settlement_reference TEXT`,
      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS failure_reason TEXT`,
      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS processing_at TIMESTAMPTZ`,
      `ALTER TABLE payouts ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ`,
    ];

    for (
      const sql
      of alters
    ) {
      await client.query(
        sql
      );
    }

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_entries_phase
        ON entries(phase_id);

      CREATE INDEX IF NOT EXISTS idx_entries_user
        ON entries(telegram_user_id);

      CREATE INDEX IF NOT EXISTS idx_payments_phase
        ON payments(phase_id);

      CREATE INDEX IF NOT EXISTS idx_payouts_status
        ON payouts(status);

      CREATE INDEX IF NOT EXISTS idx_refconv_referrer_phase
        ON referral_conversions(referrer_id, phase_id);

      CREATE INDEX IF NOT EXISTS idx_ton_challenge_user
        ON ton_proof_challenges(telegram_user_id, expires_at);
    `);

    await client.query(
      "COMMIT"
    );

    console.log(
      "Database initialized successfully."
    );
  } catch (
    error
  ) {
    await client.query(
      "ROLLBACK"
    );

    throw error;
  } finally {
    client.release();
  }
}

async function audit(
  client,
  eventType,
  actorTelegramId = null,
  phaseId = null,
  payload = null
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
        $4::jsonb
      )
    `,
    [
      eventType,
      actorTelegramId,
      phaseId,
      safeJson(
        payload
      ),
    ]
  );
}
/* =========================================================
   USER / PHASE HELPERS
========================================================= */

async function upsertUser(
  client,
  telegramUser
) {
  const displayName =
    displayNameFromTelegramUser(
      telegramUser
    );

  await client.query(
    `
      INSERT INTO users (
        telegram_id,
        username,
        first_name,
        last_name,
        language_code,
        is_premium,
        display_name
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
      ON CONFLICT (telegram_id)
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

        display_name =
          EXCLUDED.display_name,

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

      telegramUser.is_premium ??
        null,

      displayName,
    ]
  );
}

async function getOrCreateCurrentPhase(
  client
) {
  const phaseDate =
    getMoscowDateString();

  let row =
    (
      await client.query(
        `
          SELECT *
          FROM phases
          WHERE phase_date = $1
          FOR UPDATE
        `,
        [
          phaseDate,
        ]
      )
    ).rows[0];

  if (row) {
    return row;
  }

  const drawSeed =
    crypto.randomBytes(
      32
    );

  const drawSeedText =
    drawSeed.toString(
      "base64url"
    );

  const drawCommitHash =
    sha256Hex(
      drawSeed
    );

  row =
    (
      await client.query(
        `
          INSERT INTO phases (
            phase_date,
            status,
            draw_commit_hash,
            draw_seed_secret
          )
          VALUES (
            $1,
            'open',
            $2,
            $3
          )
          ON CONFLICT (phase_date)
          DO UPDATE SET
            phase_date =
              EXCLUDED.phase_date
          RETURNING *
        `,
        [
          phaseDate,
          drawCommitHash,
          drawSeedText,
        ]
      )
    ).rows[0];

  return row;
}

async function getCurrentPhase() {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    const phase =
      await getOrCreateCurrentPhase(
        client
      );

    await client.query(
      "COMMIT"
    );

    return phase;
  } catch (
    error
  ) {
    await client.query(
      "ROLLBACK"
    );

    throw error;
  } finally {
    client.release();
  }
}

async function refreshPhaseTotals(
  client,
  phaseId
) {
  const counts =
    (
      await client.query(
        `
          SELECT
            COUNT(*)::bigint
              AS entry_count,

            COUNT(*) FILTER (
              WHERE is_free = FALSE
            )::bigint
              AS paid_entry_count,

            COUNT(*) FILTER (
              WHERE is_free = TRUE
            )::bigint
              AS free_entry_count

          FROM entries

          WHERE phase_id = $1
        `,
        [
          phaseId,
        ]
      )
    ).rows[0];

  const starsRow =
    (
      await client.query(
        `
          SELECT
            COALESCE(
              SUM(
                stars_amount
              ),
              0
            )::numeric
              AS total_stars

          FROM payments

          WHERE phase_id = $1
            AND status =
              'succeeded'
        `,
        [
          phaseId,
        ]
      )
    ).rows[0];

  const totalStars =
    Number(
      starsRow.total_stars ||
        0
    );

  const grossUsd =
    grossUsdFromStars(
      totalStars
    );

  const winnerStars =
    totalStars *
    WINNER_SHARE;

  const charityStars =
    totalStars *
    CHARITY_SHARE;

  const operationsStars =
    totalStars *
    OPERATIONS_SHARE;

  await client.query(
    `
      UPDATE phases

      SET
        total_stars = $2,

        entry_count = $3,

        paid_entry_count = $4,

        free_entry_count = $5,

        gross_usd = $6,

        winner_pool_usd = $7,

        charity_usd = $8,

        operations_usd = $9,

        winner_pool_stars = $10,

        charity_stars = $11,

        operations_stars = $12,

        updated_at = NOW()

      WHERE id = $1
    `,
    [
      phaseId,

      totalStars,

      Number(
        counts.entry_count ||
          0
      ),

      Number(
        counts.paid_entry_count ||
          0
      ),

      Number(
        counts.free_entry_count ||
          0
      ),

      money6(
        grossUsd
      ),

      money6(
        grossUsd *
          WINNER_SHARE
      ),

      money6(
        grossUsd *
          CHARITY_SHARE
      ),

      money6(
        grossUsd *
          OPERATIONS_SHARE
      ),

      money6(
        winnerStars
      ),

      money6(
        charityStars
      ),

      money6(
        operationsStars
      ),
    ]
  );

  const legacyAllocations = [
    [
      "winners",
      winnerStars,
    ],

    [
      "charity",
      charityStars,
    ],

    [
      "operations",
      operationsStars,
    ],
  ];

  for (
    const [
      type,
      amount,
    ]
    of legacyAllocations
  ) {
    await client.query(
      `
        INSERT INTO allocations (
          phase_id,
          type,
          stars_amount
        )
        VALUES (
          $1,
          $2,
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
        phaseId,
        type,
        money6(
          amount
        ),
      ]
    );
  }
}

/* =========================================================
   REFERRALS
========================================================= */

async function getOrCreateReferralLink(
  client,
  telegramUserId,
  phaseId
) {
  let row =
    (
      await client.query(
        `
          SELECT *
          FROM referral_links
          WHERE referrer_id = $1
            AND phase_id = $2
        `,
        [
          telegramUserId,
          phaseId,
        ]
      )
    ).rows[0];

  if (!row) {
    const code =
      `ref_${phaseId}_${randomToken(
        9
      )}`;

    row =
      (
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
              referrer_id =
                EXCLUDED.referrer_id
            RETURNING *
          `,
          [
            telegramUserId,
            phaseId,
            code,
          ]
        )
      ).rows[0];
  }

  return {
    code:
      row.code,

    link:
      BOT_USERNAME
        ? `https://t.me/${BOT_USERNAME}?startapp=${encodeURIComponent(
            row.code
          )}`
        : null,
  };
}

async function maybeRecordReferralConversion(
  client,
  refereeTelegramId,
  phaseId,
  paymentId
) {
  const attachment =
    (
      await client.query(
        `
          SELECT *
          FROM referral_attachments
          WHERE phase_id = $1
            AND referred_user_id = $2
          FOR UPDATE
        `,
        [
          phaseId,
          refereeTelegramId,
        ]
      )
    ).rows[0];

  if (!attachment) {
    return;
  }

  await client.query(
    `
      INSERT INTO referral_conversions (
        phase_id,
        referrer_id,
        referred_user_id,
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
      phaseId,

      attachment.referrer_id,

      refereeTelegramId,

      paymentId,
    ]
  );

  const count =
    Number(
      (
        await client.query(
          `
            SELECT
              COUNT(*)::int
                AS count

            FROM referral_conversions

            WHERE phase_id = $1
              AND referrer_id = $2
          `,
          [
            phaseId,
            attachment.referrer_id,
          ]
        )
      ).rows[0]
        ?.count ||
        0
    );

  if (
    count >=
    2
  ) {
    await client.query(
      `
        INSERT INTO free_entry_grants (
          phase_id,
          telegram_user_id,
          reason,
          required_referrals,
          status
        )
        VALUES (
          $1,
          $2,
          'two_referrals',
          2,
          'available'
        )
        ON CONFLICT (
          telegram_user_id,
          phase_id
        )
        DO NOTHING
      `,
      [
        phaseId,

        attachment.referrer_id,
      ]
    );
  }
}

/* =========================================================
   TON PROOF
========================================================= */

function walletCodeDescriptors() {
  const zeroKey =
    Buffer.alloc(
      32
    );

  const build = (
    version,
    wallet,
    parseData
  ) => ({
    version,

    codeHash:
      wallet.init.code
        .hash()
        .toString(
          "hex"
        ),

    parseData,
  });

  return [
    build(
      "V1R1",

      WalletContractV1R1.create({
        workchain:
          0,

        publicKey:
          zeroKey,
      }),

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
    ),

    build(
      "V1R2",

      WalletContractV1R2.create({
        workchain:
          0,

        publicKey:
          zeroKey,
      }),

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
    ),

    build(
      "V1R3",

      WalletContractV1R3.create({
        workchain:
          0,

        publicKey:
          zeroKey,
      }),

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
    ),

    build(
      "V2R1",

      WalletContractV2R1.create({
        workchain:
          0,

        publicKey:
          zeroKey,
      }),

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
    ),

    build(
      "V2R2",

      WalletContractV2R2.create({
        workchain:
          0,

        publicKey:
          zeroKey,
      }),

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
    ),

    build(
      "V3R1",

      WalletContractV3R1.create({
        workchain:
          0,

        publicKey:
          zeroKey,
      }),

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
    ),

    build(
      "V3R2",

      WalletContractV3R2.create({
        workchain:
          0,

        publicKey:
          zeroKey,
      }),

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
    ),

    build(
      "V4R2",

      WalletContractV4.create({
        workchain:
          0,

        publicKey:
          zeroKey,

        walletId:
          0x29a9a317,
      }),

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
    ),

    build(
      "V5R1",

      WalletContractV5R1.create({
        workchain:
          0,

        publicKey:
          zeroKey,

        walletId: {
          networkGlobalId:
            -239,
        },
      }),

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
    ),
  ];
}

let walletDescriptorsCache =
  null;

function extractPublicKeyFromStateInit(
  stateInit
) {
  if (
    !stateInit
      ?.code ||
    !stateInit
      ?.data
  ) {
    return null;
  }

  if (
    !walletDescriptorsCache
  ) {
    walletDescriptorsCache =
      walletCodeDescriptors();
  }

  const codeHash =
    stateInit.code
      .hash()
      .toString(
        "hex"
      );

  const descriptor =
    walletDescriptorsCache.find(
      (
        item
      ) =>
        item.codeHash ===
        codeHash
    );

  if (!descriptor) {
    return null;
  }

  try {
    const slice =
      stateInit.data.beginParse();

    const publicKey =
      descriptor.parseData(
        slice
      );

    if (
      !Buffer.isBuffer(
        publicKey
      ) ||
      publicKey.length !==
        32
    ) {
      return null;
    }

    return {
      publicKey,

      version:
        descriptor.version,
    };
  } catch {
    return null;
  }
}

function buildTonProofDigest(
  address,
  proof
) {
  const domain =
    Buffer.from(
      String(
        proof.domain.value
      ),
      "utf8"
    );

  if (
    domain.length !==
    Number(
      proof.domain.lengthBytes
    )
  ) {
    throw new Error(
      "TON Proof domain length mismatch"
    );
  }

  const wc =
    Buffer.alloc(
      4
    );

  wc.writeInt32BE(
    address.workChain,
    0
  );

  const domainLen =
    Buffer.alloc(
      4
    );

  domainLen.writeUInt32LE(
    domain.length,
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
        "ton-proof-item-v2/",
        "utf8"
      ),

      wc,

      address.hash,

      domainLen,

      domain,

      timestamp,

      Buffer.from(
        String(
          proof.payload
        ),
        "utf8"
      ),
    ]);

  const messageHash =
    sha256Buffer(
      message
    );

  return sha256Buffer(
    Buffer.concat([
      Buffer.from([
        0xff,
        0xff,
      ]),

      Buffer.from(
        "ton-connect",
        "utf8"
      ),

      messageHash,
    ])
  );
}

async function verifyTonProof({
  telegramUserId,
  proof,
  address,
  walletStateInit,
  network,
}) {
  if (
    !proof ||
    !address ||
    !walletStateInit
  ) {
    throw new Error(
      "TON Proof payload is incomplete"
    );
  }

  if (
    String(
      network
    ) !==
    TON_NETWORK
  ) {
    throw new Error(
      "Wrong TON network"
    );
  }

  if (
    !proof.domain ||
    String(
      proof.domain.value
    ) !==
      TON_PROOF_DOMAIN
  ) {
    throw new Error(
      "TON Proof domain mismatch"
    );
  }

  const timestamp =
    Number(
      proof.timestamp
    );

  const now =
    Math.floor(
      Date.now() /
        1000
    );

  if (
    !Number.isSafeInteger(
      timestamp
    ) ||
    Math.abs(
      now -
        timestamp
    ) >
      TON_PROOF_TTL_SECONDS
  ) {
    throw new Error(
      "TON Proof expired"
    );
  }

  const challenge =
    (
      await pool.query(
        `
          SELECT *
          FROM ton_proof_challenges
          WHERE telegram_user_id = $1
            AND nonce = $2
            AND used_at IS NULL
            AND expires_at > NOW()
          ORDER BY created_at DESC
          LIMIT 1
        `,
        [
          telegramUserId,

          String(
            proof.payload
          ),
        ]
      )
    ).rows[0];

  if (!challenge) {
    throw new Error(
      "TON Proof challenge is invalid or expired"
    );
  }

  const parsedAddress =
    Address.parse(
      String(
        address
      )
    );

  const stateInitCell =
    Cell.fromBase64(
      String(
        walletStateInit
      )
    );

  const stateInit =
    loadStateInit(
      stateInitCell.beginParse()
    );

  const derivedAddress =
    contractAddress(
      parsedAddress.workChain,
      stateInit
    );

  if (
    !derivedAddress.equals(
      parsedAddress
    )
  ) {
    throw new Error(
      "walletStateInit does not match wallet address"
    );
  }

  const extracted =
    extractPublicKeyFromStateInit(
      stateInit
    );

  if (
    !extracted
      ?.publicKey
  ) {
    throw new Error(
      "Unsupported wallet contract for local TON Proof verification"
    );
  }

  const signature =
    Buffer.from(
      String(
        proof.signature
      ),
      "base64"
    );

  if (
    signature.length !==
    64
  ) {
    throw new Error(
      "Invalid TON Proof signature"
    );
  }

  const digest =
    buildTonProofDigest(
      parsedAddress,
      proof
    );

  const ok =
    nacl.sign.detached.verify(
      new Uint8Array(
        digest
      ),

      new Uint8Array(
        signature
      ),

      new Uint8Array(
        extracted.publicKey
      )
    );

  if (!ok) {
    throw new Error(
      "TON Proof signature verification failed"
    );
  }

  return {
    address:
      parsedAddress.toString({
        bounceable:
          false,

        testOnly:
          TON_NETWORK !==
          "-239",
      }),

    version:
      extracted.version,

    challengeId:
      challenge.id,
  };
}

/* =========================================================
   ADMIN AUTH
========================================================= */

function requireAdmin(
  req,
  res,
  next
) {
  const provided =
    String(
      req.headers[
        "x-admin-secret"
      ] ||
        ""
    );

  if (
    !ADMIN_SECRET ||
    !timingSafeEqualText(
      provided,
      ADMIN_SECRET
    )
  ) {
    return res
      .status(
        401
      )
      .json({
        error:
          "Unauthorized.",
      });
  }

  return next();
}
/* =========================================================
   PAYMENT CREATION
========================================================= */

async function createEntryInvoice(
  telegramUser
) {
  if (
    !PAYMENTS_ENABLED
  ) {
    throw new Error(
      "Payments are currently disabled"
    );
  }

  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    await upsertUser(
      client,
      telegramUser
    );

    const phase =
      await getOrCreateCurrentPhase(
        client
      );

    if (
      phase.status !==
      "open"
    ) {
      throw new Error(
        "Today's phase is not open"
      );
    }

    const existing =
      (
        await client.query(
          `
            SELECT id
            FROM entries
            WHERE telegram_user_id = $1
              AND phase_id = $2
            LIMIT 1
          `,
          [
            telegramUser.id,
            phase.id,
          ]
        )
      ).rows[0];

    if (
      existing
    ) {
      throw new Error(
        "You already have an entry for today's phase"
      );
    }

    const grant =
      (
        await client.query(
          `
            SELECT *
            FROM free_entry_grants
            WHERE phase_id = $1
              AND telegram_user_id = $2
              AND status = 'available'
            LIMIT 1
          `,
          [
            phase.id,
            telegramUser.id,
          ]
        )
      ).rows[0];

    if (
      grant
    ) {
      await client.query(
        "COMMIT"
      );

      return {
        freeEntry:
          true,

        phaseId:
          Number(
            phase.id
          ),
      };
    }

    const invoiceToken =
      crypto.randomUUID();

    const payload =
      `pz_entry:${invoiceToken}:${phase.id}:${telegramUser.id}`;

    const expiresAt =
      new Date(
        Date.now() +
          15 *
            60_000
      );

    await client.query(
      `
        INSERT INTO invoices (
          invoice_token,
          telegram_user_id,
          phase_id,
          stars_amount,
          currency,
          payload,
          status,
          expires_at
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          'XTR',
          $5,
          'created',
          $6
        )
      `,
      [
        invoiceToken,
        telegramUser.id,
        phase.id,
        ENTRY_STARS,
        payload,
        expiresAt,
      ]
    );

    const invoiceLink =
      await telegramApi(
        "createInvoiceLink",
        {
          title:
            "Project Z Daily Entry",

          description:
            `Project Z daily entry — ${ENTRY_STARS} Telegram Stars`,

          payload,

          currency:
            "XTR",

          prices: [
            {
              label:
                "Daily entry",

              amount:
                ENTRY_STARS,
            },
          ],
        }
      );

    await audit(
      client,
      "invoice_created",
      telegramUser.id,
      phase.id,
      {
        invoiceToken,

        stars:
          ENTRY_STARS,
      }
    );

    await client.query(
      "COMMIT"
    );

    return {
      freeEntry:
        false,

      invoiceLink,

      invoiceToken,

      stars:
        ENTRY_STARS,

      entryUsdDisplay:
        ENTRY_USD_DISPLAY,
    };
  } catch (
    error
  ) {
    await client.query(
      "ROLLBACK"
    );

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   PAYMENT WEBHOOK HANDLING
========================================================= */

async function handlePreCheckoutQuery(
  query
) {
  try {
    const invoice =
      (
        await pool.query(
          `
            SELECT
              i.*,
              p.status AS phase_status,
              p.phase_date

            FROM invoices i

            JOIN phases p
              ON p.id = i.phase_id

            WHERE i.payload = $1

            LIMIT 1
          `,
          [
            query.invoice_payload,
          ]
        )
      ).rows[0];

    let ok =
      true;

    let errorMessage =
      undefined;

    if (
      !invoice
    ) {
      ok =
        false;

      errorMessage =
        "Invoice not found.";
    } else if (
      invoice.status !==
      "created"
    ) {
      ok =
        false;

      errorMessage =
        "Invoice is no longer active.";
    } else if (
      new Date(
        invoice.expires_at
      ).getTime() <=
      Date.now()
    ) {
      ok =
        false;

      errorMessage =
        "Invoice expired. Please create a new one.";
    } else if (
      String(
        query.currency
      ) !==
      "XTR"
    ) {
      ok =
        false;

      errorMessage =
        "Invalid payment currency.";
    } else if (
      Number(
        query.total_amount
      ) !==
      Number(
        invoice.stars_amount
      )
    ) {
      ok =
        false;

      errorMessage =
        "Invalid payment amount.";
    } else if (
      Number(
        query.from
          ?.id
      ) !==
      Number(
        invoice.telegram_user_id
      )
    ) {
      ok =
        false;

      errorMessage =
        "This invoice belongs to another user.";
    } else if (
      invoice.phase_status !==
        "open" ||
      toDateOnlyString(
        invoice.phase_date
      ) !==
        getMoscowDateString()
    ) {
      ok =
        false;

      errorMessage =
        "This daily phase has ended.";
    }

    await telegramApi(
      "answerPreCheckoutQuery",
      {
        pre_checkout_query_id:
          query.id,

        ok,

        ...(ok
          ? {}
          : {
              error_message:
                errorMessage,
            }),
      }
    );
  } catch (
    error
  ) {
    console.error(
      "Pre-checkout error:",
      error.message
    );

    try {
      await telegramApi(
        "answerPreCheckoutQuery",
        {
          pre_checkout_query_id:
            query.id,

          ok:
            false,

          error_message:
            "Payment validation failed. Please try again.",
        }
      );
    } catch {}
  }
}

async function queueUnexpectedRefund({
  userId,
  telegramPaymentChargeId,
  reason,
}) {
  if (
    !telegramPaymentChargeId
  ) {
    return;
  }

  await pool.query(
    `
      INSERT INTO payment_reconciliations (
        telegram_user_id,
        telegram_payment_charge_id,
        reason,
        status
      )
      VALUES (
        $1,
        $2,
        $3,
        'refund_pending'
      )
      ON CONFLICT (
        telegram_payment_charge_id
      )
      DO NOTHING
    `,
    [
      userId ||
        null,

      telegramPaymentChargeId,

      reason,
    ]
  );
}

async function handleSuccessfulPayment(
  message
) {
  const payment =
    message
      ?.successful_payment;

  const userId =
    message
      ?.from
      ?.id;

  if (
    !payment ||
    !userId
  ) {
    return;
  }

  const chargeId =
    payment.telegram_payment_charge_id;

  const payload =
    payment.invoice_payload;

  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    const duplicate =
      (
        await client.query(
          `
            SELECT id
            FROM payments
            WHERE telegram_payment_charge_id = $1
            LIMIT 1
          `,
          [
            chargeId,
          ]
        )
      ).rows[0];

    if (
      duplicate
    ) {
      await client.query(
        "COMMIT"
      );

      return;
    }

    const invoice =
      (
        await client.query(
          `
            SELECT
              i.*,
              p.status AS phase_status,
              p.phase_date

            FROM invoices i

            JOIN phases p
              ON p.id = i.phase_id

            WHERE i.payload = $1

            FOR UPDATE OF i, p
          `,
          [
            payload,
          ]
        )
      ).rows[0];

    const invalidReason =
      !invoice
        ? "invoice_not_found"

        : Number(
            invoice.telegram_user_id
          ) !==
          Number(
            userId
          )
          ? "wrong_user"

        : String(
            payment.currency
          ) !==
          "XTR"
          ? "wrong_currency"

        : Number(
            payment.total_amount
          ) !==
          Number(
            invoice.stars_amount
          )
          ? "wrong_amount"

        : invoice.status ===
          "paid"
          ? "invoice_already_paid"

        : invoice.phase_status !==
            "open" ||
          toDateOnlyString(
            invoice.phase_date
          ) !==
            getMoscowDateString()
          ? "phase_closed"

        : null;

    if (
      invalidReason
    ) {
      await client.query(
        "ROLLBACK"
      );

      await queueUnexpectedRefund({
        userId,

        telegramPaymentChargeId:
          chargeId,

        reason:
          invalidReason,
      });

      return;
    }

    await upsertUser(
      client,
      message.from
    );

    const paymentRow =
      (
        await client.query(
          `
            INSERT INTO payments (
              telegram_payment_charge_id,
              provider_payment_charge_id,
              telegram_user_id,
              phase_id,
              stars_amount,
              currency,
              invoice_payload,
              status,
              raw_payment
            )
            VALUES (
              $1,
              $2,
              $3,
              $4,
              $5,
              'XTR',
              $6,
              'succeeded',
              $7::jsonb
            )
            RETURNING *
          `,
          [
            chargeId,

            payment.provider_payment_charge_id ||
              null,

            userId,

            invoice.phase_id,

            invoice.stars_amount,

            invoice.payload,

            safeJson(
              payment
            ),
          ]
        )
      ).rows[0];

    const firstPaidCount =
      Number(
        (
          await client.query(
            `
              SELECT
                COUNT(*)::int
                  AS count

              FROM entries

              WHERE phase_id = $1
                AND is_free = FALSE
            `,
            [
              invoice.phase_id,
            ]
          )
        ).rows[0]
          ?.count ||
          0
      );

    await client.query(
      `
        INSERT INTO entries (
          telegram_user_id,
          phase_id,
          payment_id,
          source,
          is_free,
          is_first_payer
        )
        VALUES (
          $1,
          $2,
          $3,
          'paid',
          FALSE,
          $4
        )
        ON CONFLICT (
          telegram_user_id,
          phase_id
        )
        DO NOTHING
      `,
      [
        userId,

        invoice.phase_id,

        paymentRow.id,

        firstPaidCount ===
          0,
      ]
    );

    if (
      firstPaidCount ===
      0
    ) {
      const firstEntry =
        (
          await client.query(
            `
              SELECT id
              FROM entries
              WHERE telegram_user_id = $1
                AND phase_id = $2
              LIMIT 1
            `,
            [
              userId,

              invoice.phase_id,
            ]
          )
        ).rows[0];

      if (
        firstEntry
      ) {
        await client.query(
          `
            UPDATE phases
            SET
              first_verified_entry_id =
                COALESCE(
                  first_verified_entry_id,
                  $2
                )
            WHERE id = $1
          `,
          [
            invoice.phase_id,

            firstEntry.id,
          ]
        );
      }
    }

    await client.query(
      `
        UPDATE invoices
        SET
          status = 'paid',

          paid_at = NOW()

        WHERE id = $1
      `,
      [
        invoice.id,
      ]
    );

    await maybeRecordReferralConversion(
      client,
      userId,
      invoice.phase_id,
      paymentRow.id
    );

    await refreshPhaseTotals(
      client,
      invoice.phase_id
    );

    await audit(
      client,
      "payment_succeeded",
      userId,
      invoice.phase_id,
      {
        paymentId:
          paymentRow.id,

        chargeId,

        stars:
          invoice.stars_amount,
      }
    );

    await client.query(
      "COMMIT"
    );
  } catch (
    error
  ) {
    await client.query(
      "ROLLBACK"
    );

    console.error(
      "Successful payment processing failed:",
      error.message
    );

    await queueUnexpectedRefund({
      userId,

      telegramPaymentChargeId:
        chargeId,

      reason:
        `processing_error:${error.message}`.slice(
          0,
          500
        ),
    }).catch(
      () => {}
    );
  } finally {
    client.release();
  }
}

/* =========================================================
   REFUND WORKER
========================================================= */

async function processPendingRefunds() {
  if (
    !BOT_TOKEN
  ) {
    return;
  }

  const rows =
    (
      await pool.query(
        `
          SELECT *
          FROM payment_reconciliations
          WHERE status = 'refund_pending'
            AND attempts < 10
          ORDER BY created_at ASC
          LIMIT 10
        `
      )
    ).rows;

  for (
    const row
    of rows
  ) {
    try {
      await telegramApi(
        "refundStarPayment",
        {
          user_id:
            Number(
              row.telegram_user_id
            ),

          telegram_payment_charge_id:
            row.telegram_payment_charge_id,
        }
      );

      await pool.query(
        `
          UPDATE payment_reconciliations
          SET
            status = 'refunded',

            attempts =
              attempts + 1,

            last_error =
              NULL,

            updated_at =
              NOW()

          WHERE id = $1
        `,
        [
          row.id,
        ]
      );

      await pool.query(
        `
          UPDATE payments
          SET
            status = 'refunded',

            refunded_at =
              NOW()

          WHERE telegram_payment_charge_id = $1
        `,
        [
          row.telegram_payment_charge_id,
        ]
      );
    } catch (
      error
    ) {
      await pool.query(
        `
          UPDATE payment_reconciliations
          SET
            attempts =
              attempts + 1,

            last_error = $2,

            updated_at =
              NOW()

          WHERE id = $1
        `,
        [
          row.id,

          String(
            error.message
          ).slice(
            0,
            1000
          ),
        ]
      );
    }
  }
}

/* =========================================================
   FREE ENTRY CLAIM
========================================================= */

async function claimFreeEntry(
  telegramUser
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    await upsertUser(
      client,
      telegramUser
    );

    const phase =
      await getOrCreateCurrentPhase(
        client
      );

    const existing =
      (
        await client.query(
          `
            SELECT id
            FROM entries
            WHERE telegram_user_id = $1
              AND phase_id = $2
            LIMIT 1
          `,
          [
            telegramUser.id,
            phase.id,
          ]
        )
      ).rows[0];

    if (
      existing
    ) {
      throw new Error(
        "You already have an entry for today's phase"
      );
    }

    const grant =
      (
        await client.query(
          `
            SELECT *
            FROM free_entry_grants
            WHERE phase_id = $1
              AND telegram_user_id = $2
              AND status = 'available'
            FOR UPDATE
          `,
          [
            phase.id,
            telegramUser.id,
          ]
        )
      ).rows[0];

    if (
      !grant
    ) {
      throw new Error(
        "No free entry is currently available"
      );
    }

    await client.query(
      `
        INSERT INTO entries (
          telegram_user_id,
          phase_id,
          source,
          is_free,
          is_first_payer
        )
        VALUES (
          $1,
          $2,
          'referral_free',
          TRUE,
          FALSE
        )
      `,
      [
        telegramUser.id,
        phase.id,
      ]
    );

    await client.query(
      `
        UPDATE free_entry_grants
        SET
          status = 'claimed',

          claimed_at =
            NOW()

        WHERE id = $1
      `,
      [
        grant.id,
      ]
    );

    await refreshPhaseTotals(
      client,
      phase.id
    );

    await audit(
      client,
      "free_entry_claimed",
      telegramUser.id,
      phase.id,
      {
        grantId:
          grant.id,
      }
    );

    await client.query(
      "COMMIT"
    );

    return {
      ok:
        true,

      phaseId:
        Number(
          phase.id
        ),
    };
  } catch (
    error
  ) {
    await client.query(
      "ROLLBACK"
    );

    throw error;
  } finally {
    client.release();
  }
}
/* =========================================================
   DRAW / FINALIZATION
========================================================= */

function deterministicOrder(
  seedText,
  phaseId,
  entries
) {
  const seed =
    Buffer.from(
      seedText,
      "base64url"
    );

  return entries
    .map(
      (
        entry
      ) => ({
        ...entry,

        _score:
          crypto
            .createHmac(
              "sha256",
              seed
            )
            .update(
              `${phaseId}:${entry.id}:${entry.telegram_user_id}`
            )
            .digest(
              "hex"
            ),
      })
    )
    .sort(
      (
        a,
        b
      ) =>
        a._score.localeCompare(
          b._score
        )
    );
}

async function finalizePhase(
  phaseId
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    const phase =
      (
        await client.query(
          `
            SELECT *
            FROM phases
            WHERE id = $1
            FOR UPDATE
          `,
          [
            phaseId,
          ]
        )
      ).rows[0];

    if (
      !phase
    ) {
      throw new Error(
        "Phase not found"
      );
    }

    if (
      phase.status ===
      "finalized"
    ) {
      await client.query(
        "COMMIT"
      );

      return phase;
    }

    if (
      !isPastMoscowDate(
        phase.phase_date
      )
    ) {
      throw new Error(
        "Current/future phase cannot be finalized"
      );
    }

    await refreshPhaseTotals(
      client,
      phase.id
    );

    const refreshed =
      (
        await client.query(
          `
            SELECT *
            FROM phases
            WHERE id = $1
            FOR UPDATE
          `,
          [
            phase.id,
          ]
        )
      ).rows[0];

    const entries =
      (
        await client.query(
          `
            SELECT
              e.*,
              u.display_name

            FROM entries e

            LEFT JOIN users u
              ON u.telegram_id =
                e.telegram_user_id

            WHERE e.phase_id = $1

            ORDER BY e.id ASC
          `,
          [
            phase.id,
          ]
        )
      ).rows;

    const grossUsd =
      Number(
        refreshed.gross_usd ||
          0
      );

    const requestedWinnerCount =
      winnerCountForGrossUsd(
        grossUsd
      );

    const actualWinnerCount =
      Math.min(
        requestedWinnerCount,
        entries.length
      );

    const seedText =
      refreshed.draw_seed_secret ||
      randomToken(
        32
      );

    if (
      !refreshed.draw_commit_hash
    ) {
      await client.query(
        `
          UPDATE phases
          SET
            draw_seed_secret = $2,

            draw_commit_hash = $3

          WHERE id = $1
        `,
        [
          phase.id,

          seedText,

          sha256Hex(
            Buffer.from(
              seedText,
              "base64url"
            )
          ),
        ]
      );
    }

    let selected =
      [];

    if (
      actualWinnerCount >
      0
    ) {
      const firstPayer =
        entries.find(
          (
            entry
          ) =>
            entry.is_first_payer ===
            true
        ) ||
        entries.find(
          (
            entry
          ) =>
            entry.is_first_payer
        ) ||
        null;

      const others =
        entries.filter(
          (
            entry
          ) =>
            !firstPayer ||
            Number(
              entry.id
            ) !==
              Number(
                firstPayer.id
              )
        );

      const ordered =
        deterministicOrder(
          seedText,
          phase.id,
          others
        );

      selected =
        firstPayer
          ? [
              firstPayer,
              ...ordered.slice(
                0,
                Math.max(
                  0,
                  actualWinnerCount -
                    1
                )
              ),
            ]
          : ordered.slice(
              0,
              actualWinnerCount
            );
    }

    const winnerPoolUsd =
      grossUsd *
      WINNER_SHARE;

    const winnerPoolStarsEquiv =
      Number(
        refreshed.total_stars ||
          0
      ) *
      WINNER_SHARE;

    const perWinnerUsd =
      selected.length >
      0
        ? winnerPoolUsd /
          selected.length
        : 0;

    const perWinnerStarsEquiv =
      selected.length >
      0
        ? winnerPoolStarsEquiv /
          selected.length
        : 0;

    for (
      let i = 0;
      i <
      selected.length;
      i++
    ) {
      const entry =
        selected[i];

      const winner =
        (
          await client.query(
            `
              INSERT INTO winners (
                phase_id,
                entry_id,
                telegram_user_id,
                rank,
                prize_stars,
                is_first_payer,
                prize_usd,
                prize_stars_equiv
              )
              VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7,
                $8
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
                  EXCLUDED.is_first_payer,

                prize_usd =
                  EXCLUDED.prize_usd,

                prize_stars_equiv =
                  EXCLUDED.prize_stars_equiv

              RETURNING *
            `,
            [
              phase.id,

              entry.id,

              entry.telegram_user_id,

              i +
                1,

              money6(
                perWinnerStarsEquiv
              ),

              Boolean(
                entry.is_first_payer
              ),

              money6(
                perWinnerUsd
              ),

              money6(
                perWinnerStarsEquiv
              ),
            ]
          )
        ).rows[0];

      const userWallet =
        (
          await client.query(
            `
              SELECT
                ton_wallet_address

              FROM users

              WHERE telegram_id = $1
            `,
            [
              entry.telegram_user_id,
            ]
          )
        ).rows[0]
          ?.ton_wallet_address;

      await client.query(
        `
          INSERT INTO payouts (
            winner_id,
            telegram_user_id,
            phase_id,
            amount_stars,
            prize_usd,
            usdt_amount_micro,
            ton_wallet_address,
            status
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8
          )
          ON CONFLICT (
            winner_id
          )
          DO UPDATE SET
            prize_usd =
              EXCLUDED.prize_usd,

            usdt_amount_micro =
              EXCLUDED.usdt_amount_micro,

            ton_wallet_address =
              COALESCE(
                payouts.ton_wallet_address,
                EXCLUDED.ton_wallet_address
              ),

            status =
              CASE
                WHEN payouts.status =
                  'paid'
                  THEN 'paid'

                WHEN COALESCE(
                  payouts.ton_wallet_address,
                  EXCLUDED.ton_wallet_address
                ) IS NULL
                  THEN 'waiting_wallet'

                ELSE 'pending'
              END
        `,
        [
          winner.id,

          entry.telegram_user_id,

          phase.id,

          Math.max(
            1,
            Math.round(
              perWinnerStarsEquiv
            )
          ),

          money6(
            perWinnerUsd
          ),

          Math.round(
            perWinnerUsd *
              1_000_000
          ),

          userWallet ||
            null,

          userWallet
            ? "pending"
            : "waiting_wallet",
        ]
      );
    }

    await client.query(
      `
        UPDATE phases
        SET
          status =
            'finalized',

          winner_count =
            $2,

          draw_reveal =
            $3,

          finalized_at =
            NOW(),

          updated_at =
            NOW()

        WHERE id = $1
      `,
      [
        phase.id,

        selected.length,

        seedText,
      ]
    );

    await audit(
      client,
      "phase_finalized",
      null,
      phase.id,
      {
        grossUsd:
          money6(
            grossUsd
          ),

        totalStars:
          Number(
            refreshed.total_stars ||
              0
          ),

        requestedWinnerCount,

        actualWinnerCount:
          selected.length,

        winnerShare:
          WINNER_SHARE,

        charityShare:
          CHARITY_SHARE,

        operationsShare:
          OPERATIONS_SHARE,

        drawCommitHash:
          refreshed.draw_commit_hash,
      }
    );

    await client.query(
      "COMMIT"
    );

    return (
      await pool.query(
        `
          SELECT *
          FROM phases
          WHERE id = $1
        `,
        [
          phase.id,
        ]
      )
    ).rows[0];
  } catch (
    error
  ) {
    await client.query(
      "ROLLBACK"
    );

    throw error;
  } finally {
    client.release();
  }
}

async function finalizeOldPhases() {
  const rows =
    (
      await pool.query(
        `
          SELECT id
          FROM phases

          WHERE status =
              'open'

            AND phase_date <
              $1::date

          ORDER BY
            phase_date ASC

          LIMIT 20
        `,
        [
          getMoscowDateString(),
        ]
      )
    ).rows;

  for (
    const row
    of rows
  ) {
    try {
      await finalizePhase(
        row.id
      );
    } catch (
      error
    ) {
      console.error(
        `Failed to finalize phase ${row.id}:`,
        error.message
      );
    }
  }
}

/* =========================================================
   PUBLIC API
========================================================= */

app.get(
  "/health",
  async (
    req,
    res
  ) => {
    let db =
      false;

    try {
      await pool.query(
        "SELECT 1"
      );

      db =
        true;
    } catch {}

    res
      .status(
        db
          ? 200
          : 503
      )
      .json({
        ok:
          db,

        service:
          "Project Z",

        database:
          db,

        paymentsEnabled:
          PAYMENTS_ENABLED,

        paymentsReady:
          PAYMENTS_ENABLED &&
          missingEnv.length ===
            0 &&
          ENTRY_STARS >
            0,

        missingRequiredEnv:
          missingEnv,

        entryStars:
          ENTRY_STARS,

        entryUsdDisplay:
          ENTRY_USD_DISPLAY,

        starUsdEconomicRate:
          STAR_USD_RATE,

        split: {
          winners:
            WINNER_SHARE,

          charity:
            CHARITY_SHARE,

          operations:
            OPERATIONS_SHARE,
        },

        timezone:
          MOSCOW_TIME_ZONE,

        moscowDate:
          getMoscowDateString(),

        tonNetwork:
          TON_NETWORK,

        tonProofDomain:
          TON_PROOF_DOMAIN,

        treasuryWalletAddress:
          TREASURY_WALLET_ADDRESS ||
          null,

        usdtJettonMaster:
          USDT_JETTON_MASTER,

        automaticSettlementEnabled:
          AUTOMATIC_SETTLEMENT_ENABLED,
      });
  }
);

app.get(
  "/",
  (
    req,
    res
  ) => {
    res.json({
      ok:
        true,

      service:
        "Project Z API",

      health:
        "/health",
    });
  }
);

app.get(
  "/api/stats",
  async (
    req,
    res,
    next
  ) => {
    try {
      const phase =
        await getCurrentPhase();

      const participants =
        (
          await pool.query(
            `
              SELECT
                e.telegram_user_id,
                e.created_at,

                COALESCE(
                  u.display_name,
                  'Participant'
                )
                  AS display_name

              FROM entries e

              LEFT JOIN users u
                ON u.telegram_id =
                  e.telegram_user_id

              WHERE e.phase_id = $1

              ORDER BY
                e.created_at DESC

              LIMIT 50
            `,
            [
              phase.id,
            ]
          )
        ).rows;

      const totalStars =
        Number(
          phase.total_stars ||
            0
        );

      const grossUsd =
        grossUsdFromStars(
          totalStars
        );

      const prizePoolUsd =
        grossUsd *
        WINNER_SHARE;

      const prizePoolStars =
        totalStars *
        WINNER_SHARE;

      res.json({
        phaseId:
          Number(
            phase.id
          ),

        phaseDate:
          toDateOnlyString(
            phase.phase_date
          ),

        phaseStatus:
          phase.status,

        participants:
          Number(
            phase.entry_count ||
              participants.length
          ),

        paidParticipants:
          Number(
            phase.paid_entry_count ||
              0
          ),

        freeParticipants:
          Number(
            phase.free_entry_count ||
              0
          ),

        totalStars,

        grossUsd:
          money6(
            grossUsd
          ),

        poolStars:
          money6(
            prizePoolStars
          ),

        poolUsd:
          money6(
            prizePoolUsd
          ),

        charityUsd:
          money6(
            grossUsd *
              CHARITY_SHARE
          ),

        operationsUsd:
          money6(
            grossUsd *
              OPERATIONS_SHARE
          ),

        drawCommitHash:
          phase.draw_commit_hash ||
          null,

        participantList:
          participants.map(
            (
              participant
            ) => ({
              displayName:
                participant.display_name,

              createdAt:
                participant.created_at,
            })
          ),
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.get(
  "/api/winners",
  async (
    req,
    res,
    next
  ) => {
    try {
      const rows =
        (
          await pool.query(`
            SELECT
              w.id,
              w.phase_id,
              w.telegram_user_id,
              w.rank,
              w.prize_usd,

              COALESCE(
                w.prize_stars_equiv,
                w.prize_stars
              )
                AS prize_stars_equiv,

              w.created_at,

              p.phase_date,
              p.draw_commit_hash,
              p.draw_reveal,

              COALESCE(
                u.display_name,
                'Winner'
              )
                AS display_name,

              po.status
                AS payout_status,

              po.ton_tx_hash

            FROM winners w

            JOIN phases p
              ON p.id =
                w.phase_id

            LEFT JOIN users u
              ON u.telegram_id =
                w.telegram_user_id

            LEFT JOIN payouts po
              ON po.winner_id =
                w.id

            ORDER BY
              p.phase_date DESC,
              w.rank ASC

            LIMIT 200
          `)
        ).rows;

      res.json({
        winners:
          rows.map(
            (
              row
            ) => ({
              id:
                Number(
                  row.id
                ),

              phaseId:
                Number(
                  row.phase_id
                ),

              phaseDate:
                toDateOnlyString(
                  row.phase_date
                ),

              displayName:
                row.display_name,

              rank:
                Number(
                  row.rank
                ),

              prizeUsd:
                Number(
                  row.prize_usd
                ),

              prizeStars:
                Number(
                  row.prize_stars_equiv
                ),

              payoutStatus:
                row.payout_status,

              tonTxHash:
                row.ton_tx_hash ||
                null,

              drawCommitHash:
                row.draw_commit_hash ||
                null,

              drawReveal:
                row.draw_reveal ||
                null,
            })
          ),
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);
/* =========================================================
   AUTHENTICATED USER API
========================================================= */

app.post(
  "/api/user-status",
  async (
    req,
    res,
    next
  ) => {
    const verified =
      requireTelegramUser(
        req,
        res
      );

    if (!verified) {
      return;
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      await upsertUser(
        client,
        verified.user
      );

      const phase =
        await getOrCreateCurrentPhase(
          client
        );

      const entry =
        (
          await client.query(
            `
              SELECT *
              FROM entries
              WHERE telegram_user_id = $1
                AND phase_id = $2
              ORDER BY created_at ASC
              LIMIT 1
            `,
            [
              verified.user.id,
              phase.id,
            ]
          )
        ).rows[0];

      const referral =
        await getOrCreateReferralLink(
          client,
          verified.user.id,
          phase.id
        );

      const referralProgress =
        Number(
          (
            await client.query(
              `
                SELECT
                  COUNT(*)::int
                    AS count

                FROM referral_conversions

                WHERE phase_id = $1
                  AND referrer_id = $2
              `,
              [
                phase.id,
                verified.user.id,
              ]
            )
          ).rows[0]
            ?.count ||
            0
        );

      const grant =
        (
          await client.query(
            `
              SELECT
                status

              FROM free_entry_grants

              WHERE phase_id = $1
                AND telegram_user_id = $2

              LIMIT 1
            `,
            [
              phase.id,
              verified.user.id,
            ]
          )
        ).rows[0];

      const userRow =
        (
          await client.query(
            `
              SELECT
                ton_wallet_address,
                ton_wallet_verified_at

              FROM users

              WHERE telegram_id = $1
            `,
            [
              verified.user.id,
            ]
          )
        ).rows[0];

      await client.query(
        "COMMIT"
      );

      res.json({
        telegramUserId:
          verified.user.id,

        phaseId:
          Number(
            phase.id
          ),

        phaseDate:
          toDateOnlyString(
            phase.phase_date
          ),

        hasEntry:
          Boolean(
            entry
          ),

        entrySource:
          entry
            ?.source ||
          null,

        isFirstPayer:
          Boolean(
            entry
              ?.is_first_payer
          ),

        referralLink:
          referral.link,

        referralCode:
          referral.code,

        referralProgress,

        freeEntryAvailable:
          grant
            ?.status ===
          "available",

        freeEntryStatus:
          grant
            ?.status ||
          null,

        tonWalletAddress:
          userRow
            ?.ton_wallet_address ||
          null,

        tonWalletVerified:
          Boolean(
            userRow
              ?.ton_wallet_verified_at
          ),
      });
    } catch (
      error
    ) {
      await client.query(
        "ROLLBACK"
      );

      next(
        error
      );
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/create-entry-invoice",
  paymentLimiter,
  async (
    req,
    res,
    next
  ) => {
    const verified =
      requireTelegramUser(
        req,
        res
      );

    if (!verified) {
      return;
    }

    try {
      const result =
        await createEntryInvoice(
          verified.user
        );

      res.json(
        result
      );
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.post(
  "/api/claim-free-entry",
  async (
    req,
    res,
    next
  ) => {
    const verified =
      requireTelegramUser(
        req,
        res
      );

    if (!verified) {
      return;
    }

    try {
      res.json(
        await claimFreeEntry(
          verified.user
        )
      );
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.post(
  "/api/attach-referral",
  async (
    req,
    res,
    next
  ) => {
    const verified =
      requireTelegramUser(
        req,
        res
      );

    if (!verified) {
      return;
    }

    const code =
      String(
        req.body
          ?.code ||
        ""
      ).trim();

    if (
      !/^ref_[A-Za-z0-9_-]+$/.test(
        code
      ) ||
      code.length >
        120
    ) {
      return res
        .status(
          400
        )
        .json({
          error:
            "Invalid referral code.",
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      await upsertUser(
        client,
        verified.user
      );

      const phase =
        await getOrCreateCurrentPhase(
          client
        );

      const link =
        (
          await client.query(
            `
              SELECT *
              FROM referral_links
              WHERE code = $1
                AND phase_id = $2
              LIMIT 1
            `,
            [
              code,
              phase.id,
            ]
          )
        ).rows[0];

      if (!link) {
        throw new Error(
          "Referral link is not valid for today's phase"
        );
      }

      if (
        Number(
          link.referrer_id
        ) ===
        Number(
          verified.user.id
        )
      ) {
        throw new Error(
          "You cannot refer yourself"
        );
      }

      await client.query(
        `
          INSERT INTO referral_attachments (
            phase_id,
            referrer_id,
            referred_user_id,
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
          phase.id,
          link.referrer_id,
          verified.user.id,
          link.id,
        ]
      );

      await audit(
        client,
        "referral_attached",
        verified.user.id,
        phase.id,
        {
          referrer:
            Number(
              link.referrer_id
            ),

          code,
        }
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok:
          true,
      });
    } catch (
      error
    ) {
      await client.query(
        "ROLLBACK"
      );

      next(
        error
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   TON CONNECT API
========================================================= */

app.post(
  "/api/tonconnect/nonce",
  proofLimiter,
  async (
    req,
    res,
    next
  ) => {
    const verified =
      requireTelegramUser(
        req,
        res
      );

    if (!verified) {
      return;
    }

    try {
      const nonce =
        randomToken(
          32
        );

      const expiresAt =
        new Date(
          Date.now() +
            TON_PROOF_TTL_SECONDS *
              1000
        );

      await pool.query(
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
          verified.user.id,
          nonce,
          TON_PROOF_DOMAIN,
          expiresAt,
        ]
      );

      res.json({
        nonce,

        expiresAt:
          expiresAt.toISOString(),

        domain:
          TON_PROOF_DOMAIN,

        network:
          TON_NETWORK,
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.post(
  "/api/tonconnect/verify",
  proofLimiter,
  async (
    req,
    res,
    next
  ) => {
    const verified =
      requireTelegramUser(
        req,
        res
      );

    if (!verified) {
      return;
    }

    const client =
      await pool.connect();

    try {
      const result =
        await verifyTonProof({
          telegramUserId:
            verified.user.id,

          proof:
            req.body
              ?.proof,

          address:
            req.body
              ?.address,

          walletStateInit:
            req.body
              ?.walletStateInit,

          network:
            req.body
              ?.network,
        });

      await client.query(
        "BEGIN"
      );

      await upsertUser(
        client,
        verified.user
      );

      await client.query(
        `
          UPDATE ton_proof_challenges
          SET
            used_at =
              NOW()
          WHERE id = $1
            AND used_at IS NULL
        `,
        [
          result.challengeId,
        ]
      );

      await client.query(
        `
          UPDATE users
          SET
            ton_wallet_address = $2,

            ton_wallet_verified_at =
              NOW(),

            updated_at =
              NOW()

          WHERE telegram_id = $1
        `,
        [
          verified.user.id,
          result.address,
        ]
      );

      await client.query(
        `
          UPDATE payouts
          SET
            ton_wallet_address = $2,

            status =
              CASE
                WHEN status =
                  'waiting_wallet'
                THEN 'pending'
                ELSE status
              END

          WHERE telegram_user_id = $1
            AND status IN (
              'waiting_wallet',
              'pending'
            )
        `,
        [
          verified.user.id,
          result.address,
        ]
      );

      await audit(
        client,
        "ton_wallet_verified",
        verified.user.id,
        null,
        {
          walletAddress:
            result.address,

          walletVersion:
            result.version,
        }
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok:
          true,

        walletAddress:
          result.address,

        walletVersion:
          result.version,
      });
    } catch (
      error
    ) {
      await client
        .query(
          "ROLLBACK"
        )
        .catch(
          () => {}
        );

      next(
        error
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   TELEGRAM WEBHOOK
========================================================= */

app.post(
  "/telegram/webhook",
  async (
    req,
    res
  ) => {
    const secret =
      String(
        req.headers[
          "x-telegram-bot-api-secret-token"
        ] ||
          ""
      );

    if (
      !TELEGRAM_WEBHOOK_SECRET ||
      !timingSafeEqualText(
        secret,
        TELEGRAM_WEBHOOK_SECRET
      )
    ) {
      return res
        .status(
          401
        )
        .json({
          ok:
            false,
        });
    }

    res.json({
      ok:
        true,
    });

    const update =
      req.body ||
      {};

    try {
      if (
        update.pre_checkout_query
      ) {
        await handlePreCheckoutQuery(
          update.pre_checkout_query
        );

        return;
      }

      if (
        update.message
          ?.successful_payment
      ) {
        await handleSuccessfulPayment(
          update.message
        );

        return;
      }
    } catch (
      error
    ) {
      console.error(
        "Webhook processing error:",
        error.message
      );
    }
  }
);
/* =========================================================
   ADMIN API
========================================================= */

app.get(
  "/api/admin/stars-balance",
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const balance =
        await telegramApi(
          "getMyStarBalance",
          {}
        );

      res.json({
        ok:
          true,

        balance,
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.get(
  "/api/admin/payouts",
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const status =
        String(
          req.query
            ?.status ||
          ""
        ).trim();

      const params =
        [];

      let where =
        "";

      if (
        status
      ) {
        params.push(
          status
        );

        where =
          `WHERE po.status = $1`;
      }

      const rows =
        (
          await pool.query(
            `
              SELECT
                po.*,

                w.rank,

                p.phase_date,

                COALESCE(
                  u.display_name,
                  'Winner'
                )
                  AS display_name

              FROM payouts po

              JOIN winners w
                ON w.id =
                  po.winner_id

              JOIN phases p
                ON p.id =
                  po.phase_id

              LEFT JOIN users u
                ON u.telegram_id =
                  po.telegram_user_id

              ${where}

              ORDER BY
                po.created_at DESC

              LIMIT 500
            `,
            params
          )
        ).rows;

      res.json({
        automaticSettlementEnabled:
          AUTOMATIC_SETTLEMENT_ENABLED,

        settlementAsset:
          "USDT on TON",

        treasuryWalletAddress:
          TREASURY_WALLET_ADDRESS ||
          null,

        usdtJettonMaster:
          USDT_JETTON_MASTER,

        payouts:
          rows.map(
            (
              row
            ) => ({
              id:
                Number(
                  row.id
                ),

              phaseId:
                Number(
                  row.phase_id
                ),

              phaseDate:
                toDateOnlyString(
                  row.phase_date
                ),

              rank:
                Number(
                  row.rank
                ),

              telegramUserId:
                Number(
                  row.telegram_user_id
                ),

              displayName:
                row.display_name,

              prizeUsd:
                Number(
                  row.prize_usd ||
                    0
                ),

              usdtAmountMicro:
                Number(
                  row.usdt_amount_micro ||
                    0
                ),

              tonWalletAddress:
                row.ton_wallet_address ||
                null,

              status:
                row.status,

              tonTxHash:
                row.ton_tx_hash ||
                null,

              settlementReference:
                row.settlement_reference ||
                null,

              paidAt:
                row.paid_at ||
                null,
            })
          ),
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.post(
  "/api/admin/payouts/:id/mark-paid",
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const payoutId =
        Number(
          req.params.id
        );

      const tonTxHash =
        String(
          req.body
            ?.tonTxHash ||
          ""
        ).trim();

      const settlementReference =
        String(
          req.body
            ?.settlementReference ||
          tonTxHash
        ).trim();

      if (
        !Number.isSafeInteger(
          payoutId
        ) ||
        payoutId <=
          0
      ) {
        return res
          .status(
            400
          )
          .json({
            error:
              "Invalid payout id.",
          });
      }

      if (
        !tonTxHash ||
        tonTxHash.length >
          300
      ) {
        return res
          .status(
            400
          )
          .json({
            error:
              "A confirmed TON transaction hash/reference is required.",
          });
      }

      const row =
        (
          await pool.query(
            `
              UPDATE payouts

              SET
                status =
                  'paid',

                ton_tx_hash =
                  $2,

                settlement_reference =
                  $3,

                paid_at =
                  NOW(),

                failure_reason =
                  NULL

              WHERE id =
                  $1

                AND status <>
                  'paid'

              RETURNING *
            `,
            [
              payoutId,

              tonTxHash,

              settlementReference,
            ]
          )
        ).rows[0];

      if (
        !row
      ) {
        return res
          .status(
            404
          )
          .json({
            error:
              "Payout not found or already marked paid.",
          });
      }

      res.json({
        ok:
          true,

        payout:
          row,
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.post(
  "/api/admin/payouts/:id/mark-failed",
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const payoutId =
        Number(
          req.params.id
        );

      const reason =
        String(
          req.body
            ?.reason ||
          "Settlement failed"
        ).slice(
          0,
          1000
        );

      const row =
        (
          await pool.query(
            `
              UPDATE payouts

              SET
                status =
                  'failed',

                failure_reason =
                  $2

              WHERE id =
                  $1

                AND status <>
                  'paid'

              RETURNING *
            `,
            [
              payoutId,

              reason,
            ]
          )
        ).rows[0];

      if (
        !row
      ) {
        return res
          .status(
            404
          )
          .json({
            error:
              "Payout not found.",
          });
      }

      res.json({
        ok:
          true,

        payout:
          row,
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

app.post(
  "/api/admin/finalize/:phaseId",
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const phaseId =
        Number(
          req.params.phaseId
        );

      if (
        !Number.isSafeInteger(
          phaseId
        ) ||
        phaseId <=
          0
      ) {
        return res
          .status(
            400
          )
          .json({
            error:
              "Invalid phase id.",
          });
      }

      const phase =
        await finalizePhase(
          phaseId
        );

      res.json({
        ok:
          true,

        phase,
      });
    } catch (
      error
    ) {
      next(
        error
      );
    }
  }
);

/* =========================================================
   ERROR HANDLING
========================================================= */

app.use(
  (
    req,
    res
  ) => {
    res
      .status(
        404
      )
      .json({
        error:
          "Not found.",
      });
  }
);

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "Request error:",
      error.message
    );

    const message =
      String(
        error.message ||
          "Internal server error"
      );

    const clientErrorPatterns =
      [
        /already/i,
        /invalid/i,
        /expired/i,
        /not found/i,
        /not open/i,
        /cannot/i,
        /no free entry/i,
        /wrong/i,
        /unsupported wallet/i,
        /phase has ended/i,
      ];

    const isClientError =
      clientErrorPatterns.some(
        (
          regex
        ) =>
          regex.test(
            message
          )
      );

    res
      .status(
        isClientError
          ? 400
          : 500
      )
      .json({
        error:
          isClientError
            ? message
            : "Internal server error.",
      });
  }
);

/* =========================================================
   BACKGROUND WORKERS
========================================================= */

let workersStarted =
  false;

function startWorkers() {
  if (
    workersStarted
  ) {
    return;
  }

  workersStarted =
    true;

  setInterval(
    () => {
      finalizeOldPhases()
        .catch(
          (
            error
          ) => {
            console.error(
              "Finalize worker:",
              error.message
            );
          }
        );
    },
    60_000
  ).unref();

  setInterval(
    () => {
      processPendingRefunds()
        .catch(
          (
            error
          ) => {
            console.error(
              "Refund worker:",
              error.message
            );
          }
        );
    },
    60_000
  ).unref();

  setInterval(
    () => {
      pool.query(
        `
          DELETE FROM ton_proof_challenges
          WHERE expires_at <
            NOW() -
            INTERVAL '1 day'
        `
      ).catch(
        () => {}
      );
    },
    60 *
      60_000
  ).unref();

  console.log(
    "Background workers started."
  );
}

/* =========================================================
   STARTUP / SHUTDOWN
========================================================= */

async function start() {
  if (
    !DATABASE_URL
  ) {
    throw new Error(
      "DATABASE_URL missing"
    );
  }

  await initDb();

  await getCurrentPhase();

  await finalizeOldPhases();

  startWorkers();

  const server =
    app.listen(
      PORT,
      "0.0.0.0",
      async () => {
        console.log(
          `Project Z running on 0.0.0.0:${PORT}`
        );

        console.log(
          `Moscow phase date: ${getMoscowDateString()}`
        );

        console.log(
          `Payments ready: ${
            PAYMENTS_ENABLED &&
            missingEnv.length ===
              0
          }`
        );

        console.log(
          `Allowed frontend origin: ${FRONTEND_ORIGIN}`
        );

        console.log(
          `TON Proof domain: ${TON_PROOF_DOMAIN}`
        );

        console.log(
          "Settlement asset: USDT on TON"
        );

        console.log(
          `Treasury public address configured: ${Boolean(
            TREASURY_WALLET_ADDRESS
          )}`
        );

        console.log(
          "Automatic on-chain settlement: DISABLED"
        );

        await ensureWebhook();
      }
    );

  const shutdown =
    async (
      signal
    ) => {
      console.log(
        `Received ${signal}; shutting down.`
      );

      server.close(
        async () => {
          await pool
            .end()
            .catch(
              () => {}
            );

          process.exit(
            0
          );
        }
      );

      setTimeout(
        () =>
          process.exit(
            1
          ),
        10_000
      ).unref();
    };

  process.on(
    "SIGTERM",
    () =>
      shutdown(
        "SIGTERM"
      )
  );

  process.on(
    "SIGINT",
    () =>
      shutdown(
        "SIGINT"
      )
  );
}

start().catch(
  (
    error
  ) => {
    console.error(
      "Fatal startup error:",
      error
    );

    process.exit(
      1
    );
  }
);
