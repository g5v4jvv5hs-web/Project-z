import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Pool } from 'pg';
import crypto from 'crypto';

const app = express();
app.set('trust proxy', 1);

/* =========================================================
   PROJECT Z — FINAL PRODUCTION BACKEND (v1.0)
   Money-handling system. Extremely careful.
   ========================================================= */

const PORT = Number(process.env.PORT || 10000);

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET || '';
const APP_URL = process.env.APP_URL || '';
const ENTRY_STARS = Number(process.env.ENTRY_STARS || 0);
const STAR_USD_RATE = Number(process.env.STAR_USD_RATE || 0.00141);
const PAYMENTS_ENABLED = process.env.PAYMENTS_ENABLED === 'true';
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const BOT_USERNAME = process.env.BOT_USERNAME || '';

const MOSCOW_TIME_ZONE = 'Europe/Moscow';

const requiredEnv = [
  'BOT_TOKEN',
  'DATABASE_URL',
  'TELEGRAM_WEBHOOK_SECRET',
  'APP_URL',
  'ENTRY_STARS'
];

const missingEnv = requiredEnv.filter((key) => !process.env[key]);

const paymentsReady =
  PAYMENTS_ENABLED &&
  missingEnv.length === 0 &&
  Number.isInteger(ENTRY_STARS) &&
  ENTRY_STARS > 0;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

/* =========================================================
   MIDDLEWARE
   ========================================================= */

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Telegram-Init-Data', 'X-Admin-Secret']
}));
app.use(express.json({ limit: '64kb' }));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

/* =========================================================
   HELPERS
   ========================================================= */
function safeJson(value) {
  try {
    return JSON.stringify(value ?? null);
  } catch {
    return null;
  }
}
async function audit(client, eventType, actorTelegramId = null, phaseId = null, payload = null) {
  await client.query(
    `INSERT INTO audit_logs (event_type, actor_telegram_id, phase_id, payload)
     VALUES ($1, $2, $3, $4)`,
    [eventType, actorTelegramId, phaseId, safeJson(payload)]
  );
}
function getMoscowDateString(date = new Date()) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: MOSCOW_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(date);
}
/**
 * Normalize a value coming from PostgreSQL (DATE columns may be returned
 * as JS Date or as a string depending on driver/version) into a
 * 'YYYY-MM-DD' string safe for lexicographic comparison.
 */
function toDateOnlyString(value) {
  if (!value) return null;
  if (typeof value === 'string') return value.slice(0, 10);
  if (value instanceof Date) return getMoscowDateString(value);
  return String(value).slice(0, 10);
}
/* =========================================================
   TON PROOF HELPERS
========================================================= */
/* =========================================================
   TON PROOF HELPERS
========================================================= */

function createTonProofNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function getTonProofDomain() {
  try {
    return new URL(APP_URL).host;
  } catch {
    return APP_URL;
  }
}

function getTonProofExpirationSeconds() {
  return 10 * 60;
}

function normalizeTonAddress(address) {
  if (typeof address !== 'string') {
    return null;
  }

  const value = address.trim();

  if (!value) {
    return null;
  }

  return value;
}
/* =========================================================
   TELEGRAM INIT DATA (official HMAC-SHA256)
   ========================================================= */

function verifyInitData(initData) {
  if (!initData || typeof initData !== 'string' || !BOT_TOKEN) return null;

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get('hash');
    if (!receivedHash) return null;

    params.delete('hash');

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

    const receivedBuffer = Buffer.from(receivedHash, 'hex');
    const calculatedBuffer = Buffer.from(calculatedHash, 'hex');

    if (
      receivedBuffer.length !== calculatedBuffer.length ||
      !crypto.timingSafeEqual(receivedBuffer, calculatedBuffer)
    ) {
      return null;
    }

    const authDate = Number(params.get('auth_date') || 0);
    if (!authDate) return null;

    const age = Math.floor(Date.now() / 1000) - authDate;
    if (age < -60 || age > 86400) return null; // max 24h

    const userString = params.get('user');
    if (!userString) return null;

    const user = JSON.parse(userString);
    if (!user || typeof user.id !== 'number') return null;

    return user;
  } catch {
    return null;
  }
}

function getInitData(req) {
  return (
    req.headers['x-telegram-init-data'] ||
    req.headers['X-Telegram-Init-Data'] ||
    req.body?.initData ||
    ''
  );
}

/* =========================================================
   TELEGRAM API
   ========================================================= */

async function telegramApi(method, body = {}) {
  if (!BOT_TOKEN) throw new Error('BOT_TOKEN missing');

  const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  const data = await response.json();
  if (!data.ok) throw new Error(data.description || `Telegram ${method} failed`);
  return data.result;
}

/* =========================================================
   DATABASE INITIALIZATION (auto-create tables)
   ========================================================= */
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
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
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS ton_wallet_address TEXT
    `);
    await client.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS ton_wallet_public_key TEXT
    `);
    await client.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS ton_wallet_chain INTEGER
    `);
    await client.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS ton_wallet_verified_at TIMESTAMPTZ
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
      CREATE INDEX IF NOT EXISTS idx_ton_proof_challenges_user
      ON ton_proof_challenges(telegram_user_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_ton_proof_challenges_expires
      ON ton_proof_challenges(expires_at)
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
      CREATE TABLE IF NOT EXISTS payments (
        id BIGSERIAL PRIMARY KEY,
        telegram_payment_charge_id TEXT NOT NULL UNIQUE,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        stars_amount NUMERIC(30,0) NOT NULL,
        currency TEXT NOT NULL,
        invoice_payload TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS invoices (
        id BIGSERIAL PRIMARY KEY,
        invoice_token TEXT NOT NULL UNIQUE,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        stars_amount NUMERIC(30,0) NOT NULL,
        payload TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'created',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS entries (
        id BIGSERIAL PRIMARY KEY,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        payment_id BIGINT REFERENCES payments(id),
        is_free BOOLEAN NOT NULL DEFAULT FALSE,
        is_first_payer BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (telegram_user_id, phase_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS referral_links (
        id BIGSERIAL PRIMARY KEY,
        referrer_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        code TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (referrer_id, phase_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS referral_attachments (
        id BIGSERIAL PRIMARY KEY,
        referred_user_id BIGINT NOT NULL,
        referrer_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        referral_link_id BIGINT REFERENCES referral_links(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (referred_user_id, phase_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS referral_conversions (
        id BIGSERIAL PRIMARY KEY,
        referred_user_id BIGINT NOT NULL,
        referrer_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        payment_id BIGINT NOT NULL REFERENCES payments(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (referred_user_id, phase_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS free_entry_grants (
        id BIGSERIAL PRIMARY KEY,
        telegram_user_id BIGINT NOT NULL,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        reason TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (telegram_user_id, phase_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS winners (
        id BIGSERIAL PRIMARY KEY,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        entry_id BIGINT NOT NULL UNIQUE,
        telegram_user_id BIGINT NOT NULL,
        rank INTEGER NOT NULL,
        prize_stars NUMERIC(30,0) NOT NULL,
        is_first_payer BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (phase_id, rank)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS payouts (
        id BIGSERIAL PRIMARY KEY,
        phase_id BIGINT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
        winner_id BIGINT NOT NULL REFERENCES winners(id) ON DELETE CASCADE,
        telegram_user_id BIGINT NOT NULL,
        amount_stars NUMERIC(30,0) NOT NULL
          CHECK (amount_stars > 0),
        status TEXT NOT NULL DEFAULT 'pending',
        telegram_transaction_id TEXT,
        ton_wallet_address TEXT,
        ton_tx_hash TEXT,
        failure_reason TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        processing_at TIMESTAMPTZ,
        paid_at TIMESTAMPTZ,
        UNIQUE (winner_id)
      )
    `);
    await client.query(`
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS ton_wallet_address TEXT
    `);
    await client.query(`
      ALTER TABLE payouts
      ADD COLUMN IF NOT EXISTS ton_tx_hash TEXT
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS allocations (
        id BIGSERIAL PRIMARY KEY,
        phase_id BIGINT NOT NULL REFERENCES phases(id),
        type TEXT NOT NULL,
        stars_amount NUMERIC(30,0) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (phase_id, type)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        event_type TEXT NOT NULL,
        actor_telegram_id BIGINT,
        phase_id BIGINT REFERENCES phases(id),
        payload JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_entries_phase
      ON entries(phase_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_entries_user_phase
      ON entries(telegram_user_id, phase_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_payments_phase
      ON payments(phase_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_referral_conversions_referrer
      ON referral_conversions(referrer_id, phase_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_payouts_status
      ON payouts(status)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_payouts_phase
      ON payouts(phase_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_audit_phase
      ON audit_logs(phase_id)
    `);
    await client.query('COMMIT');
    console.log('Database initialized successfully.');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
/* =========================================================
   CURRENT PHASE (Moscow calendar date)
   ========================================================= */

async function getCurrentPhase(client, create = true) {
  const phaseDate = getMoscowDateString();
  let result = await client.query(`SELECT * FROM phases WHERE phase_date = $1`, [phaseDate]);

  if (result.rows.length > 0) return result.rows[0];
  if (!create) return null;

  await client.query(
    `INSERT INTO phases (phase_date, status) VALUES ($1, 'open') ON CONFLICT (phase_date) DO NOTHING`,
    [phaseDate]
  );

  result = await client.query(`SELECT * FROM phases WHERE phase_date = $1`, [phaseDate]);
  return result.rows[0];
}

/* =========================================================
   USERS
   ========================================================= */

async function ensureUser(client, telegramUser) {
  await client.query(
    `INSERT INTO users (telegram_id, username, first_name, last_name, language_code, is_premium, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,NOW())
     ON CONFLICT (telegram_id) DO UPDATE SET
       username = EXCLUDED.username,
       first_name = EXCLUDED.first_name,
       last_name = EXCLUDED.last_name,
       language_code = EXCLUDED.language_code,
       is_premium = EXCLUDED.is_premium,
       updated_at = NOW()`,
    [
      telegramUser.id,
      telegramUser.username || null,
      telegramUser.first_name || null,
      telegramUser.last_name || null,
      telegramUser.language_code || null,
      Boolean(telegramUser.is_premium)
    ]
  );
}

/* =========================================================
   WINNER TIERS — exact boundaries from specification
   Lower inclusive, upper exclusive
   ========================================================= */

function getWinnerCountFromUsd(poolUsd) {
  const usd = Number(poolUsd);
  if (!Number.isFinite(usd) || usd < 100) return 0;

  if (usd < 300) return 10;       // $100 – $300
  if (usd < 600) return 20;       // $300 – $600
  if (usd < 1200) return 30;      // $600 – $1,200
  if (usd < 2000) return 40;      // $1,200 – $2,000
  if (usd < 4000) return 50;      // $2,000 – $4,000
  if (usd < 8000) return 80;      // $4,000 – $8,000
  if (usd < 12000) return 100;    // $8,000 – $12,000
  if (usd < 15000) return 120;    // $12,000 – $15,000
  if (usd < 25000) return 185;    // $15,000 – $25,000
  if (usd < 35000) return 250;    // $25,000 – $35,000
  if (usd < 50000) return 350;    // $35,000 – $50,000
  if (usd < 70000) return 550;    // $50,000 – $70,000
  if (usd < 130000) return 1000;  // $70,000 – $130,000
  if (usd < 170000) return 1300;  // $130,000 – $170,000
  if (usd < 250000) return 2000;  // $170,000 – $250,000
  if (usd < 400000) return 3000;  // $250,000 – $400,000
  if (usd < 650000) return 50000; // $400,000 – $650,000  ← exact 50,000
  if (usd < 1000000) return 10000;
  if (usd < 2000000) return 30000;
  if (usd < 4000000) return 50000;
  if (usd < 10000000) return 100000;
  return 100000;
}

/* =========================================================
   REFERRAL
   ========================================================= */

function makeReferralCode(userId, phaseDate) {
  const cleanDate = String(phaseDate).replaceAll('-', '');
  const random = crypto.randomBytes(4).toString('hex');
  return `ref_${userId}_${cleanDate}_${random}`;
}

async function getOrCreateReferralLink(client, userId, phase) {
  const existing = await client.query(
    `SELECT * FROM referral_links WHERE referrer_id = $1 AND phase_id = $2`,
    [userId, phase.id]
  );
  if (existing.rows.length) return existing.rows[0];

  const code = makeReferralCode(userId, phase.phase_date);
  const result = await client.query(
    `INSERT INTO referral_links (referrer_id, phase_id, code)
     VALUES ($1,$2,$3)
     ON CONFLICT (referrer_id, phase_id) DO UPDATE SET code = referral_links.code
     RETURNING *`,
    [userId, phase.id, code]
  );
  return result.rows[0];
}

/* =========================================================
   INVOICE (Telegram Stars)
   ========================================================= */
/* =========================================================
   INVOICE (Telegram Stars)
========================================================= */

async function createEntryInvoice(userId, phaseId) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `pz_entry:${phaseId}:${userId}:${nonce}`;

  const result = await telegramApi('createInvoiceLink', {
    title: 'Project Z Entry',
    description: 'Daily Project Z entry',
    payload,
    currency: 'XTR',
    prices: [
      {
        label: 'Project Z Entry',
        amount: ENTRY_STARS
      }
    ]
  });

  return { link: result, payload };
}

/* =========================================================
   TON PROOF CHALLENGE API
========================================================= */
async function createEntryInvoice(userId, phaseId) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `pz_entry:${phaseId}:${userId}:${nonce}`;

  const result = await telegramApi('createInvoiceLink', {
    title: 'Project Z Entry',
    description: 'Daily Project Z entry',
    payload,
    currency: 'XTR',
    prices: [
      {
        label: 'Project Z Entry',
        amount: ENTRY_STARS
      }
    ]
  });

  return { link: result, payload };
}

/* =========================================================
   TON PROOF CHALLENGE API
========================================================= */

app.post('/api/tonconnect/nonce', async (req, res) => {
  const client = await pool.connect();

  try {
    const initData = req.body?.initData;

    if (!initData) {
      return res.status(400).json({
        ok: false,
        error: 'Missing Telegram initData'
      });
    }

    const telegramUser = verifyInitData(initData);

    if (!telegramUser?.id) {
      return res.status(401).json({
        ok: false,
        error: 'Invalid Telegram initData'
      });
    }

    await client.query('BEGIN');

    await ensureUser(client, telegramUser);

    const nonce = createTonProofNonce();
    const domain = getTonProofDomain();
    const expirationSeconds = getTonProofExpirationSeconds();

    const expiresAt = new Date(
      Date.now() + expirationSeconds * 1000
    );

    await client.query(
      `DELETE FROM ton_proof_challenges
       WHERE telegram_user_id = $1
         AND used_at IS NULL`,
      [telegramUser.id]
    );

    await client.query(
      `INSERT INTO ton_proof_challenges
       (
         telegram_user_id,
         nonce,
         domain,
         expires_at
       )
       VALUES ($1, $2, $3, $4)`,
      [
        telegramUser.id,
        nonce,
        domain,
        expiresAt
      ]
    );

    await audit(
      client,
      'ton_proof_challenge_created',
      telegramUser.id,
      null,
      {
        domain,
        expiresAt: expiresAt.toISOString()
      }
    );

    await client.query('COMMIT');

    return res.json({
      ok: true,
      nonce,
      domain,
      expiresAt: expiresAt.toISOString()
    });

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(
      'TON Proof nonce error:',
      error
    );

    return res.status(500).json({
      ok: false,
      error: 'Failed to create TON Proof challenge'
    });

  } finally {
    client.release();
  }
});


/* =========================================================
   TON PROOF VERIFICATION
========================================================= */

function sha256(buffer) {
  return crypto
    .createHash('sha256')
    .update(buffer)
    .digest();
}

function buildTonProofDigest(address, proof) {
  const workchain = Buffer.alloc(4);

  workchain.writeInt32BE(
    address.workChain,
    0
  );

  const domainBytes = Buffer.from(
    proof.domain.value,
    'utf8'
  );

  if (
    proof.domain.lengthBytes !==
    domainBytes.length
  ) {
    throw new Error(
      'TON Proof domain length mismatch'
    );
  }

  const domainLength = Buffer.alloc(4);

  domainLength.writeUInt32LE(
    proof.domain.lengthBytes,
    0
  );

  const timestamp = Buffer.alloc(8);

  timestamp.writeBigUInt64LE(
    BigInt(proof.timestamp),
    0
  );

  const message = Buffer.concat([
    Buffer.from(
      'ton-proof-item-v2/',
      'utf8'
    ),
    workchain,
    Buffer.from(address.hash),
    domainLength,
    domainBytes,
    timestamp,
    Buffer.from(
      proof.payload,
      'utf8'
    )
  ]);

  const innerHash = sha256(message);

  return sha256(
    Buffer.concat([
      Buffer.from([0xff, 0xff]),
      Buffer.from(
        'ton-connect',
        'utf8'
      ),
      innerHash
    ])
  );
}


async function extractTonWalletPublicKey(stateInit) {
  try {
    const {
      WalletContractV1R1,
      WalletContractV1R2,
      WalletContractV1R3,
      WalletContractV2R1,
      WalletContractV2R2,
      WalletContractV3R1,
      WalletContractV3R2,
      WalletContractV4,
      WalletContractV5R1
    } = await import('@ton/ton');

    if (
      !stateInit?.code ||
      !stateInit?.data
    ) {
      return null;
    }

    function loadV1(slice) {
      slice.loadUint(32);
      return slice.loadBuffer(32);
    }

    function loadV2(slice) {
      slice.loadUint(32);
      return slice.loadBuffer(32);
    }

    function loadV3(slice) {
      slice.loadUint(32);
      slice.loadUint(32);
      return slice.loadBuffer(32);
    }

    function loadV4(slice) {
      slice.loadUint(32);
      slice.loadUint(32);
      return slice.loadBuffer(32);
    }

    function loadV5(slice) {
      slice.loadBoolean();
      slice.loadUint(32);
      slice.loadUint(32);
      return slice.loadBuffer(32);
    }

    const knownWallets = [
      {
        contract: WalletContractV1R1,
        load: loadV1
      },
      {
        contract: WalletContractV1R2,
        load: loadV1
      },
      {
        contract: WalletContractV1R3,
        load: loadV1
      },
      {
        contract: WalletContractV2R1,
        load: loadV2
      },
      {
        contract: WalletContractV2R2,
        load: loadV2
      },
      {
        contract: WalletContractV3R1,
        load: loadV3
      },
      {
        contract: WalletContractV3R2,
        load: loadV3
      },
      {
        contract: WalletContractV4,
        load: loadV4
      },
      {
        contract: WalletContractV5R1,
        load: loadV5
      }
    ];

    for (const wallet of knownWallets) {
      try {
        const walletInstance =
          wallet.contract.create({
            workchain: 0,
            publicKey: Buffer.alloc(32)
          });

        const knownCode =
          walletInstance.init.code;

        if (
          knownCode.equals(
            stateInit.code
          )
        ) {
          return wallet.load(
            stateInit.data.beginParse()
          );
        }

      } catch {
        // Try next wallet version.
      }
    }

    return null;

  } catch (error) {
    console.error(
      'TON public key extraction error:',
      error
    );

    return null;
  }
}


/* =========================================================
   VERIFY TON PROOF
========================================================= */

app.post(
  '/api/tonconnect/verify',
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      const initData =
        req.body?.initData;

      const proof =
        req.body?.proof;

      const addressString =
        normalizeTonAddress(
          req.body?.address
        );

      const walletStateInit =
        req.body?.walletStateInit;

      const network =
        String(
          req.body?.network ?? ''
        );

      if (!initData) {
        return res.status(400).json({
          ok: false,
          error: 'Missing Telegram initData'
        });
      }

      if (!proof) {
        return res.status(400).json({
          ok: false,
          error: 'Missing TON Proof'
        });
      }

      if (!addressString) {
        return res.status(400).json({
          ok: false,
          error: 'Missing TON wallet address'
        });
      }

      if (!walletStateInit) {
        return res.status(400).json({
          ok: false,
          error: 'Missing walletStateInit'
        });
      }

      if (network !== '-239') {
        return res.status(400).json({
          ok: false,
          error:
            'Only TON mainnet wallets are accepted'
        });
      }

      const telegramUser =
        verifyInitData(initData);

      if (!telegramUser?.id) {
        return res.status(401).json({
          ok: false,
          error: 'Invalid Telegram initData'
        });
      }

      if (
        typeof proof.timestamp !== 'number' ||
        !Number.isFinite(proof.timestamp)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            'Invalid TON Proof timestamp'
        });
      }

      if (
        !proof.domain ||
        typeof proof.domain.value !== 'string' ||
        typeof proof.domain.lengthBytes !== 'number'
      ) {
        return res.status(400).json({
          ok: false,
          error: 'Invalid TON Proof domain'
        });
      }

      if (typeof proof.payload !== 'string') {
        return res.status(400).json({
          ok: false,
          error: 'Invalid TON Proof payload'
        });
      }

      if (typeof proof.signature !== 'string') {
        return res.status(400).json({
          ok: false,
          error: 'Invalid TON Proof signature'
        });
      }

      const expectedDomain =
        getTonProofDomain();

      if (
        proof.domain.value !==
        expectedDomain
      ) {
        return res.status(401).json({
          ok: false,
          error:
            'TON Proof domain mismatch'
        });
      }

      const now =
        Math.floor(
          Date.now() / 1000
        );

      const maxAge = 15 * 60;

      if (
        Math.abs(
          now -
          proof.timestamp
        ) > maxAge
      ) {
        return res.status(401).json({
          ok: false,
          error: 'TON Proof expired'
        });
      }

      const challengeResult =
        await client.query(
          `SELECT
             id,
             telegram_user_id,
             nonce,
             domain,
             expires_at,
             used_at
           FROM ton_proof_challenges
           WHERE telegram_user_id = $1
             AND nonce = $2
             AND domain = $3
           ORDER BY id DESC
           LIMIT 1`,
          [
            telegramUser.id,
            proof.payload,
            expectedDomain
          ]
        );

      if (
        challengeResult.rowCount === 0
      ) {
        return res.status(401).json({
          ok: false,
          error:
            'Invalid or unknown TON Proof nonce'
        });
      }

      const challenge =
        challengeResult.rows[0];

      if (challenge.used_at) {
        return res.status(401).json({
          ok: false,
          error:
            'TON Proof nonce already used'
        });
      }

      if (
        new Date(
          challenge.expires_at
        ).getTime() <=
        Date.now()
      ) {
        return res.status(401).json({
          ok: false,
          error:
            'TON Proof nonce expired'
        });
      }

      const {
        Address,
        Cell,
        contractAddress,
        loadStateInit
      } = await import('@ton/ton');

      const wantedAddress =
        Address.parse(
          addressString
        );

      const stateInit =
        loadStateInit(
          Cell
            .fromBase64(
              walletStateInit
            )
            .beginParse()
        );

      const derivedAddress =
        contractAddress(
          wantedAddress.workChain,
          stateInit
        );

      if (
        !derivedAddress.equals(
          wantedAddress
        )
      ) {
        return res.status(401).json({
          ok: false,
          error:
            'walletStateInit does not match wallet address'
        });
      }

      const publicKey =
        await extractTonWalletPublicKey(
          stateInit
        );

      if (!publicKey) {
        return res.status(400).json({
          ok: false,
          error:
            'Unsupported TON wallet contract'
        });
      }

      const digest =
        buildTonProofDigest(
          wantedAddress,
          proof
        );

      const signature =
        Buffer.from(
          proof.signature,
          'base64'
        );

      if (signature.length !== 64) {
        return res.status(401).json({
          ok: false,
          error:
            'Invalid TON Proof signature'
        });
      }

      const valid =
        crypto.verify(
          null,
          digest,
          {
            key: Buffer.concat([
              Buffer.from(
                '302a300506032b6570032100',
                'hex'
              ),
              Buffer.from(publicKey)
            ]),
            format: 'der',
            type: 'spki'
          },
          signature
        );

      if (!valid) {
        return res.status(401).json({
          ok: false,
          error:
            'TON Proof signature verification failed'
        });
      }

      const consumeResult =
        await client.query(
          `UPDATE ton_proof_challenges
           SET used_at = NOW()
           WHERE id = $1
             AND used_at IS NULL
             AND expires_at > NOW()
           RETURNING id`,
          [challenge.id]
        );

      if (
        consumeResult.rowCount === 0
      ) {
        return res.status(409).json({
          ok: false,
          error:
            'TON Proof challenge was already consumed'
        });
      }

      await client.query(
        `UPDATE users
         SET
           ton_wallet_address = $1,
           ton_wallet_public_key = $2,
           ton_wallet_chain = $3,
           ton_wallet_verified_at = NOW()
         WHERE telegram_user_id = $4`,
        [
          wantedAddress.toString(),
          Buffer.from(
            publicKey
          ).toString('hex'),
          Number(network),
          telegramUser.id
        ]
      );

      await audit(
        client,
        'ton_wallet_verified',
        telegramUser.id,
        null,
        {
          walletAddress:
            wantedAddress.toString(),
          network:
            Number(network)
        }
      );

      return res.json({
        ok: true,
        verified: true,
        walletAddress:
          wantedAddress.toString(),
        network:
          Number(network)
      });

    } catch (error) {
      console.error(
        'TON Proof verification error:',
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          'TON Proof verification failed'
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ROUTES
   ========================================================= */

app.get('/health', async (req, res) => {
  let databaseOk = false;
  try {
    await pool.query('SELECT 1');
    databaseOk = true;
  } catch {}

  res.json({
    ok: databaseOk,
    project: 'Project Z',
    paymentsReady,
    database: databaseOk,
    missingEnv,
    moscowDate: getMoscowDateString(),
    time: new Date().toISOString()
  });
});

app.get('/', (req, res) => {
  res.json({
    name: 'Project Z',
    status: 'running',
    paymentsReady,
    moscowDate: getMoscowDateString()
  });
});

app.get('/api/stats', async (req, res) => {
  const client = await pool.connect();
  try {
    const phase = await getCurrentPhase(client);

    const entries = await client.query(
      `SELECT COUNT(*)::int AS count
       FROM entries
       WHERE phase_id = $1`,
      [phase.id]
    );

    const participants = Number(entries.rows[0].count);

    // Prize Pool = exactly 70% of all successfully collected Stars.
    // The database continues to store the FULL amount paid.
    const poolStars = Math.floor(Number(phase.total_stars || 0) * 0.70);
    const poolUsd = poolStars * STAR_USD_RATE;
    const winnerCount = getWinnerCountFromUsd(poolUsd);

    // Public participant list only.
    // Never expose Telegram IDs or payment/private data.
    const participantResult = await client.query(
      `SELECT
         u.username,
         u.first_name,
         u.last_name,
         e.created_at,
         e.is_first_payer
       FROM entries e
       JOIN users u
         ON u.telegram_id = e.telegram_user_id
       WHERE e.phase_id = $1
       ORDER BY e.id DESC
       LIMIT 20`,
      [phase.id]
    );

    const participantList = participantResult.rows.map((row) => {
      const fullName = [row.first_name, row.last_name]
        .filter(Boolean)
        .join(' ')
        .trim();

      const displayName =
        row.username ||
        fullName ||
        'Participant';

      return {
        username: row.username || null,
        displayName,
        createdAt: row.created_at,
        isFirstPayer: Boolean(row.is_first_payer)
      };
    });

    res.json({
      phaseDate: phase.phase_date,
      status: phase.status,
      poolStars,
      poolUsd: Number(poolUsd.toFixed(4)),
      participants,
      participantList,
      winnerCount,
      entryStars: ENTRY_STARS,
      entryUsdDisplay: 2,
      paymentsEnabled: paymentsReady
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'db_error' });
  } finally {
    client.release();
  }
});

app.post('/api/user-status', async (req, res) => {
  const initData = getInitData(req);
  const user = verifyInitData(initData);
  if (!user) return res.status(401).json({ error: 'invalid_init_data' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureUser(client, user);
    const phase = await getCurrentPhase(client);

    const entry = await client.query(
      `SELECT * FROM entries WHERE telegram_user_id = $1 AND phase_id = $2`,
      [user.id, phase.id]
    );

    const conversions = await client.query(
      `SELECT COUNT(*)::int AS count FROM referral_conversions WHERE referrer_id = $1 AND phase_id = $2`,
      [user.id, phase.id]
    );

    const grant = await client.query(
      `SELECT * FROM free_entry_grants WHERE telegram_user_id = $1 AND phase_id = $2`,
      [user.id, phase.id]
    );

    const referralLink = await getOrCreateReferralLink(client, user.id, phase);
    await client.query('COMMIT');

    const referralCount = Number(conversions.rows[0].count);

    res.json({
      phaseDate: phase.phase_date,
      hasEntry: entry.rows.length > 0,
      isFree: entry.rows.length > 0 ? Boolean(entry.rows[0].is_free) : false,
      isFirstPayer: entry.rows.length > 0 ? Boolean(entry.rows[0].is_first_payer) : false,
      referralProgress: Math.min(referralCount, 2),
      qualifyingReferrals: referralCount,
      freeUnlocked: grant.rows.length > 0 || referralCount >= 2,
      referralCode: referralLink.code,
      referralLink: BOT_USERNAME
        ? `https://t.me/${BOT_USERNAME}?startapp=${encodeURIComponent(referralLink.code)}`
        : null
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'db_error' });
  } finally {
    client.release();
  }
});

app.post('/api/attach-referral', async (req, res) => {
  const initData = getInitData(req);
  const user = verifyInitData(initData);
  if (!user) return res.status(401).json({ error: 'invalid_init_data' });

  const code = String(req.body?.code || '').trim();
  if (!code.startsWith('ref_')) return res.status(400).json({ error: 'bad_referral_code' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureUser(client, user);
    const phase = await getCurrentPhase(client);

    const link = await client.query(
      `SELECT * FROM referral_links WHERE code = $1 AND phase_id = $2`,
      [code, phase.id]
    );

    if (!link.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'expired_or_invalid_referral' });
    }

    const referral = link.rows[0];
    if (Number(referral.referrer_id) === Number(user.id)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'self_referral' });
    }

    await client.query(
      `INSERT INTO referral_attachments (referred_user_id, referrer_id, phase_id, referral_link_id)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (referred_user_id, phase_id) DO NOTHING`,
      [user.id, referral.referrer_id, phase.id, referral.id]
    );

    await audit(client, 'referral_attached', user.id, phase.id, {
      referrerId: referral.referrer_id,
      code
    });

    await client.query('COMMIT');
    res.json({ ok: true, phaseDate: phase.phase_date });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'referral_attach_failed' });
  } finally {
    client.release();
  }
});

app.post('/api/create-entry-invoice', async (req, res) => {
  if (!paymentsReady) return res.status(503).json({ error: 'payments_disabled' });

  const initData = getInitData(req);
  const user = verifyInitData(initData);
  if (!user) return res.status(401).json({ error: 'invalid_init_data' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureUser(client, user);
    const phase = await getCurrentPhase(client);

    if (phase.status !== 'open') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'phase_closed' });
    }

    const existing = await client.query(
      `SELECT id FROM entries WHERE telegram_user_id = $1 AND phase_id = $2 FOR UPDATE`,
      [user.id, phase.id]
    );

    if (existing.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'already_entered' });
    }

    // If already has 2 successful referrals → free entry
    const referralCount = await client.query(
      `SELECT COUNT(*)::int AS count FROM referral_conversions WHERE referrer_id = $1 AND phase_id = $2`,
      [user.id, phase.id]
    );

    if (Number(referralCount.rows[0].count) >= 2) {
      await client.query(
        `INSERT INTO free_entry_grants (telegram_user_id, phase_id, reason)
         VALUES ($1,$2,'two_successful_referrals')
         ON CONFLICT (telegram_user_id, phase_id) DO NOTHING`,
        [user.id, phase.id]
      );
      await client.query('COMMIT');
      return res.json({ freeEntry: true, reason: 'two_successful_referrals' });
    }

    const invoice = await createEntryInvoice(user.id, phase.id);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await client.query(
      `INSERT INTO invoices (invoice_token, telegram_user_id, phase_id, stars_amount, payload, status, expires_at)
       VALUES ($1,$2,$3,$4,$5,'created',$6)`,
      [invoice.link, user.id, phase.id, ENTRY_STARS, invoice.payload, expiresAt]
    );

    await audit(client, 'invoice_created', user.id, phase.id, {
      payload: invoice.payload,
      stars: ENTRY_STARS
    });

    await client.query('COMMIT');
    res.json({
      freeEntry: false,
      invoiceLink: invoice.link,
      entryStars: ENTRY_STARS,
      entryUsdDisplay: 2
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'invoice_failed' });
  } finally {
    client.release();
  }
});

app.post('/api/claim-free-entry', async (req, res) => {
  const initData = getInitData(req);
  const user = verifyInitData(initData);
  if (!user) return res.status(401).json({ error: 'invalid_init_data' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureUser(client, user);
    const phase = await getCurrentPhase(client);

    if (phase.status !== 'open') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'phase_closed' });
    }

    const existing = await client.query(
      `SELECT * FROM entries WHERE telegram_user_id = $1 AND phase_id = $2 FOR UPDATE`,
      [user.id, phase.id]
    );

    if (existing.rows.length) {
      await client.query('COMMIT');
      return res.json({
        ok: true,
        alreadyEntered: true,
        isFree: Boolean(existing.rows[0].is_free)
      });
    }

    const conversions = await client.query(
      `SELECT COUNT(*)::int AS count FROM referral_conversions WHERE referrer_id = $1 AND phase_id = $2`,
      [user.id, phase.id]
    );

    if (Number(conversions.rows[0].count) < 2) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'two_successful_referrals_required' });
    }

    await client.query(
      `INSERT INTO free_entry_grants (telegram_user_id, phase_id, reason)
       VALUES ($1,$2,'two_successful_referrals')
       ON CONFLICT (telegram_user_id, phase_id) DO NOTHING`,
      [user.id, phase.id]
    );

    // Free entry does NOT increase the monetary pool
    const entry = await client.query(
      `INSERT INTO entries (telegram_user_id, phase_id, payment_id, is_free, is_first_payer)
       VALUES ($1,$2,NULL,TRUE,FALSE)
       ON CONFLICT (telegram_user_id, phase_id) DO NOTHING
       RETURNING id`,
      [user.id, phase.id]
    );

    await audit(client, 'free_entry_created', user.id, phase.id, {
      entryId: entry.rows[0]?.id || null,
      reason: 'two_successful_referrals'
    });

    await client.query('COMMIT');
    res.json({ ok: true, freeEntry: true });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'free_entry_failed' });
  } finally {
    client.release();
  }
});

/* =========================================================
   TELEGRAM WEBHOOK (critical money path)
   ========================================================= */

app.post('/telegram/webhook', async (req, res) => {
  const secret = req.headers['x-telegram-bot-api-secret-token'];
  if (!WEBHOOK_SECRET || secret !== WEBHOOK_SECRET) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const update = req.body;
  if (!update) return res.sendStatus(200);

  // ---------- PRE CHECKOUT ----------
  if (update.pre_checkout_query) {
    const q = update.pre_checkout_query;
    try {
      if (!paymentsReady) {
        await telegramApi('answerPreCheckoutQuery', {
          pre_checkout_query_id: q.id,
          ok: false,
          error_message: 'Payments temporarily disabled.'
        });
        return res.sendStatus(200);
      }

      if (q.currency !== 'XTR' || Number(q.total_amount) !== ENTRY_STARS) {
        await telegramApi('answerPreCheckoutQuery', {
          pre_checkout_query_id: q.id,
          ok: false,
          error_message: 'Invalid payment amount or currency.'
        });
        return res.sendStatus(200);
      }

      const client = await pool.connect();
      try {
        const invoice = await client.query(
          `SELECT * FROM invoices
           WHERE payload = $1 AND status = 'created' AND expires_at > NOW()`,
          [q.invoice_payload]
        );

        if (!invoice.rows.length) {
          await telegramApi('answerPreCheckoutQuery', {
            pre_checkout_query_id: q.id,
            ok: false,
            error_message: 'Invoice expired or invalid.'
          });
          return res.sendStatus(200);
        }

        const inv = invoice.rows[0];
        if (
          Number(inv.stars_amount) !== Number(q.total_amount) ||
          Number(inv.telegram_user_id) !== Number(q.from.id)
        ) {
          await telegramApi('answerPreCheckoutQuery', {
            pre_checkout_query_id: q.id,
            ok: false,
            error_message: 'Invoice validation failed.'
          });
          return res.sendStatus(200);
        }

        await telegramApi('answerPreCheckoutQuery', {
          pre_checkout_query_id: q.id,
          ok: true
        });
        return res.sendStatus(200);
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('pre_checkout error:', error);
      try {
        await telegramApi('answerPreCheckoutQuery', {
          pre_checkout_query_id: q.id,
          ok: false,
          error_message: 'Temporary payment error.'
        });
      } catch {}
      return res.sendStatus(200);
    }
  }

  // ---------- SUCCESSFUL PAYMENT ----------
  if (update.message?.successful_payment) {
    const payment = update.message.successful_payment;
    const from = update.message.from;

    if (!paymentsReady) return res.sendStatus(200);
    if (payment.currency !== 'XTR' || Number(payment.total_amount) !== ENTRY_STARS) {
      return res.sendStatus(200);
    }

    const chargeId = payment.telegram_payment_charge_id;
    const payload = payment.invoice_payload || '';

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Idempotency – critical
      const alreadyProcessed = await client.query(
        `SELECT id FROM payments WHERE telegram_payment_charge_id = $1 FOR UPDATE`,
        [chargeId]
      );
      if (alreadyProcessed.rows.length) {
        await client.query('COMMIT');
        return res.sendStatus(200);
      }

      const invoice = await client.query(
        `SELECT * FROM invoices WHERE payload = $1 FOR UPDATE`,
        [payload]
      );
      if (!invoice.rows.length) {
        await client.query('ROLLBACK');
        return res.sendStatus(200);
      }

      const inv = invoice.rows[0];
      if (
        Number(inv.telegram_user_id) !== Number(from.id) ||
        Number(inv.stars_amount) !== Number(payment.total_amount)
      ) {
        await client.query('ROLLBACK');
        return res.sendStatus(200);
      }

      if (inv.status === 'paid') {
        await client.query('COMMIT');
        return res.sendStatus(200);
      }

      const phaseResult = await client.query(
        `SELECT * FROM phases WHERE id = $1 FOR UPDATE`,
        [inv.phase_id]
      );
      if (!phaseResult.rows.length) {
        await client.query('ROLLBACK');
        return res.sendStatus(200);
      }

      const phase = phaseResult.rows[0];
      if (phase.status !== 'open') {
        await client.query(`UPDATE invoices SET status = 'paid_after_phase_close' WHERE id = $1`, [inv.id]);
        await audit(client, 'payment_received_after_phase_close', from.id, phase.id, { chargeId, payload });
        await client.query('COMMIT');
        return res.sendStatus(200);
      }

      await ensureUser(client, from);

      const paymentResult = await client.query(
        `INSERT INTO payments (
           telegram_payment_charge_id, telegram_user_id, phase_id,
           stars_amount, currency, invoice_payload, status
         ) VALUES ($1,$2,$3,$4,'XTR',$5,'succeeded')
         RETURNING id`,
        [chargeId, from.id, phase.id, payment.total_amount, payload]
      );
      const paymentId = paymentResult.rows[0].id;

      const existingEntry = await client.query(
        `SELECT * FROM entries WHERE telegram_user_id = $1 AND phase_id = $2 FOR UPDATE`,
        [from.id, phase.id]
      );

      if (existingEntry.rows.length) {
        await client.query(`UPDATE invoices SET status = 'paid_duplicate_entry' WHERE id = $1`, [inv.id]);
        await audit(client, 'duplicate_paid_entry', from.id, phase.id, { chargeId });
        await client.query('COMMIT');
        return res.sendStatus(200);
      }

      // First verified payer of the day
      const firstPayerCheck = await client.query(
        `SELECT id FROM entries WHERE phase_id = $1 AND is_first_payer = TRUE LIMIT 1`,
        [phase.id]
      );
      const isFirstPayer = firstPayerCheck.rows.length === 0;

      const entryResult = await client.query(
        `INSERT INTO entries (telegram_user_id, phase_id, payment_id, is_free, is_first_payer)
         VALUES ($1,$2,$3,FALSE,$4) RETURNING id`,
        [from.id, phase.id, paymentId, isFirstPayer]
      );
      const entryId = entryResult.rows[0].id;

      await client.query(
        `UPDATE phases SET
           total_stars = total_stars + $1,
           first_verified_entry_id = CASE WHEN $2 = TRUE THEN $3 ELSE first_verified_entry_id END,
           updated_at = NOW()
         WHERE id = $4`,
        [payment.total_amount, isFirstPayer, entryId, phase.id]
      );

      await client.query(`UPDATE invoices SET status = 'paid' WHERE id = $1`, [inv.id]);

      // Referral conversion (only real successful payment counts)
      const attachment = await client.query(
        `SELECT * FROM referral_attachments
         WHERE referred_user_id = $1 AND phase_id = $2 FOR UPDATE`,
        [from.id, phase.id]
      );

      if (attachment.rows.length) {
        const referrerId = attachment.rows[0].referrer_id;
        if (Number(referrerId) !== Number(from.id)) {
          await client.query(
            `INSERT INTO referral_conversions (referred_user_id, referrer_id, phase_id, payment_id)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (referred_user_id, phase_id) DO NOTHING`,
            [from.id, referrerId, phase.id, paymentId]
          );

          const referralCount = await client.query(
            `SELECT COUNT(*)::int AS count
             FROM referral_conversions
             WHERE referrer_id = $1 AND phase_id = $2`,
            [referrerId, phase.id]
          );

          // Exactly when reaching 2 → unlock free entry (once only)
          if (Number(referralCount.rows[0].count) >= 2) {
            await client.query(
              `INSERT INTO free_entry_grants (telegram_user_id, phase_id, reason)
               VALUES ($1,$2,'two_successful_referrals')
               ON CONFLICT (telegram_user_id, phase_id) DO NOTHING`,
              [referrerId, phase.id]
            );
          }
        }
      }

      await audit(client, 'payment_succeeded', from.id, phase.id, {
        chargeId,
        entryId,
        stars: Number(payment.total_amount),
        firstPayer: isFirstPayer
      });

      await client.query('COMMIT');
      return res.sendStatus(200);
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('successful payment error:', error);
      return res.sendStatus(200);
    } finally {
      client.release();
    }
  }

  return res.sendStatus(200);
});

/* =========================================================
   ADMIN – FINALIZE PHASE (protected)
   ========================================================= */
/* =========================================================
   ADMIN – FINALIZE PHASE (protected)
   ========================================================= */

function verifyAdmin(req) {
  if (!ADMIN_SECRET) return false;
  const supplied =
    req.headers['x-admin-secret'] ||
    req.body?.adminSecret ||
    '';

  return (
    typeof supplied === 'string' &&
    supplied.length > 0 &&
    supplied === ADMIN_SECRET
  );
}

app.post('/api/admin/finalize-phase', async (req, res) => {
  if (!verifyAdmin(req)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const requestedPhaseDate = req.body?.phaseDate || null;
  const force = Boolean(req.body?.force);

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    let phase;

    if (requestedPhaseDate) {
      const result = await client.query(
        `SELECT * FROM phases
         WHERE phase_date = $1
         FOR UPDATE`,
        [requestedPhaseDate]
      );

      if (!result.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({
          error: 'phase_not_found'
        });
      }

      phase = result.rows[0];
    } else {
      phase = await getCurrentPhase(client);
    }

    if (phase.status === 'finalized') {
      await client.query('COMMIT');

      return res.json({
        alreadyFinalized: true,
        phaseDate: phase.phase_date
      });
    }

    // Prevent early finalization unless force=true
    const todayMoscow = getMoscowDateString();
    const phaseDateOnly = toDateOnlyString(phase.phase_date);

    if (
      phaseDateOnly &&
      phaseDateOnly >= todayMoscow &&
      !force
    ) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'phase_not_yet_ended',
        message:
          'Phase can only be finalized after Moscow midnight. Use force:true only in emergency.'
      });
    }

    await client.query(
      `UPDATE phases
       SET status = 'finalizing',
           updated_at = NOW()
       WHERE id = $1`,
      [phase.id]
    );

    const totalStars = Number(phase.total_stars || 0);
    const poolUsd = totalStars * STAR_USD_RATE;
    const configuredWinnerCount =
      getWinnerCountFromUsd(poolUsd);

    // Exact 69% / 1% / 30%
    const winnerPool = Math.floor(totalStars * 0.69);
    const charity = Math.floor(totalStars * 0.01);
    const operations =
      totalStars - winnerPool - charity;

    const entriesResult = await client.query(
      `SELECT id, telegram_user_id, is_first_payer
       FROM entries
       WHERE phase_id = $1
       ORDER BY id ASC`,
      [phase.id]
    );

    const entries = entriesResult.rows;

    /*
     * No entries / no money
     */
    if (
      totalStars <= 0 ||
      entries.length === 0
    ) {
      await client.query(
        `UPDATE phases
         SET status = 'finalized',
             winner_pool_stars = 0,
             charity_stars = $1,
             operations_stars = $2,
             winner_count = 0,
             finalized_at = NOW(),
             updated_at = NOW()
         WHERE id = $3`,
        [
          charity,
          operations,
          phase.id
        ]
      );

      await client.query(
        `INSERT INTO allocations
           (phase_id, type, stars_amount)
         VALUES
           ($1, 'winners', 0),
           ($1, 'charity', $2),
           ($1, 'operations', $3)
         ON CONFLICT (phase_id, type)
         DO UPDATE SET
           stars_amount = EXCLUDED.stars_amount`,
        [
          phase.id,
          charity,
          operations
        ]
      );

      await audit(
        client,
        'phase_finalized',
        null,
        phase.id,
        {
          winners: 0,
          totalStars
        }
      );

      await client.query('COMMIT');

      return res.json({
        finalized: true,
        winners: 0
      });
    }

    /*
     * Calculate actual winner count.
     * Never select more winners than entries.
     */
    const winnerCount = Math.min(
      configuredWinnerCount,
      entries.length
    );

    if (winnerCount <= 0) {
      await client.query(
        `UPDATE phases
         SET status = 'finalized',
             winner_pool_stars = 0,
             charity_stars = $1,
             operations_stars = $2,
             winner_count = 0,
             finalized_at = NOW(),
             updated_at = NOW()
         WHERE id = $3`,
        [
          charity,
          operations,
          phase.id
        ]
      );

      await client.query('COMMIT');

      return res.json({
        finalized: true,
        winners: 0,
        poolUsd
      });
    }

    /*
     * Base prize per winner.
     *
     * Any remainder from the 69% winner pool
     * will be distributed one Star at a time
     * starting from Rank 1.
     *
     * This keeps the total winner allocation
     * exactly equal to winnerPool.
     */
    const basePrizePerWinner = Math.floor(
      winnerPool / winnerCount
    );

    const winnerRemainder =
      winnerPool -
      basePrizePerWinner * winnerCount;

    /*
     * Select winners
     */
    const selectedIds = new Set();

    // Guarantee first verified payer
    const firstPayer = entries.find(
      (e) => e.is_first_payer
    );

    if (firstPayer) {
      selectedIds.add(
        Number(firstPayer.id)
      );
    }

    // Cryptographically secure random selection
    while (
      selectedIds.size < winnerCount
    ) {
      const index = crypto.randomInt(
        0,
        entries.length
      );

      selectedIds.add(
        Number(entries[index].id)
      );
    }

    /*
     * Rank 1 = first payer if one exists.
     * Remaining winners are shuffled securely.
     */
    const selected = entries.filter((e) =>
      selectedIds.has(Number(e.id))
    );

    const first = selected.find(
      (e) => e.is_first_payer
    );

    const others = selected.filter(
      (e) => !e.is_first_payer
    );

    for (
      let i = others.length - 1;
      i > 0;
      i--
    ) {
      const j = crypto.randomInt(
        0,
        i + 1
      );

      [others[i], others[j]] = [
        others[j],
        others[i]
      ];
    }

    const ordered = first
      ? [first, ...others]
      : others;

    /*
     * Insert winners + payout ledger
     *
     * Each winner receives:
     * basePrizePerWinner
     *
     * Plus 1 extra Star for the first
     * `winnerRemainder` ranks.
     *
     * This guarantees:
     *
     * winners = exactly 69%
     * charity = exactly 1%
     * operations = exactly 30%
     */
    let rank = 1;

    for (const entry of ordered) {
      const currentRank = rank++;

      const prizeStars =
        basePrizePerWinner +
        (
          currentRank <= winnerRemainder
            ? 1
            : 0
        );

      /*
       * Insert winner.
       */
      await client.query(
        `INSERT INTO winners
           (
             phase_id,
             entry_id,
             telegram_user_id,
             rank,
             prize_stars,
             is_first_payer
           )
         VALUES
           ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (entry_id)
         DO NOTHING`,
        [
          phase.id,
          entry.id,
          entry.telegram_user_id,
          currentRank,
          prizeStars,
          Boolean(entry.is_first_payer)
        ]
      );

      /*
       * Get the winner row ID.
       *
       * This also works if the winner row
       * already existed because of a retry.
       */
      const winnerResult = await client.query(
        `SELECT id, prize_stars
         FROM winners
         WHERE phase_id = $1
           AND entry_id = $2
         LIMIT 1`,
        [
          phase.id,
          entry.id
        ]
      );

      if (!winnerResult.rows.length) {
        throw new Error(
          `winner_row_missing_for_entry_${entry.id}`
        );
      }

      const winner = winnerResult.rows[0];

      /*
       * Create payout ledger entry.
       *
       * IMPORTANT:
       * This does NOT send money yet.
       * It creates a safe pending payout
       * record for the future payout worker.
       */
      await client.query(
        `INSERT INTO payouts
           (
             phase_id,
             winner_id,
             telegram_user_id,
             amount_stars,
             status
           )
         VALUES
           ($1, $2, $3, $4, 'pending')
         ON CONFLICT (winner_id)
         DO NOTHING`,
        [
          phase.id,
          winner.id,
          entry.telegram_user_id,
          Number(winner.prize_stars)
        ]
      );
    }

    /*
     * Because the remainder was distributed
     * among winners, the actual winner amount
     * is exactly the 69% winner pool.
     */
    const actualWinnerPrize = winnerPool;

    /*
     * Exact remaining 30% after 69% winners
     * and 1% charity.
     */
    const finalOperations =
      totalStars -
      actualWinnerPrize -
      charity;

    await client.query(
      `UPDATE phases
       SET status = 'finalized',
           winner_pool_stars = $1,
           charity_stars = $2,
           operations_stars = $3,
           winner_count = $4,
           finalized_at = NOW(),
           updated_at = NOW()
       WHERE id = $5`,
      [
        actualWinnerPrize,
        charity,
        finalOperations,
        winnerCount,
        phase.id
      ]
    );

    await client.query(
      `INSERT INTO allocations
         (phase_id, type, stars_amount)
       VALUES
         ($1, 'winners', $2),
         ($1, 'charity', $3),
         ($1, 'operations', $4)
       ON CONFLICT (phase_id, type)
       DO UPDATE SET
         stars_amount = EXCLUDED.stars_amount`,
      [
        phase.id,
        actualWinnerPrize,
        charity,
        finalOperations
      ]
    );

    await audit(
      client,
      'phase_finalized',
      null,
      phase.id,
      {
        totalStars,
        poolUsd,
        configuredWinnerCount,
        actualWinnerCount: winnerCount,
        winnerPoolStars: actualWinnerPrize,
        basePrizePerWinner,
        winnerRemainder,
        charity: charity,
        operations: finalOperations,
        payoutsCreated: winnerCount
      }
    );

    await client.query('COMMIT');

    res.json({
      finalized: true,
      phaseDate: phase.phase_date,
      totalStars,
      poolUsd,
      winners: winnerCount,
      winnerPoolStars: actualWinnerPrize,
      basePrizePerWinner,
      winnerRemainder,
      charityStars: charity,
      operationsStars: finalOperations,
      payoutsCreated: winnerCount
    });

  } catch (error) {
    await client.query('ROLLBACK');

    console.error(
      'finalize error:',
      error
    );

    res.status(500).json({
      error: 'finalize_failed'
    });

  } finally {
    client.release();
  }
});
/* =========================================================
   PUBLIC WINNERS (privacy-safe)
   ========================================================= */

app.get('/api/winners', async (req, res) => {
  const phaseDate = req.query.phaseDate || getMoscowDateString();
  const client = await pool.connect();

  try {
    const phase = await client.query(`SELECT * FROM phases WHERE phase_date = $1`, [phaseDate]);
    if (!phase.rows.length) {
      return res.json({ phaseDate, finalized: false, winnerCount: 0, winners: [] });
    }

    const result = await client.query(
      `SELECT w.rank, w.prize_stars, w.is_first_payer,
              u.username, u.first_name, u.last_name
       FROM winners w
       LEFT JOIN users u ON u.telegram_id = w.telegram_user_id
       WHERE w.phase_id = $1
       ORDER BY w.rank ASC`,
      [phase.rows[0].id]
    );

    res.json({
      phaseDate,
      finalized: phase.rows[0].status === 'finalized',
      winnerCount: Number(phase.rows[0].winner_count || 0),
      winners: result.rows.map((w) => {
        const fullName = [w.first_name, w.last_name]
          .filter(Boolean)
          .join(' ')
          .trim();
        const displayName = w.username || fullName || 'Winner';
        const prizeStars = Number(w.prize_stars);

        return {
          rank: Number(w.rank),
          username: w.username || null,
          displayName,
          prizeStars,
          prizeUsd: Number((prizeStars * STAR_USD_RATE).toFixed(4)),
          isFirstPayer: Boolean(w.is_first_payer)
        };
      })
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'db_error' });
  } finally {
    client.release();
  }
});

/* =========================================================
   WEBHOOK SETUP + STARTUP
   ========================================================= */
async function autoFinalizeExpiredPhases() {
  const todayMoscow = getMoscowDateString();
  const client = await pool.connect();

  try {
    const result = await client.query(
      `SELECT phase_date
       FROM phases
       WHERE phase_date < $1
         AND status = 'open'
       ORDER BY phase_date ASC
       LIMIT 7`,
      [todayMoscow]
    );

    for (const row of result.rows) {
      const phaseDate = toDateOnlyString(row.phase_date);

      try {
        const response = await fetch(
          `${APP_URL.replace(/\/$/, '')}/api/admin/finalize-phase`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Admin-Secret': ADMIN_SECRET
            },
            body: JSON.stringify({
              phaseDate
            })
          }
        );

        const data = await response.json().catch(() => ({}));

        console.log(
          'Auto-finalize:',
          phaseDate,
          response.status,
          data
        );
      } catch (error) {
        console.error(
          'Auto-finalize request failed:',
          phaseDate,
          error
        );
      }
    }
  } catch (error) {
    console.error(
      'Auto-finalize scan failed:',
      error
    );
  } finally {
    client.release();
  }
}


/* =========================================================
   PAYOUT WORKER
   ========================================================= */

const PAYOUT_PROCESS_INTERVAL_MS = 30 * 1000;
const PAYOUT_STALE_AFTER_MINUTES = 15;

let payoutWorkerRunning = false;

async function processPendingPayouts() {
  if (payoutWorkerRunning) {
    return;
  }

  payoutWorkerRunning = true;

  const client = await pool.connect();

  try {
    /*
     * Recover payouts that were interrupted.
     *
     * If the server crashes while a payout is processing,
     * return it to pending after 15 minutes.
     */
    await client.query(
      `UPDATE payouts
       SET status = 'pending',
           processing_at = NULL,
           failure_reason = 'Recovered from interrupted processing'
       WHERE status = 'processing'
         AND processing_at IS NOT NULL
         AND processing_at < NOW() - ($1 * INTERVAL '1 minute')`,
      [PAYOUT_STALE_AFTER_MINUTES]
    );

    /*
     * Start a transaction and lock pending payouts.
     *
     * SKIP LOCKED prevents two worker executions
     * from processing the same payout simultaneously.
     */
    await client.query('BEGIN');

    const result = await client.query(
      `SELECT
         p.id,
         p.phase_id,
         p.winner_id,
         p.telegram_user_id,
         p.amount_stars,
         p.status,
         w.rank,
         w.prize_stars
       FROM payouts p
       INNER JOIN winners w
         ON w.id = p.winner_id
       WHERE p.status = 'pending'
       ORDER BY p.id ASC
       LIMIT 25
       FOR UPDATE OF p SKIP LOCKED`
    );

    if (!result.rows.length) {
      await client.query('COMMIT');
      return;
    }

    /*
     * Mark the selected payouts as processing.
     */
    const payoutIds = result.rows.map(
      (row) => row.id
    );

    await client.query(
      `UPDATE payouts
       SET status = 'processing',
           processing_at = NOW(),
           failure_reason = NULL
       WHERE id = ANY($1::bigint[])`,
      [payoutIds]
    );

    await client.query('COMMIT');

    /*
     * IMPORTANT:
     *
     * This worker does NOT falsely mark payouts as paid.
     *
     * Telegram Bot API does not provide a general
     * sendStars(user_id, amount) method for arbitrary
     * direct Stars transfers from a bot balance.
     *
     * Therefore these payouts remain "processing"
     * until a real settlement mechanism is connected.
     */
    for (const payout of result.rows) {
      console.log(
        'Payout awaiting settlement:',
        {
          payoutId: payout.id,
          phaseId: payout.phase_id,
          winnerId: payout.winner_id,
          telegramUserId: payout.telegram_user_id,
          amountStars: payout.amount_stars,
          rank: payout.rank
        }
      );
    }

  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {
      // Ignore rollback errors.
    }

    console.error(
      'Payout worker error:',
      error
    );

  } finally {
    client.release();
    payoutWorkerRunning = false;
  }
}


function startPayoutWorker() {
  /*
   * Run immediately after startup.
   */
  processPendingPayouts().catch((error) => {
    console.error(
      'Initial payout worker error:',
      error
    );
  });

  /*
   * Then run every 30 seconds.
   */
  setInterval(() => {
    processPendingPayouts().catch((error) => {
      console.error(
        'Payout worker interval error:',
        error
      );
    });
  }, PAYOUT_PROCESS_INTERVAL_MS);

  console.log(
    `Payout worker started. Interval: ${
      PAYOUT_PROCESS_INTERVAL_MS / 1000
    }s`
  );
}


async function configureTelegramWebhook() {
  if (!BOT_TOKEN || !WEBHOOK_SECRET || !APP_URL) {
    console.log(
      'Webhook setup skipped: missing Telegram configuration.'
    );
    return;
  }

  const webhookUrl =
    `${APP_URL.replace(/\/$/, '')}/telegram/webhook`;

  try {
    const result = await telegramApi(
      'setWebhook',
      {
        url: webhookUrl,
        secret_token: WEBHOOK_SECRET,
        allowed_updates: [
          'message',
          'pre_checkout_query'
        ],
        drop_pending_updates: false
      }
    );

    console.log(
      'Telegram webhook configured:',
      result
    );

  } catch (error) {
    console.error(
      'Webhook configuration failed:',
      error.message
    );
  }
}


async function start() {
  try {
    await initializeDatabase();

    /*
     * Start payout worker.
     */
    startPayoutWorker();

    /*
     * Auto-finalize expired Moscow phases
     * every 60 seconds.
     */
    setInterval(() => {
      autoFinalizeExpiredPhases().catch((error) => {
        console.error(
          'Auto-finalize interval error:',
          error
        );
      });
    }, 60 * 1000);

    /*
     * Run auto-finalization immediately
     * when the server starts.
     */
    autoFinalizeExpiredPhases().catch((error) => {
      console.error(
        'Initial auto-finalize error:',
        error
      );
    });

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

        if (missingEnv.length) {
          console.log(
            'Missing environment variables:',
            missingEnv.join(', ')
          );
        }

        if (
          PAYMENTS_ENABLED &&
          ENTRY_STARS <= 0
        ) {
          console.log(
            'WARNING: ENTRY_STARS must be a positive integer.'
          );
        }

        await configureTelegramWebhook();
      }
    );

  } catch (error) {
    console.error(
      'FATAL STARTUP ERROR:',
      error
    );

    process.exit(1);
  }
}


/* =========================================================
   ERROR HANDLERS & START
   ========================================================= */

process.on(
  'unhandledRejection',
  (error) => {
    console.error(
      'Unhandled rejection:',
      error
    );
  }
);

process.on(
  'uncaughtException',
  (error) => {
    console.error(
      'Uncaught exception:',
      error
    );
  }
);

start();
