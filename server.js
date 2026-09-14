import express from "express";
import cors from "cors";
import crypto from "crypto";
import pg from "pg";

const { Pool } = pg;

const app = express();

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "100kb" }));

const PORT = Number(process.env.PORT || 3000);

const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET;
const APP_URL = process.env.APP_URL || "https://project-z-zryq.onrender.com";

const ENTRY_STARS = Number(process.env.ENTRY_STARS || 1420);
const ENTRY_USD_DISPLAY = 2;

const MOSCOW_TIMEZONE = "Europe/Moscow";

if (!BOT_TOKEN) {
  console.error("BOT_TOKEN is missing.");
}

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
}

if (!WEBHOOK_SECRET) {
  console.error("TELEGRAM_WEBHOOK_SECRET is missing.");
}

if (!Number.isInteger(ENTRY_STARS) || ENTRY_STARS <= 0) {
  throw new Error("ENTRY_STARS must be a positive integer.");
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    })
  : null;

/* =========================================================
   WINNER TIERS
   ========================================================= */

const WINNER_TIERS = [
  [100, 300, 10],
  [300, 600, 20],
  [600, 1200, 30],
  [1200, 2000, 40],
  [2000, 4000, 50],
  [4000, 8000, 80],
  [8000, 12000, 100],
  [12000, 15000, 120],
  [15000, 25000, 185],
  [25000, 35000, 250],
  [35000, 50000, 350],
  [50000, 70000, 550],
  [70000, 130000, 1000],
  [130000, 170000, 1300],
  [170000, 250000, 2000],
  [250000, 400000, 3000],
  [400000, 650000, 50000],
  [650000, 1000000, 10000],
  [1000000, 2000000, 30000],
  [2000000, 4000000, 50000],
  [4000000, 10000000, 100000]
];

function getWinnerCount(poolUsd) {
  for (const [min, max, winners] of WINNER_TIERS) {
    if (poolUsd >= min && poolUsd < max) {
      return winners;
    }
  }

  if (poolUsd >= 10000000) {
    return 100000;
  }

  return 0;
}

/* =========================================================
   MOSCOW DAILY PHASE
   ========================================================= */

function getMoscowDateKey(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: MOSCOW_TIMEZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(date);

  const map = Object.fromEntries(parts.map(p => [p.type, p.value]));

  return `${map.year}-${map.month}-${map.day}`;
}

function getNextMoscowMidnight() {
  const now = new Date();

  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: MOSCOW_TIMEZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });

  const parts = Object.fromEntries(
    formatter
      .formatToParts(now)
      .filter(p => p.type !== "literal")
      .map(p => [p.type, p.value])
  );

  const currentDateKey =
    `${parts.year}-${parts.month}-${parts.day}`;

  const tomorrow = new Date(`${currentDateKey}T00:00:00Z`);
  tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);

  return tomorrow;
}

/* =========================================================
   TELEGRAM INIT DATA VERIFICATION
   ========================================================= */

function verifyTelegramInitData(initData) {
  if (!initData || !BOT_TOKEN) {
    return null;
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash) {
    return null;
  }

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (calculatedHash.length !== receivedHash.length) {
    return null;
  }

  if (
    !crypto.timingSafeEqual(
      Buffer.from(calculatedHash, "utf8"),
      Buffer.from(receivedHash, "utf8")
    )
  ) {
    return null;
  }

  const authDate = Number(params.get("auth_date"));

  if (!authDate) {
    return null;
  }

  const age = Math.floor(Date.now() / 1000) - authDate;

  if (age > 86400 || age < -300) {
    return null;
  }

  const userRaw = params.get("user");

  if (!userRaw) {
    return null;
  }

  try {
    return JSON.parse(userRaw);
  } catch {
    return null;
  }
}

/* =========================================================
   TELEGRAM API
   ========================================================= */

async function telegram(method, body) {
  if (!BOT_TOKEN) {
    throw new Error("BOT_TOKEN is not configured.");
  }

  const response = await fetch(
    `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    }
  );

  const data = await response.json();

  if (!data.ok) {
    throw new Error(
      data.description || `Telegram API error: ${method}`
    );
  }

  return data.result;
}

/* =========================================================
   WEBHOOK
   ========================================================= */

function safeEqual(a, b) {
  if (!a || !b) return false;

  const aa = Buffer.from(a);
  const bb = Buffer.from(b);

  if (aa.length !== bb.length) return false;

  return crypto.timingSafeEqual(aa, bb);
}

app.post("/telegram/webhook", async (req, res) => {
  try {
    if (
      WEBHOOK_SECRET &&
      !safeEqual(
        req.headers["x-telegram-bot-api-secret-token"],
        WEBHOOK_SECRET
      )
    ) {
      return res.sendStatus(403);
    }

    const update = req.body;

    if (update.pre_checkout_query) {
      const query = update.pre_checkout_query;

      await telegram("answerPreCheckoutQuery", {
        pre_checkout_query_id: query.id,
        ok: true
      });

      return res.sendStatus(200);
    }

    if (update.message?.successful_payment) {
      await processSuccessfulPayment(update.message);
      return res.sendStatus(200);
    }

    if (update.message?.text === "/start") {
      const chatId = update.message.chat.id;

      await telegram("sendMessage", {
        chat_id: chatId,
        text:
          "Project Z is online.\n\n" +
          "Open the Mini App to participate."
      });
    }

    return res.sendStatus(200);
  } catch (error) {
    console.error("Telegram webhook error:", error);
    return res.sendStatus(500);
  }
});

/* =========================================================
   PAYMENT PROCESSING
   ========================================================= */

async function processSuccessfulPayment(message) {
  if (!pool) {
    throw new Error("DATABASE_URL is required.");
  }

  const payment = message.successful_payment;

  if (payment.currency !== "XTR") {
    throw new Error("Invalid payment currency.");
  }

  if (Number(payment.total_amount) !== ENTRY_STARS) {
    throw new Error("Invalid payment amount.");
  }

  const chargeId = payment.telegram_payment_charge_id;

  const payload = JSON.parse(payment.invoice_payload);

  if (
    payload.project !== "project_z" ||
    payload.type !== "daily_entry"
  ) {
    throw new Error("Invalid invoice payload.");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const duplicate = await client.query(
      `
      SELECT id
      FROM payments
      WHERE telegram_payment_charge_id = $1
      FOR UPDATE
      `,
      [chargeId]
    );

    if (duplicate.rowCount > 0) {
      await client.query("COMMIT");
      return;
    }

    const phaseDate = getMoscowDateKey();

    const user = message.from;

    await client.query(
      `
      INSERT INTO users (
        telegram_id,
        username,
        first_name,
        last_name
      )
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (telegram_id)
      DO UPDATE SET
        username = EXCLUDED.username,
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name
      `,
      [
        String(user.id),
        user.username || null,
        user.first_name || null,
        user.last_name || null
      ]
    );

    const phase = await client.query(
      `
      INSERT INTO phases (phase_date)
      VALUES ($1)
      ON CONFLICT (phase_date)
      DO UPDATE SET phase_date = EXCLUDED.phase_date
      RETURNING id
      `,
      [phaseDate]
    );

    const phaseId = phase.rows[0].id;

    const existingEntries = await client.query(
      `
      SELECT id
      FROM entries
      WHERE phase_id = $1
      AND telegram_id = $2
      LIMIT 1
      `,
      [phaseId, String(user.id)]
    );

    if (existingEntries.rowCount > 0) {
      await client.query(
        `
        INSERT INTO payments (
          telegram_payment_charge_id,
          telegram_user_id,
          phase_id,
          stars,
          status
        )
        VALUES ($1, $2, $3, $4, 'duplicate_user')
        `,
        [
          chargeId,
          String(user.id),
          phaseId,
          ENTRY_STARS
        ]
      );

      await client.query("COMMIT");
      return;
    }

    await client.query(
      `
      INSERT INTO payments (
        telegram_payment_charge_id,
        telegram_user_id,
        phase_id,
        stars,
        status
      )
      VALUES ($1, $2, $3, $4, 'successful')
      `,
      [
        chargeId,
        String(user.id),
        phaseId,
        ENTRY_STARS
      ]
    );

    const entry = await client.query(
      `
      INSERT INTO entries (
        phase_id,
        telegram_id,
        stars,
        first_verified_payer
      )
      VALUES ($1, $2, $3, FALSE)
      RETURNING id
      `,
      [
        phaseId,
        String(user.id),
        ENTRY_STARS
      ]
    );

    const firstPayer = await client.query(
      `
      SELECT id
      FROM entries
      WHERE phase_id = $1
      AND first_verified_payer = TRUE
      LIMIT 1
      FOR UPDATE
      `,
      [phaseId]
    );

    if (firstPayer.rowCount === 0) {
      await client.query(
        `
        UPDATE entries
        SET first_verified_payer = TRUE
        WHERE id = $1
        `,
        [entry.rows[0].id]
      );
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   CREATE PAYMENT INVOICE
   ========================================================= */

app.post("/api/create-entry-invoice", async (req, res) => {
  try {
    if (!pool) {
      return res.status(503).json({
        error: "Database is not configured."
      });
    }

    const initData =
      req.headers["x-telegram-init-data"];

    const telegramUser =
      verifyTelegramInitData(initData);

    if (!telegramUser) {
      return res.status(401).json({
        error: "Invalid Telegram session."
      });
    }

    const phaseDate = getMoscowDateKey();

    const result = await pool.query(
      `
      SELECT e.id
      FROM entries e
      JOIN phases p ON p.id = e.phase_id
      WHERE p.phase_date = $1
      AND e.telegram_id = $2
      LIMIT 1
      `,
      [phaseDate, String(telegramUser.id)]
    );

    if (result.rowCount > 0) {
      return res.status(409).json({
        error: "You have already entered today's phase."
      });
    }

    const payload = JSON.stringify({
      project: "project_z",
      type: "daily_entry",
      phaseDate,
      telegramId: String(telegramUser.id)
    });

    const invoiceLink = await telegram(
      "createInvoiceLink",
      {
        title: "Project Z Daily Entry",
        description:
          "One entry for the current daily Project Z phase.",
        payload,
        currency: "XTR",
        prices: [
          {
            label: "Daily Entry",
            amount: ENTRY_STARS
          }
        ]
      }
    );

    return res.json({
      ok: true,
      invoiceLink,
      displayPriceUsd: ENTRY_USD_DISPLAY,
      stars: ENTRY_STARS
    });
  } catch (error) {
    console.error("Invoice error:", error);

    return res.status(500).json({
      error: "Unable to create payment invoice."
    });
  }
});

/* =========================================================
   STATS
   ========================================================= */

app.get("/api/stats", async (_req, res) => {
  try {
    if (!pool) {
      return res.status(503).json({
        error: "Database is not configured."
      });
    }

    const phaseDate = getMoscowDateKey();

    const result = await pool.query(
      `
      SELECT
        COALESCE(SUM(e.stars), 0) AS stars,
        COUNT(e.id) AS entries
      FROM phases p
      LEFT JOIN entries e ON e.phase_id = p.id
      WHERE p.phase_date = $1
      `,
      [phaseDate]
    );

    const stars = Number(result.rows[0].stars || 0);

    /*
      Display conversion is configurable.
      The actual Telegram Stars charge remains ENTRY_STARS.
    */

    const usdPool =
      (stars / ENTRY_STARS) * ENTRY_USD_DISPLAY;

    const winnerCount =
      getWinnerCount(usdPool);

    res.json({
      ok: true,
      mode: "LIVE",
      phaseDate,
      poolUsd: Number(usdPool.toFixed(2)),
      entries: Number(result.rows[0].entries),
      winnerCount,
      prizePoolPercent: 69,
      charityPercent: 1,
      operationsPercent: 30
    });
  } catch (error) {
    console.error("Stats error:", error);

    res.status(500).json({
      error: "Unable to load statistics."
    });
  }
});

/* =========================================================
   HEALTH
   ========================================================= */

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    project: "Project Z",
    mode: "LIVE",
    timezone: MOSCOW_TIMEZONE
  });
});

app.get("/health", async (_req, res) => {
  if (!pool) {
    return res.status(503).json({
      ok: false,
      database: false
    });
  }

  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true
    });
  } catch {
    res.status(503).json({
      ok: false,
      database: false
    });
  }
});

/* =========================================================
   DATABASE SETUP
   ========================================================= */

async function initializeDatabase() {
  if (!pool) {
    throw new Error(
      "DATABASE_URL is required before Project Z can start."
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      telegram_id TEXT PRIMARY KEY,
      username TEXT,
      first_name TEXT,
      last_name TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS phases (
      id BIGSERIAL PRIMARY KEY,
      phase_date DATE UNIQUE NOT NULL,
      finalized BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      telegram_payment_charge_id TEXT UNIQUE NOT NULL,
      telegram_user_id TEXT NOT NULL,
      phase_id BIGINT NOT NULL REFERENCES phases(id),
      stars INTEGER NOT NULL,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS entries (
      id BIGSERIAL PRIMARY KEY,
      phase_id BIGINT NOT NULL REFERENCES phases(id),
      telegram_id TEXT NOT NULL REFERENCES users(telegram_id),
      stars INTEGER NOT NULL,
      first_verified_payer BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (phase_id, telegram_id)
    );

    CREATE TABLE IF NOT EXISTS winners (
      id BIGSERIAL PRIMARY KEY,
      phase_id BIGINT NOT NULL REFERENCES phases(id),
      entry_id BIGINT NOT NULL REFERENCES entries(id),
      prize_usd NUMERIC(20, 8) NOT NULL,
      rank INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (phase_id, entry_id),
      UNIQUE (phase_id, rank)
    );

    CREATE INDEX IF NOT EXISTS idx_entries_phase
      ON entries(phase_id);

    CREATE INDEX IF NOT EXISTS idx_payments_phase
      ON payments(phase_id);

    CREATE INDEX IF NOT EXISTS idx_winners_phase
      ON winners(phase_id);
  `);

  console.log("Database initialized.");
}

/* =========================================================
   START
   ========================================================= */

async function start() {
  await initializeDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `Project Z LIVE on port ${PORT}`
    );
  });

  try {
    await telegram("setWebhook", {
      url: `${APP_URL}/telegram/webhook`,
      secret_token: WEBHOOK_SECRET
    });

    console.log("Telegram webhook configured.");
  } catch (error) {
    console.error(
      "Webhook configuration failed:",
      error.message
    );
  }
}

start().catch(error => {
  console.error("FATAL STARTUP ERROR:", error);
  process.exit(1);
});
