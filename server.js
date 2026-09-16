import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Pool } from "pg";
import crypto from "crypto";
import nacl from "tweetnacl";
import { createMysteryScheduler } from "./Mysteryscheduler.js";
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

app.set(
  "trust proxy",
  1
);


/* =========================================================
   PROJECT Z
   FINAL CLEAN PRODUCTION BUILD
========================================================= */


/* =========================================================
   ENV HELPERS
========================================================= */

function strEnv(
  name,
  fallback = ""
) {
  const value =
    process.env[
      name
    ];

  if (
    typeof value ===
      "string" &&
    value.length >
      0
  ) {
    return value;
  }

  return fallback;
}


function intEnv(
  name,
  fallback
) {
  const value =
    Number(
      process.env[
        name
      ]
    );

  if (
    Number.isInteger(
      value
    )
  ) {
    return value;
  }

  return fallback;
}


function floatEnv(
  name,
  fallback
) {
  const value =
    Number(
      process.env[
        name
      ]
    );

  if (
    Number.isFinite(
      value
    )
  ) {
    return value;
  }

  return fallback;
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
    )
      .trim()
      .toLowerCase() ===
    "true"
  );
}


/* =========================================================
   CONFIG
========================================================= */

const PORT =
  intEnv(
    "PORT",
    10000
  );


const NODE_ENV =
  strEnv(
    "NODE_ENV",
    "production"
  );


const BOT_TOKEN =
  strEnv(
    "BOT_TOKEN"
  );


const DATABASE_URL =
  strEnv(
    "DATABASE_URL"
  );


const TELEGRAM_WEBHOOK_SECRET =
  strEnv(
    "TELEGRAM_WEBHOOK_SECRET"
  );


const APP_URL =
  strEnv(
    "APP_URL",
    "https://project-z-zryq.onrender.com"
  );


const FRONTEND_ORIGIN =
  strEnv(
    "FRONTEND_ORIGIN",
    "https://g5v4jvv5hs-web.github.io"
  );


const BOT_USERNAME =
  strEnv(
    "BOT_USERNAME",
    "denddkilibot"
  ).replace(
    /^@/,
    ""
  );


const ADMIN_SECRET =
  strEnv(
    "ADMIN_SECRET"
  );
const SUPPORT_ADMIN_CHAT_ID =
  strEnv(
    "SUPPORT_ADMIN_CHAT_ID"
  );

const MOSCOW_TIME_ZONE =
  strEnv(
    "MOSCOW_TIME_ZONE",
    "Europe/Moscow"
  );


const PAYMENTS_ENABLED =
  boolEnv(
    "PAYMENTS_ENABLED",
    true
  );


const ENTRY_STARS =
  intEnv(
    "ENTRY_STARS",
    100
  );


const STAR_USD_RATE =
  floatEnv(
    "STAR_USD_RATE",
    0.013
  );


const ENTRY_USD_DISPLAY =
  floatEnv(
    "ENTRY_USD_DISPLAY",
    1.99
  );


const WINNER_SHARE =
  floatEnv(
    "WINNER_SHARE",
    0.69
  );


const CHARITY_SHARE =
  floatEnv(
    "CHARITY_SHARE",
    0.01
  );


const OPERATIONS_SHARE =
  floatEnv(
    "OPERATIONS_SHARE",
    0.30
  );


const TON_NETWORK =
  strEnv(
    "TON_NETWORK",
    "-239"
  );


const TON_PROOF_TTL_SECONDS =
  intEnv(
    "TON_PROOF_TTL_SECONDS",
    900
  );


const TREASURY_WALLET_ADDRESS =
  strEnv(
    "TREASURY_WALLET_ADDRESS",
    "UQAr2SdmjtiZmeNJiSFEslRjLv6YBn7BAaU7Dpd7KMi3Jf_q"
  );


const USDT_JETTON_MASTER =
  strEnv(
    "USDT_JETTON_MASTER",
    "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
  );


/*
  IMPORTANT:
  The treasury private key / mnemonic is deliberately
  NOT stored or used by this backend.

  Real USDT settlement is kept separate from the
  public payment backend.
*/

const AUTOMATIC_SETTLEMENT_ENABLED =
  false;
const INVOICE_TTL_SECONDS =
  intEnv(
    "INVOICE_TTL_SECONDS",
    900
  );

const INIT_DATA_MAX_AGE_SECONDS =
  intEnv(
    "INIT_DATA_MAX_AGE_SECONDS",
    86400
  );

const REFUND_MAX_ATTEMPTS =
  intEnv(
    "REFUND_MAX_ATTEMPTS",
    10
  );

const PAYMENT_REQUIRED_ENV = [
  "BOT_TOKEN",
  "DATABASE_URL",
  "TELEGRAM_WEBHOOK_SECRET",
];

const missingPaymentEnv =
  PAYMENT_REQUIRED_ENV.filter(
    (key) =>
      !process.env[key]
  );

let runtimeBotUsername =
  BOT_USERNAME;

/* =========================================================
   GENERIC HELPERS
========================================================= */

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


const TON_PROOF_DOMAIN =
  strEnv(
    "TON_PROOF_DOMAIN",
    safeHost(
      FRONTEND_ORIGIN
    ) ||
      "g5v4jvv5hs-web.github.io"
  );


const REQUIRED_ENV = [
  "BOT_TOKEN",
  "DATABASE_URL",
  "TELEGRAM_WEBHOOK_SECRET",
  "APP_URL",
  "ADMIN_SECRET",
];


const missingEnv =
  REQUIRED_ENV.filter(
    (
      key
    ) =>
      !process.env[
        key
      ]
  );


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

  if (
    aa.length !==
    bb.length
  ) {
    return false;
  }

  return crypto
    .timingSafeEqual(
      aa,
      bb
    );
}


function clampInt(
  value,
  min,
  max
) {
  const n =
    Number(
      value
    );

  if (
    !Number.isFinite(
      n
    )
  ) {
    return min;
  }

  return Math.max(
    min,
    Math.min(
      max,
      Math.trunc(
        n
      )
    )
  );
}


function normalizeTonAddress(
  value
) {
  return Address
    .parse(
      String(
        value
      )
    )
    .toString({
      bounceable:
        false,

      testOnly:
        false,
    });
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


  const values =
    Object.fromEntries(
      parts
        .filter(
          (
            part
          ) =>
            part.type !==
            "literal"
        )
        .map(
          (
            part
          ) => [
            part.type,
            part.value,
          ]
        )
    );


  return (
    `${values.year}-` +
    `${values.month}-` +
    `${values.day}`
  );
}


function toDateOnlyString(
  value
) {
  if (
    !value
  ) {
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


    const values =
      Object.fromEntries(
        parts
          .filter(
            (
              part
            ) =>
              part.type !==
              "literal"
          )
          .map(
            (
              part
            ) => [
              part.type,
              part.value,
            ]
          )
      );


    return (
      `${values.year}-` +
      `${values.month}-` +
      `${values.day}`
    );
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


  if (
    name
  ) {
    return name.slice(
      0,
      120
    );
  }


  if (
    user
      ?.username
  ) {
    return (
      `@${String(
        user.username
      ).slice(
        0,
        120
      )}`
    );
  }


  return (
    `User ${
      user
        ?.id ??
      ""
    }`
  ).trim();
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
   STARTUP VALIDATION
========================================================= */

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
  !Number.isFinite(
    STAR_USD_RATE
  ) ||
  STAR_USD_RATE <=
    0
) {
  throw new Error(
    "STAR_USD_RATE must be greater than zero"
  );
}


if (
  !DATABASE_URL
) {
  console.warn(
    "DATABASE_URL is currently missing."
  );
}


if (
  !BOT_TOKEN
) {
  console.warn(
    "BOT_TOKEN is currently missing."
  );
}


/* =========================================================
   DATABASE CONNECTION
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
const mysteryScheduler =
  createMysteryScheduler({
    pool,
    telegramApi,
    timeZone:
      "Europe/Moscow",
  });

pool.on(
  "error",
  (
    error
  ) => {
    console.error(
      "Unexpected PostgreSQL pool error:",
      error
    );
  }
);


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
      if (
        !origin
      ) {
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

    credentials:
      false,
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
const supportLimiter =
  rateLimit({
    windowMs:
      60_000,

    max:
      8,

    standardHeaders:
      true,

    legacyHeaders:
      false,
  });


/* =========================================================
   PROJECT Z BUSINESS RULES
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
   TELEGRAM MINI APP INIT DATA VERIFICATION
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
        INIT_DATA_MAX_AGE_SECONDS
    ) {
      return null;
    }


    const rawUser =
      params.get(
        "user"
      );


    if (
      !rawUser
    ) {
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


  if (
    !verified
  ) {
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
async function createSupportTicket(
  telegramUser,
  messageText
) {
  if (
    !SUPPORT_ADMIN_CHAT_ID
  ) {
    throw new Error(
      "SUPPORT_ADMIN_CHAT_ID is not configured"
    );
  }

  const telegramUserId =
    Number(
      telegramUser?.id
    );

  if (
    !Number.isSafeInteger(
      telegramUserId
    )
  ) {
    throw new Error(
      "Invalid Telegram user"
    );
  }

  const cleanText =
    String(
      messageText || ""
    )
      .trim()
      .slice(
        0,
        2000
      );

  if (
    cleanText.length <
    3
  ) {
    throw new Error(
      "Support message is too short"
    );
  }

  const inserted =
    await pool.query(
      `
        INSERT INTO support_messages (
          telegram_user_id,
          message_text,
          status
        )
        VALUES (
          $1,
          $2,
          'open'
        )
        RETURNING id
      `,
      [
        telegramUserId,
        cleanText,
      ]
    );

  const ticketId =
    inserted.rows[0].id;

  const adminMessage =
    await telegramApi(
      "sendMessage",
      {
        chat_id:
          SUPPORT_ADMIN_CHAT_ID,

        text:
          `🆘 PROJECT Z SUPPORT\n\n` +
          `Ticket #${ticketId}\n\n` +
          `${cleanText}\n\n` +
          `Reply directly to this message to answer the user through the Project Z bot.`,
      }
    );

  await pool.query(
    `
      UPDATE support_messages
      SET
        admin_notification_message_id = $1
      WHERE id = $2
    `,
    [
      adminMessage.message_id,
      ticketId,
    ]
  );

  return {
    ticketId,
  };
}
async function handleSupportTelegramMessage(
  message
) {
  const chatId =
    String(
      message?.chat?.id ?? ""
    );

  const text =
    String(
      message?.text || ""
    ).trim();

  if (
    !chatId
  ) {
    return false;
  }

  const command =
    text
      .split(/\s+/)[0]
      ?.split("@")[0];
if (
  command ===
  "/start"
) {
  await mysteryScheduler.subscribe(
  message
);
  await telegramApi(
    "sendMessage",
    {
      chat_id:
        message.chat.id,
      text:
        "Z is online👁️",
    }
  );

  return true;
}
  if (
    command ===
    "/myid"
  ) {
    await telegramApi(
      "sendMessage",
      {
        chat_id:
          message.chat.id,

        text:
          `Your Telegram chat ID: ${message.chat.id}`,
      }
    );

    return true;
  }

  if (
    !SUPPORT_ADMIN_CHAT_ID ||
    chatId !==
      String(
        SUPPORT_ADMIN_CHAT_ID
      )
  ) {
    return false;
  }

  if (
    !text ||
    !message
      ?.reply_to_message
      ?.message_id
  ) {
    return false;
  }

  const notificationMessageId =
    Number(
      message
        .reply_to_message
        .message_id
    );

  const ticketResult =
    await pool.query(
      `
        SELECT
          id,
          telegram_user_id
        FROM support_messages
        WHERE
          admin_notification_message_id = $1
        ORDER BY id DESC
        LIMIT 1
      `,
      [
        notificationMessageId,
      ]
    );

  if (
    ticketResult.rows.length ===
    0
  ) {
    return false;
  }

  const ticket =
    ticketResult.rows[0];

  const replyText =
    text.slice(
      0,
      2000
    );

  const sentMessage =
    await telegramApi(
      "sendMessage",
      {
        chat_id:
          Number(
            ticket.telegram_user_id
          ),

        text:
          `PROJECT Z SUPPORT\n` +
          `Ticket #${ticket.id}\n\n` +
          replyText,
      }
    );

  await pool.query(
    `
      UPDATE support_messages
      SET
        bot_reply_message_id = $1,
        admin_reply_text = $2,
        status = 'answered',
        replied_at = NOW()
      WHERE id = $3
    `,
    [
      sentMessage.message_id,
      replyText,
      ticket.id,
    ]
  );

  return true;
}
async function telegramApi(
  method,
  body = {}
) {
  if (
    !BOT_TOKEN
  ) {
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


/* =========================================================
   TELEGRAM BOT IDENTITY
========================================================= */

async function resolveBotIdentity() {
  if (
    !BOT_TOKEN
  ) {
    return null;
  }

  try {
    const me =
      await telegramApi(
        "getMe"
      );

    if (
      me?.username
    ) {
      runtimeBotUsername =
        String(
          me.username
        ).replace(
          /^@/,
          ""
        );
    }

    console.log(
      `Telegram bot identity: @${
        runtimeBotUsername ||
        "unknown"
      }`
    );

    return me;
  } catch (
    error
  ) {
    console.error(
      "Telegram getMe failed:",
      error.message
    );

    return null;
  }
}


/* =========================================================
   TELEGRAM WEBHOOK
========================================================= */

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

    await client.query(
      `
        CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY,

          telegram_id BIGINT
            NOT NULL
            UNIQUE,

          username TEXT,

          first_name TEXT,

          last_name TEXT,

          language_code TEXT,

          is_premium BOOLEAN
            DEFAULT FALSE,

          display_name TEXT,

          ton_wallet_address TEXT,

          ton_wallet_public_key TEXT,

          ton_wallet_chain INTEGER,

          ton_wallet_verified_at
            TIMESTAMPTZ,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          updated_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW()
        );


        CREATE TABLE IF NOT EXISTS phases (
          id BIGSERIAL PRIMARY KEY,

          phase_date DATE
            NOT NULL
            UNIQUE,

          status TEXT
            NOT NULL
            DEFAULT 'open',

          total_stars NUMERIC
            NOT NULL
            DEFAULT 0,

          winner_pool_stars NUMERIC
            NOT NULL
            DEFAULT 0,

          charity_stars NUMERIC
            NOT NULL
            DEFAULT 0,

          operations_stars NUMERIC
            NOT NULL
            DEFAULT 0,

          winner_count INTEGER
            NOT NULL
            DEFAULT 0,

          first_verified_entry_id
            BIGINT,

          entry_count BIGINT
            NOT NULL
            DEFAULT 0,

          paid_entry_count BIGINT
            NOT NULL
            DEFAULT 0,

          free_entry_count BIGINT
            NOT NULL
            DEFAULT 0,

          gross_usd
            NUMERIC(20,6)
            NOT NULL
            DEFAULT 0,

          winner_pool_usd
            NUMERIC(20,6)
            NOT NULL
            DEFAULT 0,

          charity_usd
            NUMERIC(20,6)
            NOT NULL
            DEFAULT 0,

          operations_usd
            NUMERIC(20,6)
            NOT NULL
            DEFAULT 0,

          draw_commit_hash TEXT,

          draw_seed_secret TEXT,

          draw_reveal TEXT,

          finalized_at
            TIMESTAMPTZ,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          updated_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW()
        );


        CREATE TABLE IF NOT EXISTS invoices (
          id BIGSERIAL PRIMARY KEY,

          invoice_token TEXT
            NOT NULL
            UNIQUE,

          telegram_user_id BIGINT
            NOT NULL,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          stars_amount NUMERIC
            NOT NULL,

          currency TEXT
            NOT NULL
            DEFAULT 'XTR',

          payload TEXT
            NOT NULL
            UNIQUE,

          status TEXT
            NOT NULL
            DEFAULT 'created',

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          expires_at
            TIMESTAMPTZ
            NOT NULL,

          paid_at
            TIMESTAMPTZ
        );


        CREATE TABLE IF NOT EXISTS payments (
          id BIGSERIAL PRIMARY KEY,

          telegram_payment_charge_id
            TEXT
            NOT NULL
            UNIQUE,

          provider_payment_charge_id
            TEXT,

          telegram_user_id BIGINT
            NOT NULL,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          stars_amount NUMERIC
            NOT NULL,

          currency TEXT
            NOT NULL,

          invoice_payload TEXT
            NOT NULL,

          status TEXT
            NOT NULL,

          raw_payment JSONB,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          refund_attempts INTEGER
            NOT NULL
            DEFAULT 0,

          refund_last_error TEXT,

          last_refund_attempt_at
            TIMESTAMPTZ,

          refunded_at
            TIMESTAMPTZ
        );


        CREATE TABLE IF NOT EXISTS payment_reconciliations (
          id BIGSERIAL PRIMARY KEY,

          telegram_payment_charge_id
            TEXT
            UNIQUE,

          telegram_user_id
            BIGINT,

          invoice_payload
            TEXT,

          currency
            TEXT,

          stars_amount
            NUMERIC,

          reason TEXT
            NOT NULL,

          status TEXT
            NOT NULL
            DEFAULT 'needs_review',

          raw_payload
            JSONB,

          attempts INTEGER
            NOT NULL
            DEFAULT 0,

          last_error
            TEXT,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          updated_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW()
        );


        CREATE TABLE IF NOT EXISTS entries (
          id BIGSERIAL PRIMARY KEY,

          telegram_user_id BIGINT
            NOT NULL,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id),

          payment_id BIGINT
            REFERENCES payments(id),

          source TEXT
            NOT NULL
            DEFAULT 'paid',

          is_free BOOLEAN
            NOT NULL
            DEFAULT FALSE,

          is_first_payer BOOLEAN
            NOT NULL
            DEFAULT FALSE,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          UNIQUE (
            telegram_user_id,
            phase_id
          )
        );


        CREATE TABLE IF NOT EXISTS referral_links (
          id BIGSERIAL PRIMARY KEY,

          referrer_id BIGINT
            NOT NULL,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          code TEXT
            NOT NULL
            UNIQUE,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          UNIQUE (
            referrer_id,
            phase_id
          )
        );


        CREATE TABLE IF NOT EXISTS referral_attachments (
          id BIGSERIAL PRIMARY KEY,

          referred_user_id
            BIGINT
            NOT NULL,

          referrer_id BIGINT
            NOT NULL,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          referral_link_id
            BIGINT
            REFERENCES referral_links(id),

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          UNIQUE (
            referred_user_id,
            phase_id
          )
        );


        CREATE TABLE IF NOT EXISTS referral_conversions (
          id BIGSERIAL PRIMARY KEY,

          referred_user_id
            BIGINT
            NOT NULL,

          referrer_id BIGINT
            NOT NULL,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          payment_id BIGINT
            NOT NULL
            REFERENCES payments(id),

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          UNIQUE (
            referred_user_id,
            phase_id
          )
        );


        CREATE TABLE IF NOT EXISTS free_entry_grants (
          id BIGSERIAL PRIMARY KEY,

          telegram_user_id
            BIGINT
            NOT NULL,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          reason TEXT
            NOT NULL,

          required_referrals
            INTEGER
            NOT NULL
            DEFAULT 2,

          status TEXT
            NOT NULL
            DEFAULT 'available',

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          claimed_at
            TIMESTAMPTZ,

          UNIQUE (
            telegram_user_id,
            phase_id
          )
        );


        CREATE TABLE IF NOT EXISTS winners (
          id BIGSERIAL PRIMARY KEY,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          entry_id BIGINT
            NOT NULL
            UNIQUE
            REFERENCES entries(id),

          telegram_user_id
            BIGINT
            NOT NULL,

          rank INTEGER
            NOT NULL,

          prize_stars NUMERIC
            NOT NULL,

          is_first_payer BOOLEAN
            NOT NULL
            DEFAULT FALSE,

          prize_usd
            NUMERIC(20,6)
            NOT NULL
            DEFAULT 0,

          prize_stars_equiv
            NUMERIC(20,6)
            NOT NULL
            DEFAULT 0,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          UNIQUE (
            phase_id,
            rank
          )
        );


        CREATE TABLE IF NOT EXISTS payouts (
          id BIGSERIAL PRIMARY KEY,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          winner_id BIGINT
            NOT NULL
            UNIQUE
            REFERENCES winners(id)
            ON DELETE CASCADE,

          telegram_user_id
            BIGINT
            NOT NULL,

          amount_stars INTEGER
            NOT NULL
            CHECK (
              amount_stars > 0
            ),

          status TEXT
            NOT NULL
            DEFAULT 'pending',

          telegram_transaction_id
            TEXT,

          failure_reason
            TEXT,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          processing_at
            TIMESTAMPTZ,

          paid_at
            TIMESTAMPTZ,

          ton_wallet_address
            TEXT,

          ton_tx_hash
            TEXT,

          prize_usd
            NUMERIC(20,6),

          usdt_amount_micro
            BIGINT,

          settlement_asset
            TEXT
            NOT NULL
            DEFAULT 'USDT_TON',

          settlement_reference
            TEXT
        );


        CREATE TABLE IF NOT EXISTS ton_proof_challenges (
          id BIGSERIAL PRIMARY KEY,

          telegram_user_id
            BIGINT
            NOT NULL,

          nonce TEXT
            NOT NULL
            UNIQUE,

          domain TEXT
            NOT NULL,

          expires_at
            TIMESTAMPTZ
            NOT NULL,

          used_at
            TIMESTAMPTZ,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW()
        );


        CREATE TABLE IF NOT EXISTS allocations (
          id BIGSERIAL PRIMARY KEY,

          phase_id BIGINT
            NOT NULL
            REFERENCES phases(id)
            ON DELETE CASCADE,

          type TEXT
            NOT NULL,

          stars_amount NUMERIC
            NOT NULL,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          UNIQUE (
            phase_id,
            type
          )
        );
  
CREATE TABLE IF NOT EXISTS support_messages (
  id BIGSERIAL PRIMARY KEY,

  telegram_user_id
    BIGINT
    NOT NULL,

  message_text
    TEXT
    NOT NULL,

  admin_notification_message_id
    BIGINT
    UNIQUE,

  bot_reply_message_id
    BIGINT,

  admin_reply_text
    TEXT,

  status
    TEXT
    NOT NULL
    DEFAULT 'open',

  created_at
    TIMESTAMPTZ
    NOT NULL
    DEFAULT NOW(),

  replied_at
    TIMESTAMPTZ
);

        CREATE TABLE IF NOT EXISTS audit_logs (
          id BIGSERIAL PRIMARY KEY,

          event_type TEXT
            NOT NULL,

          actor_telegram_id
            BIGINT,

          phase_id BIGINT
            REFERENCES phases(id),

          payload JSONB,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW()
        );
      `
    );

    /* -----------------------------------------------------
       NON-DESTRUCTIVE DATABASE UPGRADES
    ----------------------------------------------------- */

    const alters = [
      `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS display_name TEXT`,

      `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS ton_wallet_address TEXT`,

      `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS ton_wallet_public_key TEXT`,

      `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS ton_wallet_chain INTEGER`,

      `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS ton_wallet_verified_at TIMESTAMPTZ`,

      `ALTER TABLE users
       ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,

      `ALTER TABLE invoices
       ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'XTR'`,

      `ALTER TABLE invoices
       ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ`,

      `ALTER TABLE payments
       ADD COLUMN IF NOT EXISTS provider_payment_charge_id TEXT`,

      `ALTER TABLE payments
       ADD COLUMN IF NOT EXISTS raw_payment JSONB`,

      `ALTER TABLE payments
       ADD COLUMN IF NOT EXISTS refund_attempts INTEGER NOT NULL DEFAULT 0`,

      `ALTER TABLE payments
       ADD COLUMN IF NOT EXISTS refund_last_error TEXT`,

      `ALTER TABLE payments
       ADD COLUMN IF NOT EXISTS last_refund_attempt_at TIMESTAMPTZ`,

      `ALTER TABLE payments
       ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ`,

      `ALTER TABLE payment_reconciliations
       ADD COLUMN IF NOT EXISTS invoice_payload TEXT`,

      `ALTER TABLE payment_reconciliations
       ADD COLUMN IF NOT EXISTS currency TEXT`,

      `ALTER TABLE payment_reconciliations
       ADD COLUMN IF NOT EXISTS stars_amount NUMERIC`,

      `ALTER TABLE payment_reconciliations
       ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0`,

      `ALTER TABLE payment_reconciliations
       ADD COLUMN IF NOT EXISTS last_error TEXT`,

      `ALTER TABLE payment_reconciliations
       ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,

      `ALTER TABLE entries
       ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'paid'`,

      `ALTER TABLE entries
       ADD COLUMN IF NOT EXISTS is_free BOOLEAN NOT NULL DEFAULT FALSE`,

      `ALTER TABLE entries
       ADD COLUMN IF NOT EXISTS is_first_payer BOOLEAN NOT NULL DEFAULT FALSE`,

      `ALTER TABLE free_entry_grants
       ADD COLUMN IF NOT EXISTS required_referrals INTEGER NOT NULL DEFAULT 2`,

      `ALTER TABLE free_entry_grants
       ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'available'`,

      `ALTER TABLE free_entry_grants
       ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS entry_count BIGINT NOT NULL DEFAULT 0`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS paid_entry_count BIGINT NOT NULL DEFAULT 0`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS free_entry_count BIGINT NOT NULL DEFAULT 0`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS gross_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS winner_pool_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS charity_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS operations_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS draw_commit_hash TEXT`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS draw_seed_secret TEXT`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS draw_reveal TEXT`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ`,

      `ALTER TABLE phases
       ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`,

      `ALTER TABLE winners
       ADD COLUMN IF NOT EXISTS prize_usd NUMERIC(20,6) NOT NULL DEFAULT 0`,

      `ALTER TABLE winners
       ADD COLUMN IF NOT EXISTS prize_stars_equiv NUMERIC(20,6) NOT NULL DEFAULT 0`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS prize_usd NUMERIC(20,6)`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS usdt_amount_micro BIGINT`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS settlement_asset TEXT NOT NULL DEFAULT 'USDT_TON'`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS ton_wallet_address TEXT`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS ton_tx_hash TEXT`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS settlement_reference TEXT`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS failure_reason TEXT`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS processing_at TIMESTAMPTZ`,

      `ALTER TABLE payouts
       ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ`,
    ];

    for (
      const sql of
      alters
    ) {
      await client.query(
        sql
      );
    }

    /* -----------------------------------------------------
       INDEXES + DATABASE-LEVEL SAFETY
    ----------------------------------------------------- */

    await client.query(
      `
        CREATE INDEX IF NOT EXISTS
          idx_entries_phase
          ON entries(phase_id);

        CREATE INDEX IF NOT EXISTS
          idx_entries_user
          ON entries(telegram_user_id);

        CREATE INDEX IF NOT EXISTS
          idx_payments_phase
          ON payments(phase_id);

        CREATE INDEX IF NOT EXISTS
          idx_payments_user_phase
          ON payments(
            telegram_user_id,
            phase_id
          );

        CREATE INDEX IF NOT EXISTS
          idx_invoices_user_phase
          ON invoices(
            telegram_user_id,
            phase_id
          );

        CREATE INDEX IF NOT EXISTS
          idx_payouts_status
          ON payouts(status);

        CREATE INDEX IF NOT EXISTS
          idx_refconv_referrer_phase
          ON referral_conversions(
            referrer_id,
            phase_id
          );

        CREATE INDEX IF NOT EXISTS
          idx_ton_challenge_user
          ON ton_proof_challenges(
            telegram_user_id,
            expires_at
          );
          CREATE INDEX IF NOT EXISTS
  idx_support_user
  ON support_messages(
    telegram_user_id
  );

CREATE INDEX IF NOT EXISTS
  idx_support_status
  ON support_messages(
    status
  );

        CREATE UNIQUE INDEX IF NOT EXISTS
          idx_entries_unique_payment
          ON entries(payment_id)
          WHERE payment_id IS NOT NULL;

        CREATE UNIQUE INDEX IF NOT EXISTS
          idx_entries_one_first_payer_per_phase
          ON entries(phase_id)
          WHERE is_first_payer = TRUE;
      `
    );

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
/* =========================================================
   USERS / AUDIT
========================================================= */

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
      String(
        eventType
      ).slice(
        0,
        120
      ),

      actorTelegramId ??
        null,

      phaseId ??
        null,

      safeJson(
        payload
      ),
    ]
  );
}

async function upsertUser(
  client,
  telegramUser
) {
  if (
    !telegramUser ||
    !Number.isSafeInteger(
      Number(
        telegramUser.id
      )
    )
  ) {
    throw new Error(
      "Invalid Telegram user"
    );
  }

  const telegramId =
    Number(
      telegramUser.id
    );

  const username =
    telegramUser.username
      ? String(
          telegramUser.username
        ).slice(
          0,
          120
        )
      : null;

  const firstName =
    telegramUser.first_name
      ? String(
          telegramUser.first_name
        ).slice(
          0,
          120
        )
      : null;

  const lastName =
    telegramUser.last_name
      ? String(
          telegramUser.last_name
        ).slice(
          0,
          120
        )
      : null;

  const languageCode =
    telegramUser.language_code
      ? String(
          telegramUser.language_code
        ).slice(
          0,
          32
        )
      : null;

  const isPremium =
    Boolean(
      telegramUser.is_premium
    );

  const displayName =
    displayNameFromTelegramUser(
      telegramUser
    );

  const result =
    await client.query(
      `
        INSERT INTO users (
          telegram_id,
          username,
          first_name,
          last_name,
          language_code,
          is_premium,
          display_name,
          updated_at
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
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

          display_name =
            EXCLUDED.display_name,

          updated_at =
            NOW()

        RETURNING *
      `,
      [
        telegramId,
        username,
        firstName,
        lastName,
        languageCode,
        isPremium,
        displayName,
      ]
    );

  return result
    .rows[0];
}

/* =========================================================
   DAILY PHASE
========================================================= */

function createDrawMaterial(
  phaseDate
) {
  const seed =
    randomToken(
      32
    );

  const commit =
    sha256Hex(
      `project-z|${phaseDate}|${seed}`
    );

  return {
    seed,
    commit,
  };
}

async function getOrCreatePhase(
  client,
  phaseDate =
    getMoscowDateString()
) {
  const cleanDate =
    String(
      phaseDate
    ).slice(
      0,
      10
    );

  let existing =
    (
      await client.query(
        `
          SELECT *

          FROM phases

          WHERE phase_date = $1

          LIMIT 1
        `,
        [
          cleanDate,
        ]
      )
    ).rows[0];

  if (
    existing
  ) {
    return existing;
  }

  const draw =
    createDrawMaterial(
      cleanDate
    );

  const insert =
    await client.query(
      `
        INSERT INTO phases (
          phase_date,
          status,
          draw_commit_hash,
          draw_seed_secret,
          created_at,
          updated_at
        )
        VALUES (
          $1,
          'open',
          $2,
          $3,
          NOW(),
          NOW()
        )

        ON CONFLICT (
          phase_date
        )

        DO NOTHING

        RETURNING *
      `,
      [
        cleanDate,
        draw.commit,
        draw.seed,
      ]
    );

  if (
    insert.rows[0]
  ) {
    return insert
      .rows[0];
  }

  existing =
    (
      await client.query(
        `
          SELECT *

          FROM phases

          WHERE phase_date = $1

          LIMIT 1
        `,
        [
          cleanDate,
        ]
      )
    ).rows[0];

  if (
    !existing
  ) {
    throw new Error(
      "Unable to create daily phase"
    );
  }

  return existing;
}

async function getCurrentPhase(
  client
) {
  return getOrCreatePhase(
    client,
    getMoscowDateString()
  );
}

/* =========================================================
   PHASE TOTALS / ACCOUNTING
========================================================= */

async function refreshPhaseTotals(
  client,
  phaseId
) {
  const phaseResult =
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
    );

  const phase =
    phaseResult
      .rows[0];

  if (
    !phase
  ) {
    throw new Error(
      "Phase not found"
    );
  }

  const entryStats =
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

  const paymentStats =
    (
      await client.query(
        `
          SELECT
            COALESCE(
              SUM(
                stars_amount
              ) FILTER (
                WHERE status = 'succeeded'
              ),
              0
            )::numeric
              AS total_stars

          FROM payments

          WHERE phase_id = $1
        `,
        [
          phaseId,
        ]
      )
    ).rows[0];

  const totalStars =
    Number(
      paymentStats
        ?.total_stars ||
        0
    );

  const entryCount =
    Number(
      entryStats
        ?.entry_count ||
        0
    );

  const paidEntryCount =
    Number(
      entryStats
        ?.paid_entry_count ||
        0
    );

  const freeEntryCount =
    Number(
      entryStats
        ?.free_entry_count ||
        0
    );

  const grossUsd =
    money6(
      grossUsdFromStars(
        totalStars
      )
    );

  const winnerPoolStars =
    money6(
      totalStars *
        WINNER_SHARE
    );

  const charityStars =
    money6(
      totalStars *
        CHARITY_SHARE
    );

  const operationsStars =
    money6(
      totalStars *
        OPERATIONS_SHARE
    );

  const winnerPoolUsd =
    money6(
      grossUsd *
        WINNER_SHARE
    );

  const charityUsd =
    money6(
      grossUsd *
        CHARITY_SHARE
    );

  const operationsUsd =
    money6(
      grossUsd *
        OPERATIONS_SHARE
    );

  const requestedWinnerCount =
    winnerCountForGrossUsd(
      grossUsd
    );

  const actualWinnerCount =
    Math.min(
      requestedWinnerCount,
      entryCount
    );

  const updated =
    (
      await client.query(
        `
          UPDATE phases

          SET
            total_stars =
              $2,

            winner_pool_stars =
              $3,

            charity_stars =
              $4,

            operations_stars =
              $5,

            winner_count =
              $6,

            entry_count =
              $7,

            paid_entry_count =
              $8,

            free_entry_count =
              $9,

            gross_usd =
              $10,

            winner_pool_usd =
              $11,

            charity_usd =
              $12,

            operations_usd =
              $13,

            updated_at =
              NOW()

          WHERE id = $1

          RETURNING *
        `,
        [
          phaseId,
          totalStars,
          winnerPoolStars,
          charityStars,
          operationsStars,
          actualWinnerCount,
          entryCount,
          paidEntryCount,
          freeEntryCount,
          grossUsd,
          winnerPoolUsd,
          charityUsd,
          operationsUsd,
        ]
      )
    ).rows[0];

  const allocations = [
    [
      "winners",
      winnerPoolStars,
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
      starsAmount,
    ] of allocations
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
        starsAmount,
      ]
    );
  }

  return updated;
}

/* =========================================================
   REFERRAL LINKS
========================================================= */

async function getOrCreateReferralLink(
  client,
  telegramUserId,
  phaseId
) {
  const existing =
    (
      await client.query(
        `
          SELECT *

          FROM referral_links

          WHERE referrer_id = $1
            AND phase_id = $2

          LIMIT 1
        `,
        [
          telegramUserId,
          phaseId,
        ]
      )
    ).rows[0];

  if (
    existing
  ) {
    return existing;
  }

  for (
    let attempt = 0;
    attempt <
      5;
    attempt++
  ) {
    const code =
      `z${phaseId}_${randomToken(
        9
      )}`;

    try {
      const inserted =
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

              DO NOTHING

              RETURNING *
            `,
            [
              telegramUserId,
              phaseId,
              code,
            ]
          )
        ).rows[0];

      if (
        inserted
      ) {
        return inserted;
      }

      const raced =
        (
          await client.query(
            `
              SELECT *

              FROM referral_links

              WHERE referrer_id = $1
                AND phase_id = $2

              LIMIT 1
            `,
            [
              telegramUserId,
              phaseId,
            ]
          )
        ).rows[0];

      if (
        raced
      ) {
        return raced;
      }
    } catch (
      error
    ) {
      if (
        error
          ?.code !==
        "23505"
      ) {
        throw error;
      }
    }
  }

  throw new Error(
    "Unable to create referral link"
  );
}

function buildReferralUrl(
  code
) {
  if (
    !runtimeBotUsername
  ) {
    return null;
  }

  return (
    `https://t.me/${runtimeBotUsername}` +
    `?startapp=${encodeURIComponent(
      code
    )}`
  );
}

/* =========================================================
   REFERRAL ATTACHMENT
========================================================= */

async function attachReferralCode(
  client,
  referredUserId,
  phaseId,
  code
) {
  if (
    !code ||
    typeof code !==
      "string"
  ) {
    return {
      attached:
        false,

      reason:
        "invalid_code",
    };
  }

  const cleanCode =
    code
      .trim()
      .slice(
        0,
        100
      );

  const referralLink =
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
          cleanCode,
          phaseId,
        ]
      )
    ).rows[0];

  if (
    !referralLink
  ) {
    return {
      attached:
        false,

      reason:
        "not_found",
    };
  }

  if (
    Number(
      referralLink.referrer_id
    ) ===
    Number(
      referredUserId
    )
  ) {
    return {
      attached:
        false,

      reason:
        "self_referral",
    };
  }

  const existing =
    (
      await client.query(
        `
          SELECT *

          FROM referral_attachments

          WHERE referred_user_id = $1
            AND phase_id = $2

          LIMIT 1
        `,
        [
          referredUserId,
          phaseId,
        ]
      )
    ).rows[0];

  if (
    existing
  ) {
    return {
      attached:
        Number(
          existing.referrer_id
        ) ===
        Number(
          referralLink.referrer_id
        ),

      reason:
        "already_attached",

      referrerId:
        Number(
          existing.referrer_id
        ),
    };
  }

  try {
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
      `,
      [
        referredUserId,
        referralLink.referrer_id,
        phaseId,
        referralLink.id,
      ]
    );

    await audit(
      client,
      "referral_attached",
      referredUserId,
      phaseId,
      {
        referrerId:
          Number(
            referralLink.referrer_id
          ),

        referralCode:
          cleanCode,
      }
    );

    return {
      attached:
        true,

      reason:
        "attached",

      referrerId:
        Number(
          referralLink.referrer_id
        ),
    };
  } catch (
    error
  ) {
    if (
      error
        ?.code ===
      "23505"
    ) {
      return {
        attached:
          false,

        reason:
          "already_attached",
      };
    }

    throw error;
  }
}

/* =========================================================
   REFERRAL CONVERSION
========================================================= */

async function maybeRecordReferralConversion(
  client,
  referredUserId,
  phaseId,
  paymentId
) {
  const attachment =
    (
      await client.query(
        `
          SELECT *

          FROM referral_attachments

          WHERE referred_user_id = $1
            AND phase_id = $2

          LIMIT 1
        `,
        [
          referredUserId,
          phaseId,
        ]
      )
    ).rows[0];

  if (
    !attachment
  ) {
    return {
      converted:
        false,

      reason:
        "no_attachment",
    };
  }

  if (
    Number(
      attachment.referrer_id
    ) ===
    Number(
      referredUserId
    )
  ) {
    return {
      converted:
        false,

      reason:
        "self_referral",
    };
  }

  const inserted =
    (
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

          RETURNING *
        `,
        [
          referredUserId,
          attachment.referrer_id,
          phaseId,
          paymentId,
        ]
      )
    ).rows[0];

  if (
    !inserted
  ) {
    return {
      converted:
        false,

      reason:
        "already_converted",
    };
  }

  const conversionCount =
    Number(
      (
        await client.query(
          `
            SELECT
              COUNT(*)::integer
                AS count

            FROM referral_conversions

            WHERE referrer_id = $1
              AND phase_id = $2
          `,
          [
            attachment.referrer_id,
            phaseId,
          ]
        )
      ).rows[0]
        ?.count ||
        0
    );

  let freeEntryGranted =
    false;

  if (
    conversionCount >=
    2
  ) {
    const grant =
      (
        await client.query(
          `
            INSERT INTO free_entry_grants (
              telegram_user_id,
              phase_id,
              reason,
              required_referrals,
              status
            )
            VALUES (
              $1,
              $2,
              'two_paid_referrals',
              2,
              'available'
            )

            ON CONFLICT (
              telegram_user_id,
              phase_id
            )

            DO NOTHING

            RETURNING *
          `,
          [
            attachment.referrer_id,
            phaseId,
          ]
        )
      ).rows[0];

    freeEntryGranted =
      Boolean(
        grant
      );
  }

  await audit(
    client,
    "referral_conversion",
    referredUserId,
    phaseId,
    {
      referrerId:
        Number(
          attachment.referrer_id
        ),

      paymentId:
        Number(
          paymentId
        ),

      conversionCount,

      freeEntryGranted,
    }
  );

  return {
    converted:
      true,

    referrerId:
      Number(
        attachment.referrer_id
      ),

    conversionCount,

    freeEntryGranted,
  };
}

/* =========================================================
   FREE ENTRY
========================================================= */

async function getAvailableFreeGrant(
  client,
  telegramUserId,
  phaseId,
  lock = false
) {
  const sql =
    `
      SELECT *

      FROM free_entry_grants

      WHERE telegram_user_id = $1
        AND phase_id = $2
        AND status = 'available'

      LIMIT 1

      ${
        lock
          ? "FOR UPDATE"
          : ""
      }
    `;

  return (
    await client.query(
      sql,
      [
        telegramUserId,
        phaseId,
      ]
    )
  ).rows[0] ||
    null;
}

async function claimFreeEntry(
  telegramUser
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    const userId =
      Number(
        telegramUser.id
      );

    await upsertUser(
      client,
      telegramUser
    );

    const phase =
      await getCurrentPhase(
        client
      );

    const lockedPhase =
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

    if (
      !lockedPhase ||
      lockedPhase.status !==
        "open" ||
      toDateOnlyString(
        lockedPhase.phase_date
      ) !==
        getMoscowDateString()
    ) {
      throw new Error(
        "Current phase is not open"
      );
    }

    const existingEntry =
      (
        await client.query(
          `
            SELECT *

            FROM entries

            WHERE telegram_user_id = $1
              AND phase_id = $2

            LIMIT 1
          `,
          [
            userId,
            phase.id,
          ]
        )
      ).rows[0];

    if (
      existingEntry
    ) {
      await client.query(
        "ROLLBACK"
      );

      return {
        ok:
          false,

        code:
          "already_entered",

        message:
          "You already have an entry for this phase.",
      };
    }

    const grant =
      await getAvailableFreeGrant(
        client,
        userId,
        phase.id,
        true
      );

    if (
      !grant
    ) {
      await client.query(
        "ROLLBACK"
      );

      return {
        ok:
          false,

        code:
          "no_free_entry",

        message:
          "No free entry is available.",
      };
    }

    const entry =
      (
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
              NULL,
              'referral_free',
              TRUE,
              FALSE
            )

            RETURNING *
          `,
          [
            userId,
            phase.id,
          ]
        )
      ).rows[0];

    await client.query(
      `
        UPDATE free_entry_grants

        SET
          status =
            'claimed',

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
      userId,
      phase.id,
      {
        grantId:
          Number(
            grant.id
          ),

        entryId:
          Number(
            entry.id
          ),
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

      entryId:
        Number(
          entry.id
        ),

      isFree:
        true,
    };
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   USER / PHASE STATUS
========================================================= */

async function getUserPhaseStatus(
  client,
  telegramUserId,
  phase
) {
  const entry =
    (
      await client.query(
        `
          SELECT *

          FROM entries

          WHERE telegram_user_id = $1
            AND phase_id = $2

          LIMIT 1
        `,
        [
          telegramUserId,
          phase.id,
        ]
      )
    ).rows[0] ||
    null;

  const grant =
    await getAvailableFreeGrant(
      client,
      telegramUserId,
      phase.id,
      false
    );

  const referralLink =
    await getOrCreateReferralLink(
      client,
      telegramUserId,
      phase.id
    );

  const referralConversions =
    Number(
      (
        await client.query(
          `
            SELECT
              COUNT(*)::integer
                AS count

            FROM referral_conversions

            WHERE referrer_id = $1
              AND phase_id = $2
          `,
          [
            telegramUserId,
            phase.id,
          ]
        )
      ).rows[0]
        ?.count ||
        0
    );

  const userRow =
    (
      await client.query(
        `
          SELECT
            telegram_id,
            username,
            display_name,
            ton_wallet_address,
            ton_wallet_chain,
            ton_wallet_verified_at

          FROM users

          WHERE telegram_id = $1

          LIMIT 1
        `,
        [
          telegramUserId,
        ]
      )
    ).rows[0] ||
    null;

  return {
    phase: {
      id:
        Number(
          phase.id
        ),

      date:
        toDateOnlyString(
          phase.phase_date
        ),

      status:
        phase.status,

      entryStars:
        ENTRY_STARS,

      entryUsdDisplay:
        ENTRY_USD_DISPLAY,
    },

    hasEntry:
      Boolean(
        entry
      ),

    entry:
      entry
        ? {
            id:
              Number(
                entry.id
              ),

            isFree:
              Boolean(
                entry.is_free
              ),

            isFirstPayer:
              Boolean(
                entry.is_first_payer
              ),

            source:
              entry.source,

            createdAt:
              entry.created_at,
          }
        : null,

    freeEntryAvailable:
      Boolean(
        grant
      ),

    referral: {
      code:
        referralLink.code,

      link:
        buildReferralUrl(
          referralLink.code
        ),

      successfulPaidReferrals:
        referralConversions,

      requiredForFreeEntry:
        2,
    },

    wallet: {
      address:
        userRow
          ?.ton_wallet_address ||
        null,

      chain:
        userRow
          ?.ton_wallet_chain ??
        null,

      verified:
        Boolean(
          userRow
            ?.ton_wallet_verified_at
        ),

      verifiedAt:
        userRow
          ?.ton_wallet_verified_at ||
        null,
    },
  };
}
/* =========================================================
   TELEGRAM STARS — INVOICE CREATION
========================================================= */

async function createEntryInvoice(
  telegramUser
) {
  if (
    !PAYMENTS_ENABLED
  ) {
    throw new Error(
      "Payments are temporarily disabled."
    );
  }

  if (
    missingPaymentEnv.length >
    0
  ) {
    throw new Error(
      `Payment configuration incomplete: ${missingPaymentEnv.join(
        ", "
      )}`
    );
  }

  const userId =
    Number(
      telegramUser.id
    );

  const client =
    await pool.connect();

  let invoiceRow =
    null;

  try {
    await client.query(
      "BEGIN"
    );

    await upsertUser(
      client,
      telegramUser
    );

    const phase =
      await getCurrentPhase(
        client
      );

    /*
      Serialize invoice creation for the phase.

      This prevents two simultaneous requests from
      creating competing active checkout states.
    */
    const lockedPhase =
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

    if (
      !lockedPhase ||
      lockedPhase.status !==
        "open" ||
      toDateOnlyString(
        lockedPhase.phase_date
      ) !==
        getMoscowDateString()
    ) {
      throw new Error(
        "The current daily phase is not open."
      );
    }

    const existingEntry =
      (
        await client.query(
          `
            SELECT *

            FROM entries

            WHERE telegram_user_id = $1
              AND phase_id = $2

            LIMIT 1
          `,
          [
            userId,
            phase.id,
          ]
        )
      ).rows[0];

    if (
      existingEntry
    ) {
      await client.query(
        "COMMIT"
      );

      return {
        alreadyEntered:
          true,

        freeEntry:
          false,

        phaseId:
          Number(
            phase.id
          ),
      };
    }

    const freeGrant =
      await getAvailableFreeGrant(
        client,
        userId,
        phase.id,
        false
      );

    if (
      freeGrant
    ) {
      await client.query(
        "COMMIT"
      );

      return {
        alreadyEntered:
          false,

        freeEntry:
          true,

        phaseId:
          Number(
            phase.id
          ),
      };
    }

    /*
      Any checkout that has naturally expired
      must never be accepted later as an active invoice.
    */
    await client.query(
      `
        UPDATE invoices

        SET
          status =
            'expired'

        WHERE telegram_user_id = $1
          AND phase_id = $2
          AND status IN (
            'created',
            'precheckout_approved'
          )
          AND expires_at <= NOW()
      `,
      [
        userId,
        phase.id,
      ]
    );

    /*
      If Telegram already has a checkout in progress,
      don't generate another competing payment.
    */
    const checkoutInProgress =
      (
        await client.query(
          `
            SELECT id

            FROM invoices

            WHERE telegram_user_id = $1
              AND phase_id = $2
              AND status =
                'precheckout_approved'
              AND expires_at > NOW()

            LIMIT 1
          `,
          [
            userId,
            phase.id,
          ]
        )
      ).rows[0];

    if (
      checkoutInProgress
    ) {
      await client.query(
        "COMMIT"
      );

      return {
        alreadyEntered:
          false,

        freeEntry:
          false,

        paymentPending:
          true,

        phaseId:
          Number(
            phase.id
          ),
      };
    }

    /*
      Older invoice links that were generated but
      never entered checkout become invalid.

      This guarantees that only the newest invoice
      link can start a checkout.
    */
    await client.query(
      `
        UPDATE invoices

        SET
          status =
            'cancelled'

        WHERE telegram_user_id = $1
          AND phase_id = $2
          AND status =
            'created'
      `,
      [
        userId,
        phase.id,
      ]
    );

    const invoiceToken =
      randomToken(
        18
      );

    const payload =
      [
        "pz",
        phase.id,
        userId,
        invoiceToken,
      ].join(
        ":"
      );

    if (
      Buffer.byteLength(
        payload,
        "utf8"
      ) >
      128
    ) {
      throw new Error(
        "Generated invoice payload is too long."
      );
    }

    invoiceRow =
      (
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
              NOW() +
                ($6 * INTERVAL '1 second')
            )

            RETURNING *
          `,
          [
            invoiceToken,
            userId,
            phase.id,
            ENTRY_STARS,
            payload,
            INVOICE_TTL_SECONDS,
          ]
        )
      ).rows[0];

    await audit(
      client,
      "invoice_created",
      userId,
      phase.id,
      {
        invoiceId:
          Number(
            invoiceRow.id
          ),

        stars:
          ENTRY_STARS,
      }
    );

    await client.query(
      "COMMIT"
    );
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }

  /*
    Telegram API call happens after DB commit so an
    external network delay never keeps our DB transaction open.
  */
  try {
    const invoiceLink =
      await telegramApi(
        "createInvoiceLink",
        {
          title:
            "Project Z Entry",

          description:
            "One entry for today's Project Z competition.",

          payload:
            invoiceRow.payload,

          currency:
            "XTR",

          prices: [
            {
              label:
                "Project Z Entry",

              amount:
                ENTRY_STARS,
            },
          ],
        }
      );

    return {
      alreadyEntered:
        false,

      freeEntry:
        false,

      paymentPending:
        false,

      phaseId:
        Number(
          invoiceRow.phase_id
        ),

      invoiceId:
        Number(
          invoiceRow.id
        ),

      stars:
        ENTRY_STARS,

      invoiceLink,
    };
  } catch (
    error
  ) {
    await pool.query(
      `
        UPDATE invoices

        SET
          status =
            'failed'

        WHERE id = $1
          AND status =
            'created'
      `,
      [
        invoiceRow.id,
      ]
    ).catch(
      () => {}
    );

    throw error;
  }
}

/* =========================================================
   TELEGRAM STARS — PRE-CHECKOUT
========================================================= */

async function handlePreCheckoutQuery(
  query
) {
  const client =
    await pool.connect();

  let ok =
    false;

  let errorMessage =
    "Payment validation failed. Please create a new invoice.";

  try {
    await client.query(
      "BEGIN"
    );

    const invoice =
      (
        await client.query(
          `
            SELECT
              i.*,

              p.status
                AS phase_status,

              p.phase_date
                AS phase_date

            FROM invoices i

            JOIN phases p
              ON p.id =
                i.phase_id

            WHERE i.payload = $1

            LIMIT 1

            FOR UPDATE OF i, p
          `,
          [
            query.invoice_payload,
          ]
        )
      ).rows[0];

    if (
      !invoice
    ) {
      errorMessage =
        "This invoice is invalid or no longer available.";
    } else if (
      ![
        "created",
        "precheckout_approved",
      ].includes(
        invoice.status
      )
    ) {
      errorMessage =
        "This invoice is no longer active.";
    } else if (
      new Date(
        invoice.expires_at
      ).getTime() <=
      Date.now()
    ) {
      await client.query(
        `
          UPDATE invoices

          SET
            status =
              'expired'

          WHERE id = $1
        `,
        [
          invoice.id,
        ]
      );

      errorMessage =
        "This invoice expired. Please create a new one.";
    } else if (
      String(
        query.currency
      ) !==
      "XTR"
    ) {
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
      errorMessage =
        "This invoice belongs to another Telegram account.";
    } else if (
      invoice.phase_status !==
        "open" ||
      toDateOnlyString(
        invoice.phase_date
      ) !==
        getMoscowDateString()
    ) {
      errorMessage =
        "Today's Project Z phase has ended.";
    } else {
      const existingEntry =
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
              query.from.id,
              invoice.phase_id,
            ]
          )
        ).rows[0];

      if (
        existingEntry
      ) {
        errorMessage =
          "You already have an entry for today's phase.";
      } else {
        /*
          Another invoice for this same user must not
          be simultaneously approved for checkout.
        */
        const otherApproved =
          (
            await client.query(
              `
                SELECT id

                FROM invoices

                WHERE telegram_user_id = $1
                  AND phase_id = $2
                  AND id <> $3
                  AND status =
                    'precheckout_approved'
                  AND expires_at > NOW()

                LIMIT 1
              `,
              [
                query.from.id,
                invoice.phase_id,
                invoice.id,
              ]
            )
          ).rows[0];

        if (
          otherApproved
        ) {
          errorMessage =
            "Another payment is already being processed.";
        } else {
          /*
            Once this checkout is approved, invalidate
            other unused invoice links for the same user.
          */
          await client.query(
            `
              UPDATE invoices

              SET
                status =
                  'cancelled'

              WHERE telegram_user_id = $1
                AND phase_id = $2
                AND id <> $3
                AND status =
                  'created'
            `,
            [
              query.from.id,
              invoice.phase_id,
              invoice.id,
            ]
          );

          await client.query(
            `
              UPDATE invoices

              SET
                status =
                  'precheckout_approved'

              WHERE id = $1
            `,
            [
              invoice.id,
            ]
          );

          ok =
            true;
        }
      }
    }

    await client.query(
      "COMMIT"
    );
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    console.error(
      "Pre-checkout validation failed:",
      error.message
    );

    ok =
      false;

    errorMessage =
      "Payment validation failed. Please try again.";
  } finally {
    client.release();
  }

  /*
    Telegram requires this response quickly.
  */
  try {
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
      "answerPreCheckoutQuery failed:",
      error.message
    );
  }
}

/* =========================================================
   UNEXPECTED PAYMENT / REFUND QUEUE
========================================================= */

async function queueUnexpectedRefund({
  userId,
  telegramPaymentChargeId,
  invoicePayload = null,
  currency = "XTR",
  starsAmount = null,
  reason,
  rawPayload = null,
}) {
  if (
    !telegramPaymentChargeId
  ) {
    console.error(
      "Cannot queue refund without Telegram payment charge id."
    );

    return null;
  }

  const result =
    await pool.query(
      `
        INSERT INTO payment_reconciliations (
          telegram_payment_charge_id,
          telegram_user_id,
          invoice_payload,
          currency,
          stars_amount,
          reason,
          status,
          raw_payload,
          attempts,
          updated_at
        )

        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          'refund_pending',
          $7::jsonb,
          0,
          NOW()
        )

        ON CONFLICT (
          telegram_payment_charge_id
        )

        DO UPDATE SET
          telegram_user_id =
            COALESCE(
              EXCLUDED.telegram_user_id,
              payment_reconciliations.telegram_user_id
            ),

          invoice_payload =
            COALESCE(
              EXCLUDED.invoice_payload,
              payment_reconciliations.invoice_payload
            ),

          currency =
            COALESCE(
              EXCLUDED.currency,
              payment_reconciliations.currency
            ),

          stars_amount =
            COALESCE(
              EXCLUDED.stars_amount,
              payment_reconciliations.stars_amount
            ),

          reason =
            EXCLUDED.reason,

          raw_payload =
            COALESCE(
              EXCLUDED.raw_payload,
              payment_reconciliations.raw_payload
            ),

          status =
            CASE
              WHEN payment_reconciliations.status =
                'refunded'
              THEN
                'refunded'

              ELSE
                'refund_pending'
            END,

          updated_at =
            NOW()

        RETURNING *
      `,
      [
        telegramPaymentChargeId,

        userId ??
          null,

        invoicePayload,

        currency,

        starsAmount,

        String(
          reason ||
          "unexpected_payment"
        ).slice(
          0,
          500
        ),

        safeJson(
          rawPayload
        ),
      ]
    );

  return result
    .rows[0] ||
    null;
}

/* =========================================================
   TELEGRAM STARS — SUCCESSFUL PAYMENT
========================================================= */

async function handleSuccessfulPayment(
  message
) {
  const payment =
    message
      ?.successful_payment;

  const userId =
    Number(
      message
        ?.from
        ?.id
    );

  if (
    !payment ||
    !Number.isSafeInteger(
      userId
    ) ||
    userId <=
      0
  ) {
    console.error(
      "Successful payment update missing valid Telegram user."
    );

    return;
  }

  const chargeId =
    String(
      payment.telegram_payment_charge_id ||
      ""
    );

  const invoicePayload =
    String(
      payment.invoice_payload ||
      ""
    );

  if (
    !chargeId
  ) {
    console.error(
      "Successful payment update missing charge id."
    );

    return;
  }

  /*
    Fast idempotency check.

    Telegram may retry webhook updates.
    Processing the same charge twice must be harmless.
  */
  const alreadyProcessed =
    (
      await pool.query(
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
    alreadyProcessed
  ) {
    return;
  }

  const alreadyQueued =
    (
      await pool.query(
        `
          SELECT status

          FROM payment_reconciliations

          WHERE telegram_payment_charge_id = $1

          LIMIT 1
        `,
        [
          chargeId,
        ]
      )
    ).rows[0];

  if (
    alreadyQueued
  ) {
    return;
  }

  const client =
    await pool.connect();

  let refundReason =
    null;

  let refundContext =
    null;

  try {
    await client.query(
      "BEGIN"
    );

    /*
      Re-check idempotency while inside the transaction.
    */
    const duplicate =
      (
        await client.query(
          `
            SELECT id

            FROM payments

            WHERE telegram_payment_charge_id = $1

            LIMIT 1

            FOR UPDATE
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

    /*
      Load and lock the invoice first.
    */
    const invoice =
      (
        await client.query(
          `
            SELECT
              i.*,

              p.status
                AS phase_status,

              p.phase_date
                AS phase_date

            FROM invoices i

            JOIN phases p
              ON p.id =
                i.phase_id

            WHERE i.payload = $1

            LIMIT 1

            FOR UPDATE OF i, p
          `,
          [
            invoicePayload,
          ]
        )
      ).rows[0];

    if (
      !invoice
    ) {
      refundReason =
        "invoice_not_found";
    } else if (
      Number(
        invoice.telegram_user_id
      ) !==
      userId
    ) {
      refundReason =
        "invoice_user_mismatch";
    } else if (
      String(
        payment.currency
      ) !==
      "XTR"
    ) {
      refundReason =
        "invalid_currency";
    } else if (
      Number(
        payment.total_amount
      ) !==
      Number(
        invoice.stars_amount
      )
    ) {
      refundReason =
        "invalid_amount";
    } else if (
      invoice.phase_status !==
        "open" ||
      toDateOnlyString(
        invoice.phase_date
      ) !==
        getMoscowDateString()
    ) {
      refundReason =
        "phase_closed";
    } else if (
      ![
        "created",
        "precheckout_approved",
      ].includes(
        invoice.status
      )
    ) {
      refundReason =
        `invoice_status_${invoice.status}`;
    }

    if (
      refundReason
    ) {
      refundContext = {
        phaseId:
          invoice
            ?.phase_id ||
          null,

        invoiceId:
          invoice
            ?.id ||
          null,
      };

      await client.query(
        "ROLLBACK"
      );
    } else {
      /*
        This row-level phase lock is the critical
        concurrency protection.

        Only one successful payment for this phase
        can decide "am I the first payer?" at a time.
      */
      const lockedPhase =
        (
          await client.query(
            `
              SELECT *

              FROM phases

              WHERE id = $1

              FOR UPDATE
            `,
            [
              invoice.phase_id,
            ]
          )
        ).rows[0];

      if (
        !lockedPhase ||
        lockedPhase.status !==
          "open"
      ) {
        refundReason =
          "phase_not_open";

        refundContext = {
          phaseId:
            invoice.phase_id,

          invoiceId:
            invoice.id,
        };

        await client.query(
          "ROLLBACK"
        );
      } else {
        const existingEntry =
          (
            await client.query(
              `
                SELECT *

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
          existingEntry
        ) {
          refundReason =
            "duplicate_entry_payment";

          refundContext = {
            phaseId:
              invoice.phase_id,

            invoiceId:
              invoice.id,

            existingEntryId:
              existingEntry.id,
          };

          await client.query(
            "ROLLBACK"
          );
        } else {
          /*
            Upsert the Telegram profile before financial
            records are committed.
          */
          await upsertUser(
            client,
            message.from
          );

          /*
            Because the phase row is locked, no other
            successful payment can concurrently pass
            this check for the same phase.
          */
          const previousPaidEntry =
            (
              await client.query(
                `
                  SELECT id

                  FROM entries

                  WHERE phase_id = $1
                    AND is_free = FALSE

                  ORDER BY id ASC

                  LIMIT 1
                `,
                [
                  invoice.phase_id,
                ]
              )
            ).rows[0];

          const isFirstPayer =
            !previousPaidEntry;

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

                  Number(
                    payment.total_amount
                  ),

                  invoicePayload,

                  safeJson(
                    payment
                  ),
                ]
              )
            ).rows[0];

          const entryRow =
            (
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

                  RETURNING *
                `,
                [
                  userId,

                  invoice.phase_id,

                  paymentRow.id,

                  isFirstPayer,
                ]
              )
            ).rows[0];

          if (
            isFirstPayer
          ) {
            await client.query(
              `
                UPDATE phases

                SET
                  first_verified_entry_id =
                    $2,

                  updated_at =
                    NOW()

                WHERE id = $1
              `,
              [
                invoice.phase_id,

                entryRow.id,
              ]
            );
          }

          await client.query(
            `
              UPDATE invoices

              SET
                status =
                  'paid',

                paid_at =
                  NOW()

              WHERE id = $1
            `,
            [
              invoice.id,
            ]
          );

          /*
            Any other unused invoice from this user/day
            can never become valid after the entry exists.
          */
          await client.query(
            `
              UPDATE invoices

              SET
                status =
                  'cancelled'

              WHERE telegram_user_id = $1
                AND phase_id = $2
                AND id <> $3
                AND status IN (
                  'created',
                  'precheckout_approved'
                )
            `,
            [
              userId,
              invoice.phase_id,
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
                Number(
                  paymentRow.id
                ),

              entryId:
                Number(
                  entryRow.id
                ),

              chargeId,

              stars:
                Number(
                  payment.total_amount
                ),

              isFirstPayer,
            }
          );

          await client.query(
            "COMMIT"
          );

          console.log(
            `Payment accepted: user=${userId} phase=${invoice.phase_id} stars=${payment.total_amount}`
          );

          return;
        }
      }
    }
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    console.error(
      "Successful payment processing failed:",
      error.message
    );

    refundReason =
      `processing_error:${String(
        error.message ||
        "unknown"
      ).slice(
        0,
        350
      )}`;
  } finally {
    client.release();
  }

  /*
    A real SuccessfulPayment must never silently disappear.

    If it couldn't legally/safely become an entry,
    it is placed into the automatic refund queue.
  */
  if (
    refundReason
  ) {
    try {
      await queueUnexpectedRefund({
        userId,

        telegramPaymentChargeId:
          chargeId,

        invoicePayload,

        currency:
          payment.currency ||
          "XTR",

        starsAmount:
          Number(
            payment.total_amount ||
            0
          ),

        reason:
          refundReason,

        rawPayload: {
          payment,

          refundContext,
        },
      });

      console.warn(
        `Payment queued for refund: charge=${chargeId} reason=${refundReason}`
      );
    } catch (
      queueError
    ) {
      /*
        This log is intentionally loud:
        a paid transaction requiring refund must be
        recoverable by operations if DB queueing fails.
      */
      console.error(
        "CRITICAL: unable to queue paid transaction for refund:",
        {
          chargeId,

          userId,

          refundReason,

          error:
            queueError.message,
        }
      );
    }
  }
}
/* =========================================================
   TELEGRAM STARS — REFUND WORKER
========================================================= */

let refundWorkerRunning =
  false;

async function processOneRefund() {
  const client =
    await pool.connect();

  let refundRow =
    null;

  try {
    await client.query(
      "BEGIN"
    );

    /*
      SKIP LOCKED prevents two server instances
      from refunding the same Telegram payment.
    */
    const candidate =
      (
        await client.query(
          `
            SELECT *

            FROM payment_reconciliations

            WHERE status IN (
              'refund_pending',
              'refund_retry'
            )

              AND attempts < $1

            ORDER BY id ASC

            LIMIT 1

            FOR UPDATE
            SKIP LOCKED
          `,
          [
            REFUND_MAX_ATTEMPTS,
          ]
        )
      ).rows[0];

    if (
      !candidate
    ) {
      await client.query(
        "COMMIT"
      );

      return false;
    }

    /*
      Critical safety check:

      If this charge actually became a valid entry
      despite an earlier temporary error, DO NOT refund it.
    */
    const validPayment =
      (
        await client.query(
          `
            SELECT
              p.id AS payment_id,
              e.id AS entry_id

            FROM payments p

            JOIN entries e
              ON e.payment_id =
                p.id

            WHERE p.telegram_payment_charge_id = $1
              AND p.status = 'succeeded'

            LIMIT 1
          `,
          [
            candidate.telegram_payment_charge_id,
          ]
        )
      ).rows[0];

    if (
      validPayment
    ) {
      await client.query(
        `
          UPDATE payment_reconciliations

          SET
            status =
              'resolved_valid',

            last_error =
              NULL,

            updated_at =
              NOW()

          WHERE id = $1
        `,
        [
          candidate.id,
        ]
      );

      await client.query(
        "COMMIT"
      );

      console.log(
        `Refund cancelled because payment is valid: ${candidate.telegram_payment_charge_id}`
      );

      return true;
    }

    if (
      !candidate.telegram_user_id
    ) {
      await client.query(
        `
          UPDATE payment_reconciliations

          SET
            status =
              'manual_review',

            last_error =
              'Missing Telegram user id',

            updated_at =
              NOW()

          WHERE id = $1
        `,
        [
          candidate.id,
        ]
      );

      await client.query(
        "COMMIT"
      );

      return true;
    }

    refundRow =
      (
        await client.query(
          `
            UPDATE payment_reconciliations

            SET
              status =
                'refund_processing',

              attempts =
                attempts + 1,

              last_error =
                NULL,

              updated_at =
                NOW()

            WHERE id = $1

            RETURNING *
          `,
          [
            candidate.id,
          ]
        )
      ).rows[0];

    await client.query(
      "COMMIT"
    );
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    console.error(
      "Refund queue claim failed:",
      error.message
    );

    return false;
  } finally {
    client.release();
  }

  if (
    !refundRow
  ) {
    return false;
  }

  try {
    await telegramApi(
      "refundStarPayment",
      {
        user_id:
          Number(
            refundRow.telegram_user_id
          ),

        telegram_payment_charge_id:
          refundRow.telegram_payment_charge_id,
      }
    );

    await pool.query(
      `
        UPDATE payment_reconciliations

        SET
          status =
            'refunded',

          last_error =
            NULL,

          updated_at =
            NOW()

        WHERE id = $1
      `,
      [
        refundRow.id,
      ]
    );

    /*
      Normally unexpected payments are never inserted
      into payments, but this makes reconciliation safe
      even if a legacy record exists.
    */
    await pool.query(
      `
        UPDATE payments

        SET
          status =
            'refunded',

          refunded_at =
            NOW(),

          refund_last_error =
            NULL,

          last_refund_attempt_at =
            NOW()

        WHERE telegram_payment_charge_id = $1
          AND status <> 'refunded'
      `,
      [
        refundRow.telegram_payment_charge_id,
      ]
    ).catch(
      () => {}
    );

    if (
      refundRow.invoice_payload
    ) {
      await pool.query(
        `
          UPDATE invoices

          SET
            status =
              'refunded'

          WHERE payload = $1
            AND status <> 'paid'
        `,
        [
          refundRow.invoice_payload,
        ]
      ).catch(
        () => {}
      );
    }

    console.log(
      `Telegram Stars refund completed: ${refundRow.telegram_payment_charge_id}`
    );

    return true;
  } catch (
    error
  ) {
    const finalAttempt =
      Number(
        refundRow.attempts
      ) >=
      REFUND_MAX_ATTEMPTS;

    await pool.query(
      `
        UPDATE payment_reconciliations

        SET
          status =
            $2,

          last_error =
            $3,

          updated_at =
            NOW()

        WHERE id = $1
      `,
      [
        refundRow.id,

        finalAttempt
          ? "manual_review"
          : "refund_retry",

        String(
          error.message ||
          "Refund failed"
        ).slice(
          0,
          500
        ),
      ]
    ).catch(
      () => {}
    );

    console.error(
      `Telegram Stars refund failed: ${refundRow.telegram_payment_charge_id}`,
      error.message
    );

    return true;
  }
}

async function runRefundWorker(
  maxItems = 20
) {
  if (
    refundWorkerRunning
  ) {
    return;
  }

  refundWorkerRunning =
    true;

  try {
    const limit =
      clampInt(
        maxItems,
        1,
        100
      );

    for (
      let index = 0;
      index <
        limit;
      index++
    ) {
      const processed =
        await processOneRefund();

      if (
        !processed
      ) {
        break;
      }
    }
  } catch (
    error
  ) {
    console.error(
      "Refund worker failed:",
      error.message
    );
  } finally {
    refundWorkerRunning =
      false;
  }
}

/* =========================================================
   DETERMINISTIC WINNER DRAW
========================================================= */

function deterministicEntryScore(
  seed,
  phaseDate,
  entry
) {
  return sha256Hex(
    [
      "project-z-draw-v1",
      seed,
      phaseDate,
      entry.id,
      entry.telegram_user_id,
    ].join(
      "|"
    )
  );
}

function sortEntriesForDraw(
  entries,
  seed,
  phaseDate
) {
  return entries
    .map(
      (entry) => ({
        ...entry,

        drawScore:
          deterministicEntryScore(
            seed,
            phaseDate,
            entry
          ),
      })
    )
    .sort(
      (
        a,
        b
      ) => {
        const scoreCompare =
          a.drawScore.localeCompare(
            b.drawScore
          );

        if (
          scoreCompare !==
          0
        ) {
          return scoreCompare;
        }

        return (
          Number(
            a.id
          ) -
          Number(
            b.id
          )
        );
      }
    );
}

/* =========================================================
   PHASE FINALIZATION
========================================================= */

async function finalizePhaseById(
  phaseId,
  {
    allowCurrent =
      false,
  } = {}
) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    let phase =
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
      await client.query(
        "ROLLBACK"
      );

      return {
        ok:
          false,

        code:
          "phase_not_found",
      };
    }

    if (
      phase.status ===
      "finalized"
    ) {
      await client.query(
        "COMMIT"
      );

      return {
        ok:
          true,

        alreadyFinalized:
          true,

        phaseId:
          Number(
            phase.id
          ),

        winnerCount:
          Number(
            phase.winner_count ||
            0
          ),
      };
    }

    const phaseDate =
      toDateOnlyString(
        phase.phase_date
      );

    const today =
      getMoscowDateString();

    if (
      !allowCurrent &&
      phaseDate >=
        today
    ) {
      await client.query(
        "ROLLBACK"
      );

      return {
        ok:
          false,

        code:
          "phase_not_ready",

        phaseDate,

        today,
      };
    }

    /*
      Recalculate all financial totals immediately
      before the draw.
    */
    phase =
      await refreshPhaseTotals(
        client,
        phase.id
      );

    /*
      Legacy phases might predate commit/reveal support.
      If so, generate the required material safely.
    */
    if (
      !phase.draw_seed_secret ||
      !phase.draw_commit_hash
    ) {
      const draw =
        createDrawMaterial(
          phaseDate
        );

      phase =
        (
          await client.query(
            `
              UPDATE phases

              SET
                draw_seed_secret =
                  $2,

                draw_commit_hash =
                  $3,

                updated_at =
                  NOW()

              WHERE id = $1

              RETURNING *
            `,
            [
              phase.id,
              draw.seed,
              draw.commit,
            ]
          )
        ).rows[0];
    }

    const existingWinner =
      (
        await client.query(
          `
            SELECT id

            FROM winners

            WHERE phase_id = $1

            LIMIT 1
          `,
          [
            phase.id,
          ]
        )
      ).rows[0];

    /*
      An open phase should never already contain winners.
      Refuse to overwrite financial history.
    */
    if (
      existingWinner
    ) {
      throw new Error(
        "Open phase already contains winner records."
      );
    }

    const entries =
      (
        await client.query(
          `
            SELECT
              id,
              telegram_user_id,
              is_free,
              is_first_payer,
              created_at

            FROM entries

            WHERE phase_id = $1

            ORDER BY id ASC
          `,
          [
            phase.id,
          ]
        )
      ).rows;

    const grossUsd =
      Number(
        phase.gross_usd ||
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

    const seed =
      String(
        phase.draw_seed_secret
      );

    /*
      The first valid payer is guaranteed a winning slot
      whenever this phase has at least one winner.
    */
    let firstPayerEntry =
      null;

    if (
      actualWinnerCount >
      0
    ) {
      if (
        phase.first_verified_entry_id
      ) {
        firstPayerEntry =
          entries.find(
            (entry) =>
              Number(
                entry.id
              ) ===
              Number(
                phase.first_verified_entry_id
              )
          ) ||
          null;
      }

      if (
        !firstPayerEntry
      ) {
        firstPayerEntry =
          entries.find(
            (entry) =>
              Boolean(
                entry.is_first_payer
              )
          ) ||
          null;
      }
    }

    const remainingEntries =
      entries.filter(
        (entry) =>
          !firstPayerEntry ||
          Number(
            entry.id
          ) !==
            Number(
              firstPayerEntry.id
            )
      );

    const drawnEntries =
      sortEntriesForDraw(
        remainingEntries,
        seed,
        phaseDate
      );

    const selectedEntries =
      [];

    if (
      firstPayerEntry &&
      actualWinnerCount >
        0
    ) {
      selectedEntries.push(
        firstPayerEntry
      );
    }

    const remainingSlots =
      Math.max(
        0,
        actualWinnerCount -
          selectedEntries.length
      );

    selectedEntries.push(
      ...drawnEntries.slice(
        0,
        remainingSlots
      )
    );

    /*
      Prize accounting is performed in USDT micro-units
      so rounding never creates or destroys money.

      1 USDT = 1,000,000 micro units.
    */
    const winnerPoolUsd =
      Number(
        phase.winner_pool_usd ||
        0
      );

    const winnerPoolStars =
      Number(
        phase.winner_pool_stars ||
        0
      );

    const totalPrizeMicro =
      selectedEntries.length >
      0
        ? Math.max(
            0,
            Math.round(
              winnerPoolUsd *
                1_000_000
            )
          )
        : 0;

    const basePrizeMicro =
      selectedEntries.length >
      0
        ? Math.floor(
            totalPrizeMicro /
              selectedEntries.length
          )
        : 0;

    const prizeMicroRemainder =
      selectedEntries.length >
      0
        ? totalPrizeMicro %
          selectedEntries.length
        : 0;

    const prizeStarsPerWinner =
      selectedEntries.length >
      0
        ? money6(
            winnerPoolStars /
              selectedEntries.length
          )
        : 0;

    for (
      let index = 0;
      index <
        selectedEntries.length;
      index++
    ) {
      const entry =
        selectedEntries[
          index
        ];

      const prizeMicro =
        basePrizeMicro +
        (
          index <
          prizeMicroRemainder
            ? 1
            : 0
        );

      const prizeUsd =
        money6(
          prizeMicro /
            1_000_000
        );

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

              RETURNING *
            `,
            [
              phase.id,

              entry.id,

              entry.telegram_user_id,

              index +
                1,

              prizeStarsPerWinner,

              Boolean(
                entry.is_first_payer
              ),

              prizeUsd,

              prizeStarsPerWinner,
            ]
          )
        ).rows[0];

      const winnerUser =
        (
          await client.query(
            `
              SELECT
                ton_wallet_address,
                ton_wallet_verified_at

              FROM users

              WHERE telegram_id = $1

              LIMIT 1
            `,
            [
              entry.telegram_user_id,
            ]
          )
        ).rows[0];

      const walletReady =
        Boolean(
          winnerUser
            ?.ton_wallet_address &&
          winnerUser
            ?.ton_wallet_verified_at
        );

      /*
        amount_stars is maintained for compatibility
        with the original database.

        Actual settlement is USDT on TON.
      */
      const legacyAmountStars =
        Math.max(
          1,
          Math.round(
            prizeStarsPerWinner
          )
        );

      await client.query(
        `
          INSERT INTO payouts (
            phase_id,
            winner_id,
            telegram_user_id,
            amount_stars,
            status,
            ton_wallet_address,
            prize_usd,
            usdt_amount_micro,
            settlement_asset
          )

          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            'USDT_TON'
          )

          ON CONFLICT (
            winner_id
          )

          DO NOTHING
        `,
        [
          phase.id,

          winner.id,

          entry.telegram_user_id,

          legacyAmountStars,

          walletReady
            ? "pending"
            : "awaiting_wallet",

          winnerUser
            ?.ton_wallet_address ||
          null,

          prizeUsd,

          prizeMicro,
        ]
      );
    }

    /*
      Any old checkout/free-entry state belonging
      to the finished day is closed.
    */
    await client.query(
      `
        UPDATE invoices

        SET
          status =
            'expired'

        WHERE phase_id = $1
          AND status IN (
            'created',
            'precheckout_approved'
          )
      `,
      [
        phase.id,
      ]
    );

    await client.query(
      `
        UPDATE free_entry_grants

        SET
          status =
            'expired'

        WHERE phase_id = $1
          AND status =
            'available'
      `,
      [
        phase.id,
      ]
    );

    phase =
      (
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

            RETURNING *
          `,
          [
            phase.id,

            selectedEntries.length,

            seed,
          ]
        )
      ).rows[0];

    await audit(
      client,
      "phase_finalized",
      null,
      phase.id,
      {
        phaseDate,

        grossUsd,

        requestedWinnerCount,

        actualWinnerCount:
          selectedEntries.length,

        drawCommitHash:
          phase.draw_commit_hash,

        drawReveal:
          seed,

        firstPayerEntryId:
          firstPayerEntry
            ?.id ||
          null,

        winnerPoolUsd:
          Number(
            phase.winner_pool_usd ||
            0
          ),

        settlementAsset:
          "USDT_TON",

        automaticSettlement:
          AUTOMATIC_SETTLEMENT_ENABLED,
      }
    );

    await client.query(
      "COMMIT"
    );

    console.log(
      `Phase finalized: ${phaseDate} winners=${selectedEntries.length}`
    );

    return {
      ok:
        true,

      alreadyFinalized:
        false,

      phaseId:
        Number(
          phase.id
        ),

      phaseDate,

      winnerCount:
        selectedEntries.length,

      requestedWinnerCount,

      grossUsd,

      drawCommitHash:
        phase.draw_commit_hash,

      drawReveal:
        seed,
    };
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    console.error(
      `Phase finalization failed for ${phaseId}:`,
      error.message
    );

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   AUTOMATIC DAILY FINALIZATION
========================================================= */

let finalizationWorkerRunning =
  false;

async function finalizePastPhases() {
  if (
    finalizationWorkerRunning
  ) {
    return;
  }

  finalizationWorkerRunning =
    true;

  try {
    const today =
      getMoscowDateString();

    const phases =
      (
        await pool.query(
          `
            SELECT id

            FROM phases

            WHERE status = 'open'
              AND phase_date < $1

            ORDER BY phase_date ASC
          `,
          [
            today,
          ]
        )
      ).rows;

    for (
      const phase of
      phases
    ) {
      try {
        await finalizePhaseById(
          phase.id
        );
      } catch (
        error
      ) {
        console.error(
          `Automatic finalization failed for phase ${phase.id}:`,
          error.message
        );
      }
    }
  } catch (
    error
  ) {
    console.error(
      "Finalization worker failed:",
      error.message
    );
  } finally {
    finalizationWorkerRunning =
      false;
  }
}

/* =========================================================
   PAYOUT QUEUE HELPERS
========================================================= */

async function refreshWinnerPayoutWallet(
  client,
  telegramUserId
) {
  const user =
    (
      await client.query(
        `
          SELECT
            ton_wallet_address,
            ton_wallet_verified_at

          FROM users

          WHERE telegram_id = $1

          LIMIT 1
        `,
        [
          telegramUserId,
        ]
      )
    ).rows[0];

  if (
    !user
      ?.ton_wallet_address ||
    !user
      ?.ton_wallet_verified_at
  ) {
    return 0;
  }

  const result =
    await client.query(
      `
        UPDATE payouts

        SET
          ton_wallet_address =
            $2,

          status =
            CASE
              WHEN status =
                'awaiting_wallet'
              THEN
                'pending'

              ELSE
                status
            END

        WHERE telegram_user_id = $1
          AND status IN (
            'awaiting_wallet',
            'pending'
          )
      `,
      [
        telegramUserId,

        user.ton_wallet_address,
      ]
    );

  return result.rowCount;
}

async function getPayoutQueue({
  status = null,
  limit = 100,
} = {}) {
  const safeLimit =
    clampInt(
      limit,
      1,
      500
    );

  const values =
    [];

  let where =
    "";

  if (
    status
  ) {
    values.push(
      String(
        status
      )
    );

    where =
      `WHERE p.status = $${values.length}`;
  }

  values.push(
    safeLimit
  );

  const limitPlaceholder =
    `$${values.length}`;

  const result =
    await pool.query(
      `
        SELECT
          p.id,
          p.phase_id,
          p.winner_id,
          p.telegram_user_id,
          p.status,
          p.ton_wallet_address,
          p.prize_usd,
          p.usdt_amount_micro,
          p.settlement_asset,
          p.ton_tx_hash,
          p.settlement_reference,
          p.failure_reason,
          p.created_at,
          p.processing_at,
          p.paid_at,

          w.rank,
          w.is_first_payer,

          ph.phase_date,

          u.display_name,
          u.username

        FROM payouts p

        JOIN winners w
          ON w.id =
            p.winner_id

        JOIN phases ph
          ON ph.id =
            p.phase_id

        LEFT JOIN users u
          ON u.telegram_id =
            p.telegram_user_id

        ${where}

        ORDER BY
          p.phase_id DESC,
          w.rank ASC

        LIMIT ${limitPlaceholder}
      `,
      values
    );

  return result.rows;
}
/* =========================================================
   TON CONNECT — WALLET PUBLIC KEY EXTRACTION
========================================================= */

const EMPTY_PUBLIC_KEY =
  Buffer.alloc(
    32
  );

const KNOWN_WALLET_CODES =
  [
    {
      type:
        "v1r1",

      wallet:
        WalletContractV1R1.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v1r2",

      wallet:
        WalletContractV1R2.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v1r3",

      wallet:
        WalletContractV1R3.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v2r1",

      wallet:
        WalletContractV2R1.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v2r2",

      wallet:
        WalletContractV2R2.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v3r1",

      wallet:
        WalletContractV3R1.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v3r2",

      wallet:
        WalletContractV3R2.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v4r2",

      wallet:
        WalletContractV4.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
        slice.loadUint(
          32
        );

        slice.loadUint(
          32
        );

        return slice.loadBuffer(
          32
        );
      },
    },

    {
      type:
        "v5r1",

      wallet:
        WalletContractV5R1.create({
          workchain:
            0,

          publicKey:
            EMPTY_PUBLIC_KEY,
        }),

      parsePublicKey(
        slice
      ) {
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
      },
    },
  ];

function parseWalletStateInit(
  walletStateInit
) {
  if (
    typeof walletStateInit !==
      "string" ||
    !walletStateInit.length
  ) {
    throw new Error(
      "walletStateInit missing"
    );
  }

  const boc =
    Buffer.from(
      walletStateInit,
      "base64"
    );

  const cells =
    Cell.fromBoc(
      boc
    );

  if (
    !cells.length
  ) {
    throw new Error(
      "Invalid wallet state init"
    );
  }

  return loadStateInit(
    cells[0].beginParse()
  );
}

function extractWalletPublicKey(
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

  for (
    const item of
    KNOWN_WALLET_CODES
  ) {
    try {
      if (
        item.wallet.init.code.equals(
          stateInit.code
        )
      ) {
        const publicKey =
          item.parsePublicKey(
            stateInit.data.beginParse()
          );

        if (
          publicKey.length !==
          32
        ) {
          return null;
        }

        return {
          publicKey,

          walletType:
            item.type,
        };
      }
    } catch {}
  }

  return null;
}

/* =========================================================
   TON CONNECT — PROOF MESSAGE
========================================================= */

function createTonProofMessageHash({
  address,
  domain,
  timestamp,
  payload,
}) {
  const parsedAddress =
    Address.parse(
      address
    );

  const domainBuffer =
    Buffer.from(
      domain,
      "utf8"
    );

  const payloadBuffer =
    Buffer.from(
      payload,
      "utf8"
    );

  const workchain =
    Buffer.alloc(
      4
    );

  workchain.writeInt32BE(
    parsedAddress.workChain,
    0
  );

  const domainLength =
    Buffer.alloc(
      4
    );

  domainLength.writeUInt32LE(
    domainBuffer.length,
    0
  );

  const timestampBuffer =
    Buffer.alloc(
      8
    );

  timestampBuffer.writeBigUInt64LE(
    BigInt(
      timestamp
    ),
    0
  );

  const message =
    Buffer.concat([
      Buffer.from(
        "ton-proof-item-v2/",
        "utf8"
      ),

      workchain,

      parsedAddress.hash,

      domainLength,

      domainBuffer,

      timestampBuffer,

      payloadBuffer,
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

/* =========================================================
   TON CONNECT — NONCE
========================================================= */

async function createTonProofChallenge(
  telegramUserId
) {
  const nonce =
    randomToken(
      32
    );

  const result =
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
          NOW() +
            ($4 * INTERVAL '1 second')
        )

        RETURNING *
      `,
      [
        telegramUserId,
        nonce,
        TON_PROOF_DOMAIN,
        TON_PROOF_TTL_SECONDS,
      ]
    );

  return result
    .rows[0];
}

/* =========================================================
   TON CONNECT — VERIFY PROOF
========================================================= */

async function verifyTonProof({
  telegramUser,
  address,
  network,
  publicKey,
  walletStateInit,
  proof,
}) {
  const userId =
    Number(
      telegramUser.id
    );

  if (
    String(
      network
    ) !==
    String(
      TON_NETWORK
    )
  ) {
    throw new Error(
      "Wrong TON network."
    );
  }

  if (
    !proof ||
    typeof proof !==
      "object"
  ) {
    throw new Error(
      "TON proof missing."
    );
  }

  const proofPayload =
    String(
      proof.payload ||
      ""
    );

  const proofDomain =
    String(
      proof.domain
        ?.value ||
      ""
    );

  const proofDomainLength =
    Number(
      proof.domain
        ?.lengthBytes
    );

  const proofTimestamp =
    Number(
      proof.timestamp
    );

  const signatureBase64 =
    String(
      proof.signature ||
      ""
    );

  if (
    !proofPayload ||
    !signatureBase64
  ) {
    throw new Error(
      "Incomplete TON proof."
    );
  }

  if (
    proofDomain !==
    TON_PROOF_DOMAIN
  ) {
    throw new Error(
      "TON proof domain mismatch."
    );
  }

  if (
    !proofDomain.includes(
      "."
    )
  ) {
    throw new Error(
      "Invalid TON proof domain."
    );
  }

  if (
    proofDomainLength !==
    Buffer.byteLength(
      proofDomain,
      "utf8"
    )
  ) {
    throw new Error(
      "Invalid TON proof domain length."
    );
  }

  if (
    !Number.isSafeInteger(
      proofTimestamp
    ) ||
    proofTimestamp <=
      0
  ) {
    throw new Error(
      "Invalid TON proof timestamp."
    );
  }

  const now =
    Math.floor(
      Date.now() /
        1000
    );

  if (
    proofTimestamp >
      now +
        60 ||
    now -
      proofTimestamp >
        TON_PROOF_TTL_SECONDS
  ) {
    throw new Error(
      "TON proof expired."
    );
  }

  const walletAddress =
    Address.parse(
      String(
        address
      )
    );

  const normalizedAddress =
    walletAddress.toString({
      bounceable:
        false,

      testOnly:
        false,
    });

  const stateInit =
    parseWalletStateInit(
      walletStateInit
    );

  const derivedAddress =
    contractAddress(
      walletAddress.workChain,
      stateInit
    );

  if (
    !derivedAddress.equals(
      walletAddress
    )
  ) {
    throw new Error(
      "Wallet state init does not match wallet address."
    );
  }

  const extracted =
    extractWalletPublicKey(
      stateInit
    );

  if (
    !extracted
  ) {
    throw new Error(
      "Unsupported TON wallet contract."
    );
  }

  const suppliedPublicKey =
    String(
      publicKey ||
      ""
    )
      .replace(
        /^0x/i,
        ""
      )
      .toLowerCase();

  if (
    !/^[a-f0-9]{64}$/.test(
      suppliedPublicKey
    )
  ) {
    throw new Error(
      "Invalid TON public key."
    );
  }

  const suppliedPublicKeyBuffer =
    Buffer.from(
      suppliedPublicKey,
      "hex"
    );

  if (
    !crypto.timingSafeEqual(
      suppliedPublicKeyBuffer,
      extracted.publicKey
    )
  ) {
    throw new Error(
      "TON public key mismatch."
    );
  }

  const signature =
    Buffer.from(
      signatureBase64,
      "base64"
    );

  if (
    signature.length !==
    64
  ) {
    throw new Error(
      "Invalid TON signature."
    );
  }

  const signedHash =
    createTonProofMessageHash({
      address:
        String(
          address
        ),

      domain:
        proofDomain,

      timestamp:
        proofTimestamp,

      payload:
        proofPayload,
    });

  const signatureValid =
    nacl.sign.detached.verify(
      new Uint8Array(
        signedHash
      ),

      new Uint8Array(
        signature
      ),

      new Uint8Array(
        extracted.publicKey
      )
    );

  if (
    !signatureValid
  ) {
    throw new Error(
      "TON proof signature is invalid."
    );
  }

  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    const challenge =
      (
        await client.query(
          `
            SELECT *

            FROM ton_proof_challenges

            WHERE nonce = $1

            LIMIT 1

            FOR UPDATE
          `,
          [
            proofPayload,
          ]
        )
      ).rows[0];

    if (
      !challenge
    ) {
      throw new Error(
        "TON proof challenge not found."
      );
    }

    if (
      Number(
        challenge.telegram_user_id
      ) !==
      userId
    ) {
      throw new Error(
        "TON proof challenge belongs to another user."
      );
    }

    if (
      challenge.used_at
    ) {
      throw new Error(
        "TON proof challenge was already used."
      );
    }

    if (
      new Date(
        challenge.expires_at
      ).getTime() <=
      Date.now()
    ) {
      throw new Error(
        "TON proof challenge expired."
      );
    }

    if (
      String(
        challenge.domain
      ) !==
      TON_PROOF_DOMAIN
    ) {
      throw new Error(
        "TON proof challenge domain mismatch."
      );
    }

    await upsertUser(
      client,
      telegramUser
    );

    await client.query(
      `
        UPDATE users

        SET
          ton_wallet_address =
            $2,

          ton_wallet_public_key =
            $3,

          ton_wallet_chain =
            $4,

          ton_wallet_verified_at =
            NOW(),

          updated_at =
            NOW()

        WHERE telegram_id = $1
      `,
      [
        userId,

        normalizedAddress,

        extracted.publicKey.toString(
          "hex"
        ),

        Number(
          network
        ),
      ]
    );

    await client.query(
      `
        UPDATE ton_proof_challenges

        SET
          used_at =
            NOW()

        WHERE id = $1
      `,
      [
        challenge.id,
      ]
    );

    const updatedPayouts =
      await refreshWinnerPayoutWallet(
        client,
        userId
      );

    await audit(
      client,
      "ton_wallet_verified",
      userId,
      null,
      {
        address:
          normalizedAddress,

        network:
          String(
            network
          ),

        walletType:
          extracted.walletType,

        updatedPayouts,
      }
    );

    await client.query(
      "COMMIT"
    );

    return {
      verified:
        true,

      address:
        normalizedAddress,

      network:
        String(
          network
        ),

      walletType:
        extracted.walletType,

      updatedPayouts,
    };
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   REFERRAL FROM TELEGRAM START PARAM
========================================================= */

async function attachStartReferral(
  telegramUser,
  startParam
) {
  if (
    !startParam ||
    typeof startParam !==
      "string"
  ) {
    return;
  }

  const code =
    startParam
      .trim()
      .slice(
        0,
        100
      );

  if (
    !code
  ) {
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
      telegramUser
    );

    const phase =
      await getCurrentPhase(
        client
      );

    await attachReferralCode(
      client,
      Number(
        telegramUser.id
      ),
      phase.id,
      code
    );

    await client.query(
      "COMMIT"
    );
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    console.error(
      "Start referral attach failed:",
      error.message
    );
  } finally {
    client.release();
  }
}

/* =========================================================
   PUBLIC ROUTES
========================================================= */

app.get(
  "/",
  (
    req,
    res
  ) => {
    res.json({
      name:
        "Project Z",

      status:
        "online",

      payments:
        PAYMENTS_ENABLED,

      entryStars:
        ENTRY_STARS,

      automaticSettlement:
        AUTOMATIC_SETTLEMENT_ENABLED,
    });
  }
);

app.get(
  "/health",
  async (
    req,
    res
  ) => {
    try {
      await pool.query(
        "SELECT 1"
      );

      res.json({
        ok:
          true,

        service:
          "Project Z",

        database:
          true,

        paymentsEnabled:
          PAYMENTS_ENABLED,

        paymentsReady:
          PAYMENTS_ENABLED &&
          missingPaymentEnv.length ===
            0,

        missingPaymentEnv,

        botUsername:
          runtimeBotUsername ||
          null,

        entryStars:
          ENTRY_STARS,

        starUsdRate:
          STAR_USD_RATE,

        phaseDate:
          getMoscowDateString(),

        tonNetwork:
          TON_NETWORK,

        tonProofDomain:
          TON_PROOF_DOMAIN,

        treasuryAddress:
          TREASURY_WALLET_ADDRESS,

        usdtJettonMaster:
          USDT_JETTON_MASTER,

        automaticSettlement:
          AUTOMATIC_SETTLEMENT_ENABLED,
      });
    } catch (
      error
    ) {
      res
        .status(
          503
        )
        .json({
          ok:
            false,

          database:
            false,

          error:
            "Database unavailable.",
        });
    }
  }
);

app.get(
  "/api/stats",
  async (
    req,
    res,
    next
  ) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      let phase =
        await getCurrentPhase(
          client
        );

      phase =
        await refreshPhaseTotals(
          client,
          phase.id
        );
      const participantRows =
  (
    await client.query(
      `
        SELECT
          u.display_name,
          u.username

        FROM entries e

        LEFT JOIN users u
          ON u.telegram_id =
            e.telegram_user_id

        WHERE e.phase_id = $1

        ORDER BY
          e.created_at DESC

        LIMIT 6
      `,
      [
        phase.id,
      ]
    )
  ).rows;

      await client.query(
        "COMMIT"
      );

      res.json({
        phaseId:
          Number(
            phase.id
          ),

        phaseDate:
          toDateOnlyString(
            phase.phase_date
          ),

        status:
          phase.status,

        totalStars:
          Number(
            phase.total_stars ||
            0
          ),

        grossUsd:
          Number(
            phase.gross_usd ||
            0
          ),

        winnerPoolUsd:
          Number(
            phase.winner_pool_usd ||
            0
          ),

        charityUsd:
          Number(
            phase.charity_usd ||
            0
          ),

        operationsUsd:
          Number(
            phase.operations_usd ||
            0
          ),

        entries:
          Number(
            phase.entry_count ||
            0
          ),

        paidEntries:
          Number(
            phase.paid_entry_count ||
            0
          ),

        freeEntries:
          Number(
            phase.free_entry_count ||
            0
          ),

        winnerCount:
          Number(
            phase.winner_count ||
            0
          ),

        entryStars:
          ENTRY_STARS,

        entryUsdDisplay:
          ENTRY_USD_DISPLAY,
        participantList:
  participantRows.map(
    (participant) => ({
      displayName:
        participant.display_name ||
        (
          participant.username
            ? `@${participant.username}`
            : "Participant"
        ),
    })
  ),

        drawCommitHash:
          phase.draw_commit_hash ||
          null,
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      next(
        error
      );
    } finally {
      client.release();
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
      const requestedPhaseId =
        Number(
          req.query
            ?.phaseId ||
            0
        );

      let phase =
        null;

      if (
        Number.isSafeInteger(
          requestedPhaseId
        ) &&
        requestedPhaseId >
          0
      ) {
        phase =
          (
            await pool.query(
              `
                SELECT *

                FROM phases

                WHERE id = $1

                LIMIT 1
              `,
              [
                requestedPhaseId,
              ]
            )
          ).rows[0];
      } else {
        phase =
          (
            await pool.query(
              `
                SELECT *

                FROM phases

                WHERE status =
                  'finalized'

                ORDER BY
                  phase_date DESC

                LIMIT 1
              `
            )
          ).rows[0];
      }

      if (
        !phase
      ) {
        return res.json({
          phase:
            null,

          winners: [],
        });
      }

      const winners =
        (
          await pool.query(
            `
              SELECT
                w.rank,

                w.telegram_user_id,

                w.prize_usd,

                w.is_first_payer,

                w.created_at,

                u.display_name,

                u.username

              FROM winners w

              LEFT JOIN users u
                ON u.telegram_id =
                  w.telegram_user_id

              WHERE w.phase_id = $1

              ORDER BY
                w.rank ASC
            `,
            [
              phase.id,
            ]
          )
        ).rows;

      res.json({
        phase: {
          id:
            Number(
              phase.id
            ),

          date:
            toDateOnlyString(
              phase.phase_date
            ),

          status:
            phase.status,

          drawCommitHash:
            phase.draw_commit_hash ||
            null,

          drawReveal:
            phase.draw_reveal ||
            null,

          finalizedAt:
            phase.finalized_at ||
            null,
        },

        winners:
          winners.map(
            (winner) => ({
              rank:
                Number(
                  winner.rank
                ),

              displayName:
                winner.display_name ||
                (
                  winner.username
                    ? `@${winner.username}`
                    : "Project Z User"
                ),

              prizeUsd:
                Number(
                  winner.prize_usd ||
                  0
                ),

              isFirstPayer:
                Boolean(
                  winner.is_first_payer
                ),

              createdAt:
                winner.created_at,
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
   AUTHENTICATED USER ROUTES
========================================================= */

app.all(
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

    if (
      !verified
    ) {
      return;
    }

    if (
      verified.startParam
    ) {
      await attachStartReferral(
        verified.user,
        verified.startParam
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
        verified.user
      );

      const phase =
        await getCurrentPhase(
          client
        );

      const status =
        await getUserPhaseStatus(
          client,
          Number(
            verified.user.id
          ),
          phase
        );

      await client.query(
        "COMMIT"
      );

      res.json(
        status
      );
    } catch (
      error
    ) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      next(
        error
      );
    } finally {
      client.release();
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

    if (
      !verified
    ) {
      return;
    }

    const code =
      String(
        req.body
          ?.code ||
        ""
      );

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
        await getCurrentPhase(
          client
        );

      const result =
        await attachReferralCode(
          client,
          Number(
            verified.user.id
          ),
          phase.id,
          code
        );

      await client.query(
        "COMMIT"
      );

      res.json(
        result
      );
    } catch (
      error
    ) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

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

    if (
      !verified
    ) {
      return;
    }

    try {
      if (
        verified.startParam
      ) {
        await attachStartReferral(
          verified.user,
          verified.startParam
        );
      }

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

    if (
      !verified
    ) {
      return;
    }

    try {
      const result =
        await claimFreeEntry(
          verified.user
        );

      res
        .status(
          result.ok
            ? 200
            : 409
        )
        .json(
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
  "/api/support/message",
  supportLimiter,
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

    if (
      !verified
    ) {
      return;
    }

    const message =
      String(
        req.body
          ?.message ||
        ""
      ).trim();

    if (
      message.length < 3 ||
      message.length > 2000
    ) {
      return res
        .status(400)
        .json({
          ok: false,
          error:
            "Support message must be between 3 and 2000 characters.",
        });
    }

    try {
      const result =
        await createSupportTicket(
          verified.user,
          message
        );

      res.json({
        ok: true,
        ticketId:
          result.ticketId,
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
   TON CONNECT ROUTES
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

    if (
      !verified
    ) {
      return;
    }

    try {
      const challenge =
        await createTonProofChallenge(
          Number(
            verified.user.id
          )
        );

      res.json({
        payload:
          challenge.nonce,

        domain:
          TON_PROOF_DOMAIN,

        expiresAt:
          challenge.expires_at,

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

    if (
      !verified
    ) {
      return;
    }

    try {
      const result =
        await verifyTonProof({
          telegramUser:
            verified.user,

          address:
            req.body
              ?.address,

          network:
            req.body
              ?.network,

          publicKey:
            req.body
              ?.publicKey,

          walletStateInit:
            req.body
              ?.walletStateInit ||
            req.body
              ?.stateInit,

          proof:
            req.body
              ?.proof,
        });

      res.json(
        result
      );
    } catch (
      error
    ) {
      res
        .status(
          400
        )
        .json({
          verified:
            false,

          error:
            error.message,
        });
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
    const receivedSecret =
      req.headers[
        "x-telegram-bot-api-secret-token"
      ];

    if (
      !TELEGRAM_WEBHOOK_SECRET ||
      typeof receivedSecret !==
        "string" ||
      !timingSafeEqualText(
        receivedSecret,
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

    /*
      Telegram may retry webhook updates.
      All financial handlers below are idempotent.
    */
    try {
      const update =
        req.body ||
        {};
      if (
  update.message
) {
  const handledSupport =
    await handleSupportTelegramMessage(
      update.message
    );

  if (
    handledSupport
  ) {
    return res.json({
      ok: true,
    });
  }
}

      if (
        update.pre_checkout_query
      ) {
        await handlePreCheckoutQuery(
          update.pre_checkout_query
        );
      }

      if (
        update.message
          ?.successful_payment
      ) {
        await handleSuccessfulPayment(
          update.message
        );
      }

      return res.json({
        ok:
          true,
      });
    } catch (
      error
    ) {
      console.error(
        "Telegram webhook processing error:",
        error.message
      );

      /*
        Returning 500 intentionally allows Telegram
        to retry an update that was not safely processed.
      */
      return res
        .status(
          500
        )
        .json({
          ok:
            false,
        });
    }
  }
);
/* =========================================================
   ADMIN AUTH
========================================================= */

function requireAdmin(
  req,
  res
) {
  if (
    !ADMIN_SECRET
  ) {
    res
      .status(
        503
      )
      .json({
        error:
          "Admin access is not configured.",
      });

    return false;
  }

  const suppliedSecret =
    req.headers[
      "x-admin-secret"
    ];

  if (
    typeof suppliedSecret !==
      "string" ||
    !timingSafeEqualText(
      suppliedSecret,
      ADMIN_SECRET
    )
  ) {
    res
      .status(
        401
      )
      .json({
        error:
          "Unauthorized.",
      });

    return false;
  }

  return true;
}

/* =========================================================
   ADMIN — TELEGRAM STARS BALANCE
========================================================= */

app.get(
  "/api/admin/stars-balance",
  async (
    req,
    res,
    next
  ) => {
    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }

    try {
      const balance =
        await telegramApi(
          "getMyStarBalance"
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

/* =========================================================
   ADMIN — PAYOUT QUEUE
========================================================= */

app.get(
  "/api/admin/payouts",
  async (
    req,
    res,
    next
  ) => {
    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }

    try {
      const status =
        req.query
          ?.status
          ? String(
              req.query.status
            )
          : null;

      const limit =
        clampInt(
          req.query
            ?.limit ||
            100,
          1,
          500
        );

      const payouts =
        await getPayoutQueue({
          status,
          limit,
        });

      res.json({
        ok:
          true,

        automaticSettlement:
          AUTOMATIC_SETTLEMENT_ENABLED,

        settlementAsset:
          "USDT_TON",

        count:
          payouts.length,

        payouts,
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
   ADMIN — REFUND / RECONCILIATION QUEUE
========================================================= */

app.get(
  "/api/admin/refunds",
  async (
    req,
    res,
    next
  ) => {
    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }

    try {
      const limit =
        clampInt(
          req.query
            ?.limit ||
            100,
          1,
          500
        );

      const result =
        await pool.query(
          `
            SELECT
              id,
              telegram_payment_charge_id,
              telegram_user_id,
              invoice_payload,
              currency,
              stars_amount,
              reason,
              status,
              attempts,
              last_error,
              created_at,
              updated_at

            FROM payment_reconciliations

            ORDER BY id DESC

            LIMIT $1
          `,
          [
            limit,
          ]
        );

      res.json({
        ok:
          true,

        count:
          result.rows.length,

        refunds:
          result.rows,
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
   ADMIN — RETRY REFUND QUEUE
========================================================= */

app.post(
  "/api/admin/refunds/run",
  async (
    req,
    res,
    next
  ) => {
    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }

    try {
      const maxItems =
        clampInt(
          req.body
            ?.maxItems ||
            20,
          1,
          100
        );

      await runRefundWorker(
        maxItems
      );

      res.json({
        ok:
          true,
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
   ADMIN — MARK PAYOUT PAID
========================================================= */

app.post(
  "/api/admin/payouts/:id/mark-paid",
  async (
    req,
    res,
    next
  ) => {
    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }

    const payoutId =
      Number(
        req.params.id
      );

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

    const txHash =
      String(
        req.body
          ?.txHash ||
        ""
      )
        .trim()
        .slice(
          0,
          256
        );

    const settlementReference =
      String(
        req.body
          ?.settlementReference ||
        txHash ||
        ""
      )
        .trim()
        .slice(
          0,
          256
        );

    if (
      !txHash &&
      !settlementReference
    ) {
      return res
        .status(
          400
        )
        .json({
          error:
            "A confirmed settlement reference or transaction hash is required.",
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const payout =
        (
          await client.query(
            `
              SELECT *

              FROM payouts

              WHERE id = $1

              FOR UPDATE
            `,
            [
              payoutId,
            ]
          )
        ).rows[0];

      if (
        !payout
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res
          .status(
            404
          )
          .json({
            error:
              "Payout not found.",
          });
      }

      if (
        payout.status ===
        "paid"
      ) {
        await client.query(
          "COMMIT"
        );

        return res.json({
          ok:
            true,

          alreadyPaid:
            true,

          payout,
        });
      }

      if (
        ![
          "pending",
          "processing",
          "failed",
        ].includes(
          payout.status
        )
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res
          .status(
            409
          )
          .json({
            error:
              `Payout cannot be marked paid from status: ${payout.status}`,
          });
      }

      const updated =
        (
          await client.query(
            `
              UPDATE payouts

              SET
                status =
                  'paid',

                ton_tx_hash =
                  $2,

                settlement_reference =
                  $3,

                telegram_transaction_id =
                  COALESCE(
                    telegram_transaction_id,
                    $3
                  ),

                failure_reason =
                  NULL,

                paid_at =
                  NOW()

              WHERE id = $1

              RETURNING *
            `,
            [
              payoutId,

              txHash ||
                null,

              settlementReference,
            ]
          )
        ).rows[0];

      await audit(
        client,
        "payout_marked_paid",
        null,
        payout.phase_id,
        {
          payoutId,

          winnerId:
            Number(
              payout.winner_id
            ),

          telegramUserId:
            Number(
              payout.telegram_user_id
            ),

          prizeUsd:
            Number(
              payout.prize_usd ||
              0
            ),

          transactionHash:
            txHash ||
            null,

          settlementReference,
        }
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok:
          true,

        payout:
          updated,
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      next(
        error
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN — MARK PAYOUT FAILED
========================================================= */

app.post(
  "/api/admin/payouts/:id/mark-failed",
  async (
    req,
    res,
    next
  ) => {
    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }

    const payoutId =
      Number(
        req.params.id
      );

    const failureReason =
      String(
        req.body
          ?.reason ||
        "Settlement failed"
      )
        .trim()
        .slice(
          0,
          500
        );

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

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const payout =
        (
          await client.query(
            `
              SELECT *

              FROM payouts

              WHERE id = $1

              FOR UPDATE
            `,
            [
              payoutId,
            ]
          )
        ).rows[0];

      if (
        !payout
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res
          .status(
            404
          )
          .json({
            error:
              "Payout not found.",
          });
      }

      if (
        payout.status ===
        "paid"
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res
          .status(
            409
          )
          .json({
            error:
              "A paid payout cannot be marked failed.",
          });
      }

      const updated =
        (
          await client.query(
            `
              UPDATE payouts

              SET
                status =
                  'failed',

                failure_reason =
                  $2,

                processing_at =
                  NULL

              WHERE id = $1

              RETURNING *
            `,
            [
              payoutId,
              failureReason,
            ]
          )
        ).rows[0];

      await audit(
        client,
        "payout_marked_failed",
        null,
        payout.phase_id,
        {
          payoutId,

          failureReason,
        }
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok:
          true,

        payout:
          updated,
      });
    } catch (
      error
    ) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      next(
        error
      );
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN — MANUAL PHASE FINALIZATION
========================================================= */

app.post(
  "/api/admin/finalize/:phaseId",
  async (
    req,
    res,
    next
  ) => {
    if (
      !requireAdmin(
        req,
        res
      )
    ) {
      return;
    }

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

    try {
      const result =
        await finalizePhaseById(
          phaseId,
          {
            allowCurrent:
              req.body
                ?.allowCurrent ===
              true,
          }
        );

      res
        .status(
          result.ok
            ? 200
            : 409
        )
        .json(
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

/* =========================================================
   EXPIRED TON CHALLENGE CLEANUP
========================================================= */

let challengeCleanupRunning =
  false;

async function cleanupTonChallenges() {
  if (
    challengeCleanupRunning
  ) {
    return;
  }

  challengeCleanupRunning =
    true;

  try {
    await pool.query(
      `
        DELETE FROM ton_proof_challenges

        WHERE
          expires_at <
            NOW() -
            INTERVAL '1 day'

          OR (
            used_at IS NOT NULL
            AND used_at <
              NOW() -
              INTERVAL '1 day'
          )
      `
    );
  } catch (
    error
  ) {
    console.error(
      "TON challenge cleanup failed:",
      error.message
    );
  } finally {
    challengeCleanupRunning =
      false;
  }
}

/* =========================================================
   PERIODIC WORKERS
========================================================= */

const workerIntervals =
  [];

function startWorkers() {
  /*
    Refunds are intentionally frequent because a user
    should not wait long if an unexpected Stars payment
    needs to be returned.
  */
  workerIntervals.push(
    setInterval(
      () => {
        runRefundWorker(
          20
        ).catch(
          (error) => {
            console.error(
              "Refund interval error:",
              error.message
            );
          }
        );
      },
      15_000
    )
  );

  /*
    Any Moscow-date phase from a previous day
    is automatically finalized.
  */
  workerIntervals.push(
    setInterval(
      () => {
        finalizePastPhases().catch(
          (error) => {
            console.error(
              "Finalization interval error:",
              error.message
            );
          }
        );
      },
      30_000
    )
  );

  workerIntervals.push(
    setInterval(
      () => {
        cleanupTonChallenges().catch(
          (error) => {
            console.error(
              "Challenge cleanup interval error:",
              error.message
            );
          }
        );
      },
      10 * 60_000
    )
  );

  for (
    const interval of
    workerIntervals
  ) {
    interval.unref?.();
  }

  console.log(
    "Background workers started."
  );
}

/* =========================================================
   404
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

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled request error:",
      error
        ?.stack ||
      error
        ?.message ||
      error
    );

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    res
      .status(
        500
      )
      .json({
        error:
          "Internal server error.",
      });
  }
);

/* =========================================================
   STARTUP
========================================================= */

let server =
  null;

let shuttingDown =
  false;

async function prepareCurrentPhase() {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    let phase =
      await getCurrentPhase(
        client
      );

    phase =
      await refreshPhaseTotals(
        client,
        phase.id
      );

    await client.query(
      "COMMIT"
    );

    console.log(
      `Current Moscow phase ready: ${toDateOnlyString(
        phase.phase_date
      )}`
    );

    return phase;
  } catch (
    error
  ) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

async function start() {
  console.log(
    "Starting Project Z..."
  );

  if (
    !DATABASE_URL
  ) {
    throw new Error(
      "DATABASE_URL missing"
    );
  }

  await pool.query(
    "SELECT 1"
  );

  console.log(
    "Database connection: ready"
  );

  await initDb();
await mysteryScheduler.ensureSchema();
  await prepareCurrentPhase();

  /*
    Catch up previous days before accepting traffic.
  */
  await finalizePastPhases();

  /*
    Process any refund left from a previous restart.
  */
  await runRefundWorker(
    50
  );

  /*
    Resolve the real bot username from Telegram.
    This avoids relying only on an environment variable
    for referral links.
  */
  const botIdentity =
    await resolveBotIdentity();

  if (
    BOT_TOKEN &&
    !botIdentity
  ) {
    console.warn(
      "Bot identity could not be verified at startup."
    );
  }

  const webhookReady =
    await ensureWebhook();

  console.log(
    `Telegram webhook configured: ${webhookReady}`
  );

  console.log(
    `Payments enabled: ${PAYMENTS_ENABLED}`
  );

  console.log(
    `Payments ready: ${
      PAYMENTS_ENABLED &&
      missingPaymentEnv.length ===
        0
    }`
  );

  console.log(
    `Entry price: ${ENTRY_STARS} Stars`
  );

  console.log(
    `TON Proof domain: ${TON_PROOF_DOMAIN}`
  );

  console.log(
    `Settlement asset: USDT on TON`
  );

  console.log(
    `Automatic on-chain settlement: ${AUTOMATIC_SETTLEMENT_ENABLED}`
  );

  server =
    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Project Z running on 0.0.0.0:${PORT}`
        );
      }
    );

  startWorkers();
  mysteryScheduler.start();
}


/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

async function shutdown(
  signal
) {
  if (
    shuttingDown
  ) {
    return;
  }

  shuttingDown =
    true;

  console.log(
    `Shutdown requested: ${signal}`
  );

  for (
    const interval of
    workerIntervals
  ) {
    clearInterval(
      interval
    );
  }

  try {
    if (
      server
    ) {
      await new Promise(
        (
          resolve
        ) => {
          server.close(
            () =>
              resolve()
          );

          setTimeout(
            resolve,
            10_000
          ).unref?.();
        }
      );
    }
  } catch (
    error
  ) {
    console.error(
      "HTTP shutdown error:",
      error.message
    );
  }

  try {
    mysteryScheduler.stop();
    await pool.end();
  } catch (
    error
  ) {
    console.error(
      "Database shutdown error:",
      error.message
    );
  }

  console.log(
    "Project Z stopped."
  );

  process.exit(
    0
  );
}

process.on(
  "SIGTERM",
  () => {
    shutdown(
      "SIGTERM"
    );
  }
);

process.on(
  "SIGINT",
  () => {
    shutdown(
      "SIGINT"
    );
  }
);

process.on(
  "unhandledRejection",
  (
    reason
  ) => {
    console.error(
      "Unhandled promise rejection:",
      reason
    );
  }
);

process.on(
  "uncaughtException",
  (
    error
  ) => {
    console.error(
      "Uncaught exception:",
      error
    );

    shutdown(
      "uncaughtException"
    );
  }
);

/* =========================================================
   BOOT
========================================================= */

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
