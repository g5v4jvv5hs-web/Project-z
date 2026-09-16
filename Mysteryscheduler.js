import crypto from "crypto";
import { MYSTERY_MESSAGES } from "./Mysterymassage.js";

const FIRST_WINDOW = Object.freeze({
  start: 9 * 60,
  end: 15 * 60 + 30,
});

const SECOND_WINDOW = Object.freeze({
  start: 17 * 60 + 30,
  end: 23 * 60 + 30,
});

const MOSCOW_UTC_OFFSET = "+03:00";
const MESSAGE_STEP = 137;

function randomInt(min, max) {
  return crypto.randomInt(min, max + 1);
}

function addDays(day, count) {
  const date = new Date(`${day}T12:00:00Z`);
  date.setUTCDate(date.getUTCDate() + count);
  return date.toISOString().slice(0, 10);
}

function toDayString(value) {
  if (!value) {
    return null;
  }

  if (value instanceof Date) {
    return value.toISOString().slice(0, 10);
  }

  return String(value).slice(0, 10);
}

function getZonedParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat(
    "en-CA",
    {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    }
  ).formatToParts(date);

  const values = Object.fromEntries(
    parts
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, part.value])
  );

  return {
    day:
      `${values.year}-` +
      `${values.month}-` +
      `${values.day}`,
    minuteOfDay:
      Number(values.hour) * 60 +
      Number(values.minute),
  };
}

function dateAtMoscowMinute(day, minuteOfDay) {
  const hour = Math.floor(minuteOfDay / 60);
  const minute = minuteOfDay % 60;

  return new Date(
    `${day}T` +
    `${String(hour).padStart(2, "0")}:` +
    `${String(minute).padStart(2, "0")}:00` +
    MOSCOW_UTC_OFFSET
  );
}

function chooseInWindow(
  day,
  window,
  minMinute = window.start
) {
  const lower = Math.max(
    window.start,
    minMinute
  );

  if (lower > window.end) {
    return null;
  }

  const minute = randomInt(
    lower,
    window.end
  );

  return dateAtMoscowMinute(
    day,
    minute
  );
}

function initialSchedule(
  now,
  timeZone
) {
  const current = getZonedParts(
    now,
    timeZone
  );

  const minimum =
    current.minuteOfDay + 20;

  if (minimum <= FIRST_WINDOW.end) {
    const at = chooseInWindow(
      current.day,
      FIRST_WINDOW,
      minimum
    );

    if (at) {
      return {
        day: current.day,
        slot: 1,
        at,
      };
    }
  }

  if (minimum <= SECOND_WINDOW.end) {
    const at = chooseInWindow(
      current.day,
      SECOND_WINDOW,
      minimum
    );

    if (at) {
      return {
        day: current.day,
        slot: 2,
        at,
      };
    }
  }

  const nextDay = addDays(
    current.day,
    1
  );

  return {
    day: nextDay,
    slot: 1,
    at: chooseInWindow(
      nextDay,
      FIRST_WINDOW
    ),
  };
}

function nextSchedule(
  scheduleDay,
  deliveredSlot,
  now,
  timeZone
) {
  const current = getZonedParts(
    now,
    timeZone
  );

  const day =
    toDayString(scheduleDay) ||
    current.day;

  if (
    Number(deliveredSlot) === 1 &&
    current.day === day
  ) {
    const minimum = Math.max(
      SECOND_WINDOW.start,
      current.minuteOfDay + 60
    );

    const at = chooseInWindow(
      day,
      SECOND_WINDOW,
      minimum
    );

    if (at) {
      return {
        day,
        slot: 2,
        at,
      };
    }
  }

  const baseDay =
    current.day > day
      ? current.day
      : day;

  const tomorrow = addDays(
    baseDay,
    1
  );

  return {
    day: tomorrow,
    slot: 1,
    at: chooseInWindow(
      tomorrow,
      FIRST_WINDOW
    ),
  };
}

function isPermanentTelegramFailure(
  error
) {
  const text = String(
    error?.message ||
    error ||
    ""
  ).toLowerCase();

  return (
    text.includes("bot was blocked") ||
    text.includes("chat not found") ||
    text.includes("user is deactivated") ||
    text.includes("forbidden")
  );
}

export function createMysteryScheduler({
  pool,
  telegramApi,
  timeZone = "Europe/Moscow",
}) {
  if (!pool) {
    throw new Error(
      "Mystery scheduler requires pool"
    );
  }

  if (
    typeof telegramApi !==
    "function"
  ) {
    throw new Error(
      "Mystery scheduler requires telegramApi"
    );
  }

  let running = false;
  let interval = null;

  async function ensureSchema() {
    await pool.query(
      `
        CREATE TABLE IF NOT EXISTS
          mystery_subscribers (
            telegram_user_id
              BIGINT
              PRIMARY KEY,

            chat_id
              BIGINT
              NOT NULL
              UNIQUE,

            enabled
              BOOLEAN
              NOT NULL
              DEFAULT TRUE,

            schedule_day
              DATE
              NOT NULL,

            next_slot
              SMALLINT
              NOT NULL
              CHECK (
                next_slot IN (1, 2)
              ),

            next_message_at
              TIMESTAMPTZ
              NOT NULL,

            message_offset
              INTEGER
              NOT NULL
              DEFAULT 0
              CHECK (
                message_offset >= 0
                AND
                message_offset < 500
              ),

            messages_sent_total
              BIGINT
              NOT NULL
              DEFAULT 0,

            last_sent_at
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

        CREATE INDEX IF NOT EXISTS
          idx_mystery_due
          ON mystery_subscribers(
            enabled,
            next_message_at
          );
      `
    );
  }

  async function subscribe(message) {
    const telegramUserId =
      Number(message?.from?.id);

    const chatId =
      Number(message?.chat?.id);

    if (
      !Number.isSafeInteger(
        telegramUserId
      ) ||
      !Number.isSafeInteger(
        chatId
      )
    ) {
      throw new Error(
        "Invalid Telegram subscriber"
      );
    }

    if (
      message?.chat?.type &&
      message.chat.type !== "private"
    ) {
      return false;
    }

    const schedule =
      initialSchedule(
        new Date(),
        timeZone
      );

    const offset =
      randomInt(
        0,
        MYSTERY_MESSAGES.length - 1
      );

    await pool.query(
      `
        INSERT INTO
          mystery_subscribers (
            telegram_user_id,
            chat_id,
            enabled,
            schedule_day,
            next_slot,
            next_message_at,
            message_offset,
            updated_at
          )
        VALUES (
          $1,
          $2,
          TRUE,
          $3::date,
          $4,
          $5,
          $6,
          NOW()
        )

        ON CONFLICT (
          telegram_user_id
        )

        DO UPDATE SET
          chat_id =
            EXCLUDED.chat_id,

          enabled =
            TRUE,

          schedule_day =
            CASE
              WHEN
                mystery_subscribers.enabled =
                  FALSE
                OR
                mystery_subscribers.next_message_at <=
                  NOW()
              THEN
                EXCLUDED.schedule_day
              ELSE
                mystery_subscribers.schedule_day
            END,

          next_slot =
            CASE
              WHEN
                mystery_subscribers.enabled =
                  FALSE
                OR
                mystery_subscribers.next_message_at <=
                  NOW()
              THEN
                EXCLUDED.next_slot
              ELSE
                mystery_subscribers.next_slot
            END,

          next_message_at =
            CASE
              WHEN
                mystery_subscribers.enabled =
                  FALSE
                OR
                mystery_subscribers.next_message_at <=
                  NOW()
              THEN
                EXCLUDED.next_message_at
              ELSE
                mystery_subscribers.next_message_at
            END,

          updated_at =
            NOW()
      `,
      [
        telegramUserId,
        chatId,
        schedule.day,
        schedule.slot,
        schedule.at,
        offset,
      ]
    );

    return true;
  }

  async function unsubscribe(message) {
    const telegramUserId =
      Number(message?.from?.id);

    if (
      !Number.isSafeInteger(
        telegramUserId
      )
    ) {
      return false;
    }

    await pool.query(
      `
        UPDATE
          mystery_subscribers

        SET
          enabled = FALSE,
          updated_at = NOW()

        WHERE
          telegram_user_id = $1
      `,
      [
        telegramUserId,
      ]
    );

    return true;
  }

  async function runDue(
    limit = 50
  ) {
    if (running) {
      return;
    }

    running = true;

    try {
      const result =
        await pool.query(
          `
            SELECT
              telegram_user_id,
              chat_id,
              schedule_day,
              next_slot,
              message_offset,
              messages_sent_total

            FROM
              mystery_subscribers

            WHERE
              enabled = TRUE
              AND
              next_message_at <= NOW()

            ORDER BY
              next_message_at ASC

            LIMIT $1
          `,
          [
            Math.max(
              1,
              Math.min(
                200,
                Number(limit) || 50
              )
            ),
          ]
        );

      for (
        const row of
        result.rows
      ) {
        const sentTotal =
          Number(
            row.messages_sent_total ||
            0
          );

        const offset =
          Number(
            row.message_offset ||
            0
          );

        const messageIndex =
          (
            offset +
            sentTotal * MESSAGE_STEP
          ) %
          MYSTERY_MESSAGES.length;

        try {
          await telegramApi(
            "sendMessage",
            {
              chat_id:
                String(row.chat_id),

              text:
                MYSTERY_MESSAGES[
                  messageIndex
                ],
            }
          );
        } catch (error) {
          if (
            isPermanentTelegramFailure(
              error
            )
          ) {
            await pool.query(
              `
                UPDATE
                  mystery_subscribers

                SET
                  enabled = FALSE,
                  updated_at = NOW()

                WHERE
                  telegram_user_id = $1
              `,
              [
                row.telegram_user_id,
              ]
            );
          } else {
            await pool.query(
              `
                UPDATE
                  mystery_subscribers

                SET
                  next_message_at =
                    NOW() +
                    INTERVAL '30 minutes',

                  updated_at = NOW()

                WHERE
                  telegram_user_id = $1
              `,
              [
                row.telegram_user_id,
              ]
            );
          }

          continue;
        }

        const next =
          nextSchedule(
            row.schedule_day,
            row.next_slot,
            new Date(),
            timeZone
          );

        await pool.query(
          `
            UPDATE
              mystery_subscribers

            SET
              schedule_day = $2::date,
              next_slot = $3,
              next_message_at = $4,

              messages_sent_total =
                messages_sent_total + 1,

              last_sent_at = NOW(),
              updated_at = NOW()

            WHERE
              telegram_user_id = $1
          `,
          [
            row.telegram_user_id,
            next.day,
            next.slot,
            next.at,
          ]
        );
      }
    } finally {
      running = false;
    }
  }

  function start() {
    if (interval) {
      return;
    }

    runDue().catch(
      (error) => {
        console.error(
          "Mystery message worker error:",
          error?.message ||
          error
        );
      }
    );

    interval =
      setInterval(
        () => {
          runDue().catch(
            (error) => {
              console.error(
                "Mystery message worker error:",
                error?.message ||
                error
              );
            }
          );
        },
        60_000
      );

    interval.unref?.();
  }

  function stop() {
    if (!interval) {
      return;
    }

    clearInterval(interval);
    interval = null;
  }

  return {
    ensureSchema,
    subscribe,
    unsubscribe,
    runDue,
    start,
    stop,
  };
}
