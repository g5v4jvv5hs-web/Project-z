import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;

const users = new Map();
let totalPool = 0;

// Telegram webhook
app.post(`/telegram/${BOT_TOKEN}`, async (req, res) => {
  try {
    const update = req.body;

    if (update.message) {
      const chatId = update.message.chat.id;
      const text = update.message.text || "";

      if (text === "/start") {
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: chatId,
            text: "Project Z is online! 🚀"
          })
        });
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    project: "Project Z",
    mode: "TEST"
  });
});

app.get("/api/stats", (_req, res) => {
  res.json({
    mode: "TEST",
    totalPool: Number(totalPool.toFixed(2)),
    users: users.size
  });
});

app.post("/api/user", (req, res) => {
  const { telegramId, username } = req.body || {};

  if (!telegramId) {
    return res.status(400).json({
      error: "telegramId is required"
    });
  }

  if (!users.has(String(telegramId))) {
    users.set(String(telegramId), {
      telegramId: String(telegramId),
      username: username || "",
      balance: 0
    });
  }

  res.json(users.get(String(telegramId)));
});

app.post("/api/test-entry", (req, res) => {
  const { telegramId } = req.body || {};

  if (!telegramId) {
    return res.status(400).json({
      error: "telegramId is required"
    });
  }

  const id = String(telegramId);

  if (!users.has(id)) {
    users.set(id, {
      telegramId: id,
      username: "",
      balance: 0
    });
  }

  totalPool += 2;

  const user = users.get(id);
  user.balance += 2;

  res.json({
    ok: true,
    mode: "TEST",
    simulatedEntry: 2,
    user,
    totalPool: Number(totalPool.toFixed(2))
  });
});

app.listen(PORT, () => {
  console.log(`Project Z running on port ${PORT}`);
});
if (BOT_TOKEN) {
  const webhookUrl = `https://project-z-zryq.onrender.com/telegram/${BOT_TOKEN}`;

  fetch(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`)
    .then(response => response.json())
    .then(data => console.log("Webhook:", data))
    .catch(error => console.error("Webhook error:", error));
}
