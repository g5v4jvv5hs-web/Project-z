import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// TEST MODE ONLY: in-memory data.
// No real-money payments are enabled in this starter.
const users = new Map();
let totalPool = 0;

app.get("/", (_req, res) => {
  res.json({ ok: true, project: "Project Z", mode: "TEST" });
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
  if (!telegramId) return res.status(400).json({ error: "telegramId is required" });

  if (!users.has(String(telegramId))) {
    users.set(String(telegramId), {
      telegramId: String(telegramId),
      username: username || "",
      balance: 0
    });
  }

  res.json(users.get(String(telegramId)));
});

// TEST ENTRY: credits a user with a simulated $2 entry.
// Replace this with a compliant payment flow only after legal/platform review.
app.post("/api/test-entry", (req, res) => {
  const { telegramId } = req.body || {};
  if (!telegramId) return res.status(400).json({ error: "telegramId is required" });

  const id = String(telegramId);
  if (!users.has(id)) {
    users.set(id, { telegramId: id, username: "", balance: 0 });
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
  console.log(`Project Z backend running on port ${PORT}`);
});