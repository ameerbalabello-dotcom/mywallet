const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const Stripe = require('stripe');

const app = express();
const stripe = Stripe(process.env.STRIPE_API_KEY || 'sk_test_123');
const db = new sqlite3.Database('./mywallet.db');
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

app.use(cors());
app.use(express.json());

// Initialize DB
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT,
    phone TEXT,
    balance REAL DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,
    amount REAL,
    meta TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Helpers
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing auth' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Routes
app.post('/api/signup', async (req, res) => {
  const { email, password, name, phone } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hashed = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (email, password, name, phone) VALUES (?,?,?,?)`, [email, hashed, name || '', phone || ''], function(err) {
    if (err) return res.status(400).json({ error: 'User may already exist' });
    const userId = this.lastID;
    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
    if (err || !row) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, row.password);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: row.id, email: row.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  });
});

app.get('/api/me', authenticate, (req, res) => {
  db.get(`SELECT id, email, name, phone, balance FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'User not found' });
    res.json(row);
  });
});

// Top-up (simulate stripe charge)
app.post('/api/topup', authenticate, async (req, res) => {
  const { amount, paymentMethodId } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

  try {
    // Simulate Stripe payment intent (we won't actually charge)
    // In production, create PaymentIntent and confirm on client
    const charge = { id: 'ch_simulated_' + Date.now(), amount };

    // Update balance
    db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [amount, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Could not update balance' });
      db.run(`INSERT INTO transactions (user_id, type, amount, meta) VALUES (?,?,?,?)`, [req.user.id, 'topup', amount, JSON.stringify(charge)], function(err2) {
        if (err2) return res.status(500).json({ error: 'Could not create transaction' });
        res.json({ success: true, charge });
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'Payment failed' });
  }
});

// Transfer
app.post('/api/transfer', authenticate, (req, res) => {
  const { toPhone, amount } = req.body;
  if (!toPhone || !amount || amount <= 0) return res.status(400).json({ error: 'Invalid data' });
  db.get(`SELECT * FROM users WHERE phone = ?`, [toPhone], (err, recipient) => {
    if (err || !recipient) return res.status(404).json({ error: 'Recipient not found' });
    // Check sender balance and include sender contact info
    db.get(`SELECT balance, email, phone FROM users WHERE id = ?`, [req.user.id], (err2, sender) => {
      if (err2 || !sender) return res.status(404).json({ error: 'Sender not found' });
      if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient funds' });
      db.serialize(() => {
        db.run(`UPDATE users SET balance = balance - ? WHERE id = ?`, [amount, req.user.id]);
        db.run(`UPDATE users SET balance = balance + ? WHERE id = ?`, [amount, recipient.id]);
        db.run(`INSERT INTO transactions (user_id, type, amount, meta) VALUES (?,?,?,?)`, [req.user.id, 'transfer_sent', -amount, JSON.stringify({ toPhone })]);
        db.run(`INSERT INTO transactions (user_id, type, amount, meta) VALUES (?,?,?,?)`, [recipient.id, 'transfer_received', amount, JSON.stringify({ fromPhone: sender.phone, fromEmail: sender.email })]);
        res.json({ success: true });
      });
    });
  });
});

app.get('/api/transactions', authenticate, (req, res) => {
  db.all(`SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Could not fetch transactions' });
    res.json(rows);
  });
});

app.listen(PORT, () => {
  console.log('MyWallet server running on port', PORT);
});
