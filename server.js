// server.js (replace dengan file ini)
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'isi_rahasia_kamu_acak';
const ADMIN_KEY = process.env.ADMIN_KEY || 'adminkey';

const app = express();
app.use(cors());
app.use(express.json({ limit: '30mb' })); // allow base64 payloads comfortably
app.use(express.urlencoded({ extended: true }));

// static
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// ensure uploads dir exists
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// sqlite
const DB_PATH = path.join(__dirname, 'data.sqlite');
const db = new sqlite3.Database(DB_PATH);

// init tables (idempotent)
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    account_number TEXT PRIMARY KEY,
    owner_name TEXT,
    balance INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT,
    owner_name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    created_at TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT,
    type TEXT,
    amount INTEGER,
    related_account TEXT,
    created_at TEXT,
    note TEXT,
    proof_path TEXT,
    proof_filename TEXT,
    proof_uploaded_at TEXT,
    status TEXT DEFAULT 'confirmed',
    confirmed_at TEXT,
    rejected_at TEXT
  )`);
});

// safe migration helper
function ensureColumn(table, column, definition) {
  return new Promise((resolve) => {
    db.all(`PRAGMA table_info(${table})`, (err, cols) => {
      if (err || !Array.isArray(cols)) { resolve(false); return; }
      const found = cols.find(c => c.name === column);
      if (found) { resolve(true); return; }
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`, (err2) => {
        if (err2) {
          console.warn(`Migration: failed to add column ${column} to ${table}:`, err2.message);
          resolve(false);
        } else {
          console.log(`Migration: added column ${column} to ${table}`);
          resolve(true);
        }
      });
    });
  });
}

(async () => {
  try {
    await ensureColumn('transactions', 'rejected_at', 'TEXT');
  } catch (e) {
    console.warn('Migration error:', e && e.message);
  }
})();

// helper: promises for sqlite
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function (err) {
    if (err) return reject(err);
    resolve({ lastID: this.lastID, changes: this.changes });
  }));
}

// helper: generate unique 10-digit account number
async function generateUniqueAccountNumber() {
  for (let i = 0; i < 50; i++) {
    const acc = String(Math.floor(1000000000 + Math.random() * 9000000000)); // 10 digits
    const exists = await dbGet('SELECT 1 FROM accounts WHERE account_number = ?', [acc]);
    if (!exists) return acc;
  }
  throw new Error('Gagal membuat account number unik');
}

// helper: save base64 to file
function saveBase64ToFile(base64data, filenameHint = 'proof') {
  const matches = String(base64data || '').match(/^data:(.+);base64,(.+)$/);
  let ext = '';
  let data64 = base64data;
  if (matches) {
    const mime = matches[1]; data64 = matches[2];
    const map = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'application/pdf': 'pdf' };
    ext = map[mime] || mime.split('/').pop();
  } else {
    ext = (filenameHint.split('.').pop() || 'bin').toLowerCase();
  }
  const safeName = String(filenameHint).replace(/[^a-z0-9\-_\.]/ig, '_').slice(0, 60);
  const filename = `${Date.now()}_${Math.floor(Math.random() * 9000 + 1000)}_${safeName}.${ext}`;
  const savedPath = path.join(UPLOAD_DIR, filename);
  const buffer = Buffer.from(data64, 'base64');
  fs.writeFileSync(savedPath, buffer);
  return { savedPath, filename };
}

// JWT middleware (support admin tokens)
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Unauthorized' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// helper: requireAdmin middleware
async function requireAdmin(req, res, next) {
  // Accept either Authorization: Bearer <admin-token> with payload.is_admin
  // OR accept x-admin-key === ADMIN_KEY (legacy)
  const key = req.headers['x-admin-key'];
  if (key && key === ADMIN_KEY) { return next(); }
  const auth = req.headers.authorization;
  if (!auth) return res.status(403).json({ error: 'Admin authorization required' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(403).json({ error: 'Admin authorization required' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload && payload.is_admin) { req.admin = payload; return next(); }
    return res.status(403).json({ error: 'Admin token required' });
  } catch (err) {
    return res.status(403).json({ error: 'Invalid admin token' });
  }
}

// create HTTP server + socket.io
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
app.set('io', io);

io.on('connection', (socket) => {
  socket.on('join_room', ({ room, token }) => {
    if (room) socket.join(room);
  });
});

// ---------- API routes ----------

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { owner_name, email, password } = req.body;
    if (!owner_name || !email || !password) return res.status(400).json({ error: 'owner_name,email,password required' });
    const exists = await dbGet('SELECT 1 FROM users WHERE email = ?', [email]);
    if (exists) return res.status(400).json({ error: 'Email sudah terdaftar' });

    const account_number = await generateUniqueAccountNumber();
    await dbRun('INSERT INTO accounts (account_number, owner_name, balance) VALUES (?, ?, ?)', [account_number, owner_name, 0]);
    const hash = await bcrypt.hash(password, 10);
    await dbRun('INSERT INTO users (account_number, owner_name, email, password_hash) VALUES (?, ?, ?, ?)', [account_number, owner_name, email, hash]);

    return res.json({ account_number });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/login  (accept account_number or email)
app.post('/api/login', async (req, res) => {
  try {
    const { account_number, email, password } = req.body;
    let user;
    if (account_number) {
      user = await dbGet('SELECT * FROM users WHERE account_number = ?', [account_number]);
    } else if (email) {
      user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    } else {
      return res.status(400).json({ error: 'account_number or email required' });
    }
    if (!user) return res.status(400).json({ error: 'User not found' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ account_number: user.account_number, owner_name: user.owner_name }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Admin auth endpoints ---

// POST /api/admin/register
// Requires master x-admin-key header (ENV ADMIN_KEY) to create a new admin user
app.post('/api/admin/register', async (req, res) => {
  try {
    const key = req.headers['x-admin-key'];
    if (key !== ADMIN_KEY) return res.status(403).json({ error: 'Admin key invalid' });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const existing = await dbGet('SELECT * FROM admins WHERE username = ?', [username]);
    if (existing) return res.status(400).json({ error: 'Username sudah ada' });
    const hash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();
    await dbRun('INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)', [username, hash, now]);
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/admin/login
// Returns JWT with is_admin:true
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const admin = await dbGet('SELECT * FROM admins WHERE username = ?', [username]);
    if (!admin) return res.status(400).json({ error: 'Admin not found' });
    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid password' });
    const token = jwt.sign({ is_admin: true, admin_id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/account  (auth)
app.get('/api/account', authenticateToken, async (req, res) => {
  try {
    const acc = await dbGet('SELECT * FROM accounts WHERE account_number = ?', [req.user.account_number]);
    if (!acc) return res.status(404).json({ error: 'Account not found' });
    return res.json({ owner_name: acc.owner_name, account_number: acc.account_number, balance: acc.balance || 0 });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/transactions  (auth)
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const rows = await dbAll('SELECT * FROM transactions WHERE account_number = ? ORDER BY id DESC LIMIT 200', [req.user.account_number]);
    return res.json(rows || []);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/transfer  (auth)
app.post('/api/transfer', authenticateToken, async (req, res) => {
  try {
    const fromAcc = req.user.account_number;
    const { to_account_number, amount } = req.body;
    const amt = Math.round(Number(amount) * 100); // store in sen
    if (!to_account_number || !amt || amt <= 0) return res.status(400).json({ error: 'to_account_number and amount required' });

    const fromRow = await dbGet('SELECT * FROM accounts WHERE account_number = ?', [fromAcc]);
    const toRow = await dbGet('SELECT * FROM accounts WHERE account_number = ?', [to_account_number]);
    if (!toRow) return res.status(404).json({ error: 'Tujuan tidak ditemukan' });
    if ((fromRow.balance || 0) < amt) return res.status(400).json({ error: 'Saldo tidak cukup' });

    await dbRun('UPDATE accounts SET balance = balance - ? WHERE account_number = ?', [amt, fromAcc]);
    await dbRun('UPDATE accounts SET balance = balance + ? WHERE account_number = ?', [amt, to_account_number]);

    const now = new Date().toISOString();
    await dbRun(`INSERT INTO transactions (account_number, type, amount, related_account, created_at, note, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [fromAcc, 'transfer', -amt, to_account_number, now, 'transfer outgoing', 'confirmed']);
    await dbRun(`INSERT INTO transactions (account_number, type, amount, related_account, created_at, note, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [to_account_number, 'transfer', amt, fromAcc, now, 'transfer incoming', 'confirmed']);

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/deposit  (legacy, immediate confirm)
app.post('/api/deposit', async (req, res) => {
  try {
    const { account_number, amount, proof_base64, proof_filename } = req.body;
    if (!account_number || !amount) return res.status(400).json({ error: 'account_number and amount required' });
    const acc = await dbGet('SELECT * FROM accounts WHERE account_number = ?', [account_number]);
    if (!acc) return res.status(404).json({ error: 'Account not found' });

    const amt = Math.round(Number(amount) * 100);
    let proofPath = null, savedFilename = null, proofUploadedAt = null;
    if (proof_base64) {
      const saved = saveBase64ToFile(proof_base64, proof_filename || 'proof');
      proofPath = path.relative(__dirname, saved.savedPath);
      savedFilename = saved.filename;
      proofUploadedAt = new Date().toISOString();
    }

    const newBalance = (acc.balance || 0) + amt;
    await dbRun('UPDATE accounts SET balance = ? WHERE account_number = ?', [newBalance, account_number]);

    const now = new Date().toISOString();
    await dbRun(`INSERT INTO transactions (account_number, type, amount, created_at, note, proof_path, proof_filename, proof_uploaded_at, status, confirmed_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [account_number, 'deposit', amt, now, 'deposit immediate', proofPath, savedFilename, proofUploadedAt, 'confirmed', now]);

    io.to(account_number).emit('deposit_confirmed', { pending_id: null, account_number, amount: amt, created_at: now });

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/deposit/pending  (new flow: save as pending, require admin approve)
app.post('/api/deposit/pending', async (req, res) => {
  try {
    const { account_number, amount, proof_base64, proof_filename } = req.body;
    if (!account_number || !amount) return res.status(400).json({ error: 'account_number and amount required' });
    const acc = await dbGet('SELECT * FROM accounts WHERE account_number = ?', [account_number]);
    if (!acc) return res.status(404).json({ error: 'Account not found' });

    const amt = Math.round(Number(amount) * 100);
    let proofPath = null, savedFilename = null, proofUploadedAt = null;
    if (proof_base64) {
      const saved = saveBase64ToFile(proof_base64, proof_filename || 'proof');
      proofPath = path.relative(__dirname, saved.savedPath);
      savedFilename = saved.filename;
      proofUploadedAt = new Date().toISOString();
    }

    const now = new Date().toISOString();
    const r = await dbRun(`INSERT INTO transactions (account_number, type, amount, created_at, note, proof_path, proof_filename, proof_uploaded_at, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [account_number, 'deposit', amt, now, 'deposit pending (await admin)', proofPath, savedFilename, proofUploadedAt, 'pending']);
    return res.json({ success: true, pending_id: r.lastID });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/deposit/status?pending_id=...
app.get('/api/deposit/status', async (req, res) => {
  try {
    const pending_id = Number(req.query.pending_id || 0);
    if (!pending_id) return res.status(400).json({ error: 'pending_id required' });
    const tx = await dbGet('SELECT * FROM transactions WHERE id = ?', [pending_id]);
    if (!tx) return res.status(404).json({ error: 'Not found' });
    return res.json({ status: tx.status, tx });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ADMIN: list pending deposits
app.get('/api/admin/deposits', requireAdmin, async (req, res) => {
  try {
    const rows = await dbAll('SELECT * FROM transactions WHERE status = ? ORDER BY id ASC', ['pending']);
    const result = rows.map(r => {
      if (r.proof_path) r.proof_url = '/uploads/' + path.basename(r.proof_path);
      else r.proof_url = null;
      return r;
    });
    return res.json(result);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ADMIN: approve pending deposit
app.post('/api/admin/deposit/approve', requireAdmin, async (req, res) => {
  try {
    const { pending_id } = req.body;
    if (!pending_id) return res.status(400).json({ error: 'pending_id required' });
    const tx = await dbGet('SELECT * FROM transactions WHERE id = ?', [pending_id]);
    if (!tx) return res.status(404).json({ error: 'Transaction not found' });
    if (tx.status !== 'pending') return res.status(400).json({ error: 'Transaction not pending' });

    await dbRun('UPDATE accounts SET balance = balance + ? WHERE account_number = ?', [tx.amount, tx.account_number]);
    const now = new Date().toISOString();
    await dbRun('UPDATE transactions SET status = ?, confirmed_at = ? WHERE id = ?', ['confirmed', now, pending_id]);

    io.to(tx.account_number).emit('deposit_confirmed', {
      pending_id,
      account_number: tx.account_number,
      amount: tx.amount,
      created_at: now
    });

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ADMIN: get all deposit transactions (history)
app.get('/api/admin/deposits_all', requireAdmin, async (req, res) => {
  try {
    const rows = await dbAll('SELECT * FROM transactions WHERE type = ? ORDER BY id DESC LIMIT 1000', ['deposit']);
    const result = rows.map(r => {
      if (r.proof_path) r.proof_url = '/uploads/' + path.basename(r.proof_path);
      return r;
    });
    return res.json(result);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ADMIN: reject a pending deposit (mark as rejected)
app.post('/api/admin/deposit/reject', requireAdmin, async (req, res) => {
  try {
    const { pending_id, reason } = req.body;
    if (!pending_id) return res.status(400).json({ error: 'pending_id required' });
    const tx = await dbGet('SELECT * FROM transactions WHERE id = ?', [pending_id]);
    if (!tx) return res.status(404).json({ error: 'Transaction not found' });
    if (tx.status !== 'pending') return res.status(400).json({ error: 'Transaction not pending' });

    const now = new Date().toISOString();
    await dbRun('UPDATE transactions SET status = ?, rejected_at = ?, note = ? WHERE id = ?', ['rejected', now, reason || 'rejected by admin', pending_id]);

    io.to(tx.account_number).emit('deposit_rejected', {
      pending_id,
      account_number: tx.account_number,
      amount: tx.amount,
      reason: reason || 'Ditolak oleh admin',
      rejected_at: now
    });

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// fallback
app.get('/health', (req, res) => res.json({ ok: true }));

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT} (PORT=${PORT})`);
});
