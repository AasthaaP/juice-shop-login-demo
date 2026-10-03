/**
 * Juice Shop-style login demo
 * -----------------------------------------------------------------------------
 * A tiny Express + SQLite login server built to show the difference between a
 * SECURE login flow and a VULNERABLE one (SQL Injection + XSS).
 *
 *   SECURE mode (default):   node server.js
 *   VULNERABLE mode:         node server.js --vuln     (or VULNERABLE_MODE=true)
 *
 * Both modes run client-side AND server-side validation. The only thing the
 * flag changes is HOW the query is built and HOW output is handled, so you can
 * see exactly which practice stops the attack.
 */

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

// --- Mode flag ---------------------------------------------------------------
const VULNERABLE =
  process.argv.includes('--vuln') ||
  String(process.env.VULNERABLE_MODE).toLowerCase() === 'true';

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- In-memory database + seed data ------------------------------------------
const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,   -- bcrypt hash, used by SECURE mode
    password_md5  TEXT NOT NULL    -- insecure hash, only here to make the
  );                               -- VULNERABLE SQLi demo realistic
`);

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

// The first row is the admin — this mirrors Juice Shop, where an SQLi that
// returns "the first user" lands you on the admin account.
const seed = [
  { email: 'admin@juice-sh.op', password: 'admin123' },
  { email: 'jim@juice-sh.op', password: 'ncc-1701' },
];
const insert = db.prepare(
  'INSERT INTO users (email, password_hash, password_md5) VALUES (?, ?, ?)'
);
for (const u of seed) {
  insert.run(u.email, bcrypt.hashSync(u.password, 12), md5(u.password));
}

// --- Helpers -----------------------------------------------------------------
// Server-side validation (runs in BOTH modes). Mirrors the client-side rules
// so a request that skips the browser (curl, Burp, fetch) is still checked.
function validate(email, password) {
  if (typeof email !== 'string' || typeof password !== 'string') return 'Missing fields.';
  if (!email.trim() || !password.trim()) return 'Email and password are required.';
  if (!email.includes('@')) return 'Email must contain "@".';
  if (password.length < 8) return 'Password must be at least 8 characters.';
  return null; // valid
}

// Escape user input before putting it in HTML (the XSS fix).
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// --- Login endpoint ----------------------------------------------------------
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};

  const error = validate(email, password);
  if (error) return res.status(400).json({ ok: false, message: error });

  if (VULNERABLE) {
    // ---------------- INSECURE PATH (for the Part 3 demo) ----------------
    // 1) SQL Injection: user input is concatenated straight into the query.
    //    Payload  admin@juice-sh.op'--  comments out the password check.
    const sql =
      "SELECT id, email FROM users WHERE email = '" +
      email +
      "' AND password_md5 = '" +
      md5(password) +
      "'";
    let row;
    try {
      row = db.prepare(sql).get();
    } catch (e) {
      // Leaking the DB error is itself an information-disclosure bug.
      return res.status(500).json({ ok: false, message: 'SQL error: ' + e.message });
    }
    if (row) {
      return res.json({ ok: true, message: 'Welcome back, ' + row.email + '!' });
    }
    // 2) Reflected XSS: the raw email is echoed back and (see script.js) the
    //    client drops it into the page with innerHTML, so markup executes.
    return res.status(401).json({
      ok: false,
      message: 'No account found for ' + email,
    });
  }

  // ---------------------- SECURE PATH (default) ----------------------
  // 1) Parameterized query: input can never change the SQL structure.
  const user = db
    .prepare('SELECT id, email, password_hash FROM users WHERE email = ?')
    .get(email);

  // 2) bcrypt verify: passwords are salted + hashed, never compared in SQL.
  const good = user && bcrypt.compareSync(password, user.password_hash);
  if (!good) {
    // Generic message (no username enumeration) + escaped output.
    return res.status(401).json({ ok: false, message: 'Invalid email or password.' });
  }
  return res.json({ ok: true, message: 'Welcome back, ' + escapeHtml(user.email) + '!' });
});

// Tells the front-end which banner to show.
app.get('/api/mode', (_req, res) => res.json({ vulnerable: VULNERABLE }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  Login demo running:  http://localhost:${PORT}`);
  console.log(`  Mode:                ${VULNERABLE ? 'VULNERABLE  (insecure on purpose)' : 'SECURE'}`);
  console.log(`  Seeded accounts:     admin@juice-sh.op / admin123,  jim@juice-sh.op / ncc-1701\n`);
});
