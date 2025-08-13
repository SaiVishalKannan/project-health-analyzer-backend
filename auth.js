const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const router = express.Router();
const adminModule = require('./admin');

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const db = new sqlite3.Database('pha.db');

// Create users table if not exists
const userTableSql = `CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Admin','User')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;
db.run(userTableSql);

function validEmail(email) {
  return /^([\w.-]+)@cognizant\.com$/.test(email);
}

// Sign Up
router.post('/signup', (req, res) => {
  const { full_name, email, password, role } = req.body;
  if (!full_name || !email || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Email must be @cognizant.com' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (user) return res.status(409).json({ error: 'Email already registered' });
    bcrypt.hash(password, 10, (err, hash) => {
      db.run('INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)',
        [full_name, email, hash, role],
        function (err) {
          if (err) return res.status(500).json({ error: 'DB error' });
          const payload = { user_id: this.lastID, email, role, full_name };
          const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30m' });
          res.json({ token, user: payload });
        }
      );
    });
  });
});

// Sign In
router.post('/signin', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    bcrypt.compare(password, user.password_hash, (err, match) => {
      if (!match) return res.status(401).json({ error: 'Invalid credentials' });
      const payload = { user_id: user.user_id, email: user.email, role: user.role, full_name: user.full_name };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30m' });
      res.json({ token, user: payload });
    });
  });
});

// Session check
router.get('/session', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid/expired token' });
    res.json({ user });
  });
});

module.exports = router;
