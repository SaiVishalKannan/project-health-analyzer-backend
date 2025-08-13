const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const db = new sqlite3.Database('pha.db');

// Middleware: require admin
function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err || user.role !== 'Admin') return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  });
}

// List all users
router.get('/users', requireAdmin, (req, res) => {
  db.all('SELECT user_id, full_name, email, role, created_at FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ users: rows });
  });
});

// Change user role
router.post('/user/role', requireAdmin, (req, res) => {
  const { user_id, role } = req.body;
  if (!user_id || !['Admin','User'].includes(role)) return res.status(400).json({ error: 'Invalid input' });
  db.run('UPDATE users SET role = ? WHERE user_id = ?', [role, user_id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

// Reset password (sets to 'Welcome123!')
const bcrypt = require('bcryptjs');
router.post('/user/reset-password', requireAdmin, (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'Invalid input' });
  bcrypt.hash('Welcome123!', 10, (err, hash) => {
    db.run('UPDATE users SET password_hash = ? WHERE user_id = ?', [hash, user_id], function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ success: true, new_password: 'Welcome123!' });
    });
  });
});

// Audit log: create table and endpoints
const auditTableSql = `CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT,
  action TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;
db.run(auditTableSql);

// Add audit log (helper)
function logAudit(user_id, email, action) {
  db.run('INSERT INTO audit_logs (user_id, email, action) VALUES (?, ?, ?)', [user_id, email, action]);
}

// List audit logs
router.get('/audit', requireAdmin, (req, res) => {
  db.all('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ logs: rows });
  });
});

module.exports = { router, logAudit };
