const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace-me-in-production';

const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, 'app.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  merchant_name TEXT,
  order_time TEXT,
  amount REAL,
  order_channel TEXT,
  receive_time TEXT,
  product_issue TEXT,
  complaint_status TEXT,
  complaint_method TEXT,
  accept_status TEXT,
  reject_reason TEXT,
  case_status TEXT,
  case_reason TEXT,
  mediation_status TEXT,
  mediation_amount REAL,
  remedy_taken TEXT,
  reply_status TEXT,
  reply_date TEXT,
  reply_method TEXT,
  reply_content TEXT,
  ems_record TEXT,
  order_no TEXT,
  tracking_no TEXT,
  regulator_ack_date TEXT,
  case_reply_date TEXT,
  case_reply_workdays INTEGER DEFAULT 15,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS external_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
`);

const upload = multer({ dest: uploadDir });
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(uploadDir));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: '未登录' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: '登录已过期' });
  }
}

app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: '用户名和密码必填' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
    res.json({ id: info.lastInsertRowid });
  } catch {
    res.status(400).json({ message: '用户名已存在' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ message: '账号或密码错误' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});

app.get('/api/projects', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM projects WHERE user_id=? ORDER BY updated_at DESC').all(req.user.id);
  res.json(rows);
});

app.post('/api/projects', auth, (req, res) => {
  const p = req.body;
  const stmt = db.prepare(`INSERT INTO projects (
    user_id, merchant_name, order_time, amount, order_channel, receive_time, product_issue,
    complaint_status, complaint_method, accept_status, reject_reason, case_status, case_reason,
    mediation_status, mediation_amount, remedy_taken, reply_status, reply_date, reply_method,
    reply_content, ems_record, order_no, tracking_no, regulator_ack_date, case_reply_date, case_reply_workdays, updated_at
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`);
  const info = stmt.run(req.user.id, p.merchant_name, p.order_time, p.amount || null, p.order_channel, p.receive_time, p.product_issue,
    p.complaint_status, p.complaint_method, p.accept_status, p.reject_reason, p.case_status, p.case_reason,
    p.mediation_status, p.mediation_amount || null, p.remedy_taken, p.reply_status, p.reply_date, p.reply_method,
    p.reply_content, p.ems_record, p.order_no, p.tracking_no, p.regulator_ack_date, p.case_reply_date, p.case_reply_workdays || 15);
  res.json({ id: info.lastInsertRowid });
});

app.put('/api/projects/:id', auth, (req, res) => {
  const p = req.body;
  db.prepare(`UPDATE projects SET
    merchant_name=?, order_time=?, amount=?, order_channel=?, receive_time=?, product_issue=?,
    complaint_status=?, complaint_method=?, accept_status=?, reject_reason=?, case_status=?, case_reason=?,
    mediation_status=?, mediation_amount=?, remedy_taken=?, reply_status=?, reply_date=?, reply_method=?,
    reply_content=?, ems_record=?, order_no=?, tracking_no=?, regulator_ack_date=?, case_reply_date=?, case_reply_workdays=?, updated_at=CURRENT_TIMESTAMP
    WHERE id=? AND user_id=?`).run(
    p.merchant_name, p.order_time, p.amount || null, p.order_channel, p.receive_time, p.product_issue,
    p.complaint_status, p.complaint_method, p.accept_status, p.reject_reason, p.case_status, p.case_reason,
    p.mediation_status, p.mediation_amount || null, p.remedy_taken, p.reply_status, p.reply_date, p.reply_method,
    p.reply_content, p.ems_record, p.order_no, p.tracking_no, p.regulator_ack_date, p.case_reply_date, p.case_reply_workdays || 15,
    req.params.id, req.user.id
  );
  res.json({ ok: true });
});

app.delete('/api/projects/:id', auth, (req, res) => {
  db.prepare('DELETE FROM projects WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.get('/api/links', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM external_links WHERE user_id=? ORDER BY created_at DESC').all(req.user.id));
});
app.post('/api/links', auth, (req, res) => {
  const { title, url } = req.body;
  const info = db.prepare('INSERT INTO external_links (user_id, title, url) VALUES (?,?,?)').run(req.user.id, title, url);
  res.json({ id: info.lastInsertRowid });
});
app.delete('/api/links/:id', auth, (req, res) => {
  db.prepare('DELETE FROM external_links WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post('/api/upload', auth, upload.single('image'), (req, res) => {
  res.json({ path: `/uploads/${req.file.filename}`, originalName: req.file.originalname });
});

app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
