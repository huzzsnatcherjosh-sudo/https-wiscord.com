#!/usr/bin/env node
/*  One-file Discord clone API
    npm start (or just: node backend.js)
    PORT=4433 node backend.js   (default 4433)
*/
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import path from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const http = createServer(app);
const io = new Server(http, { cors: { origin: '*' } });
const db = new sqlite3.Database(':memory:'); // swap to disk file if you like

db.serialize(() => {
  db.run(`CREATE TABLE users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    passhash TEXT,
    avatar TEXT
  )`);
  db.run(`CREATE TABLE servers(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    invite TEXT UNIQUE
  )`);
  db.run(`CREATE TABLE channels(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER,
    name TEXT,
    type TEXT DEFAULT 'text'
  )`);
  db.run(`CREATE TABLE messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER,
    user_id INTEGER,
    body TEXT,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`INSERT INTO servers(name,invite) VALUES('Default Hub','default')`);
  db.run(`INSERT INTO channels(server_id,name) VALUES(1,'general')`);
});

app.use(cors());
app.use(express.json());

const JWT_SECRET = 'change-me-or-env-var';
const auth = (req, res, next) => {
  const h = req.headers.authorization || '';
  const tok = h.replace('Bearer ', '');
  try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'bad token' }); }
};

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const passhash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users(username,passhash) VALUES(?,?)', [username, passhash], function (e) {
    if (e) return res.status(400).json({ error: 'user exists' });
    res.json({ token: jwt.sign({ id: this.lastID, username }, JWT_SECRET) });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username=?', [username], async (e, u) => {
    if (!u || !await bcrypt.compare(password, u.passhash))
      return res.status(403).json({ error: 'invalid' });
    res.json({ token: jwt.sign({ id: u.id, username }, JWT_SECRET) });
  });
});

app.get('/api/servers', (_q, res) => {
  db.all('SELECT * FROM servers', (e, r) => res.json(r));
});

app.post('/api/servers', auth, (req, res) => {
  const { name } = req.body;
  const invite = Math.random().toString(36).slice(2);
  db.run('INSERT INTO servers(name,invite) VALUES(?,?)', [name, invite], function () {
    db.run('INSERT INTO channels(server_id,name) VALUES(?,?)', [this.lastID, 'general']);
    res.json({ id: this.lastID, invite });
  });
});

app.get('/api/servers/:invite/channels', (req, res) => {
  const { invite } = req.params;
  db.get('SELECT id FROM servers WHERE invite=?', [invite], (e, s) => {
    if (!s) return res.status(404).json({ error: 'bad invite' });
    db.all('SELECT * FROM channels WHERE server_id=?', [s.id], (_e, r) => res.json(r));
  });
});

app.get('/api/channels/:id/messages', (req, res) => {
  db.all(
    `SELECT m.id,m.body,m.ts,u.username,u.avatar FROM messages m
     JOIN users u ON u.id=m.user_id WHERE m.channel_id=?
     ORDER BY m.ts LIMIT 200`,
    [req.params.id], (e, r) => res.json(r)
  );
});

io.use((sock, next) => {
  try {
    const tok = sock.handshake.auth.token;
    sock.user = jwt.verify(tok, JWT_SECRET);
    next();
  } catch { next(new Error('auth fail')); }
});

io.on('connection', s => {
  s.on('join', ({ channel }) => { s.join(`ch-${channel}`); });
  s.on('msg', ({ channel, body }) => {
    const { id, username } = s.user;
    db.run('INSERT INTO messages(channel_id,user_id,body) VALUES(?,?,?)', [channel, id, body], function () {
      const msg = { id: this.lastID, body, username, ts: Date.now() };
      io.to(`ch-${channel}`).emit('msg', msg);
    });
  });
});

const port = process.env.PORT || 4433;
http.listen(port, () => console.log(`API on :${port}`));