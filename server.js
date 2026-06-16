require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const DATA_FILE = path.join(__dirname, 'data.json');

app.use(express.json());

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------
function readData() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { transactions: [], categories: [] };
  }
}

function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

if (!fs.existsSync(DATA_FILE)) {
  writeData({ transactions: [], categories: [] });
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
const APP_URL = process.env.APP_URL || ('http://localhost:' + (process.env.PORT || 8001));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: APP_URL + '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  const allowedEmails = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
  const email = profile.emails[0].value.toLowerCase();
  if (!allowedEmails.includes(email)) return done(null, false);
  done(null, {
    id: profile.id,
    name: profile.displayName,
    email: profile.emails[0].value,
    photo: profile.photos[0] && profile.photos[0].value
  });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.send(`<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Zaloguj się – Domowy Budżet</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .login-card { background: #fff; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.12); padding: 3rem 2.5rem; text-align: center; max-width: 360px; width: 100%; }
    h1 { font-size: 1.5rem; font-weight: 700; color: #1e40af; margin-bottom: .5rem; }
    p { color: #6b7280; margin-bottom: 2rem; font-size: .95rem; }
    .google-btn { display: inline-flex; align-items: center; gap: .75rem; background: #fff; border: 1px solid #d1d5db; border-radius: 8px; padding: .75rem 1.5rem; font-size: 1rem; font-weight: 500; color: #374151; text-decoration: none; box-shadow: 0 1px 4px rgba(0,0,0,.08); transition: box-shadow .15s; }
    .google-btn:hover { box-shadow: 0 2px 8px rgba(0,0,0,.15); }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>Domowy Budżet</h1>
    <p>Zaloguj się, aby zarządzać swoim budżetem.</p>
    <a href="/auth/google" class="google-btn">Zaloguj się przez Google</a>
  </div>
</body>
</html>`);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/')
);

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name });
});

app.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => { if (err) console.error('session destroy error:', err); res.redirect('/login'); });
  });
});

// ---------------------------------------------------------------------------
// Budget API routes
// ---------------------------------------------------------------------------
app.get('/api/transactions', requireAuth, (req, res) => {
  res.json(readData().transactions);
});

app.post('/api/transactions', requireAuth, (req, res) => {
  const data = readData();
  const txn = { id: crypto.randomUUID(), ...req.body };
  data.transactions.push(txn);
  writeData(data);
  res.status(201).json(txn);
});

app.delete('/api/transactions/:id', requireAuth, (req, res) => {
  const data = readData();
  data.transactions = data.transactions.filter(t => t.id !== req.params.id);
  writeData(data);
  res.status(204).end();
});

app.get('/api/categories', requireAuth, (req, res) => {
  res.json(readData().categories);
});

app.post('/api/categories', requireAuth, (req, res) => {
  const data = readData();
  if (data.categories.some(c => c.name === req.body.name)) {
    return res.status(409).json({ error: 'Category already exists' });
  }
  data.categories.push(req.body);
  writeData(data);
  res.status(201).json(req.body);
});

// ---------------------------------------------------------------------------
// Main app
// ---------------------------------------------------------------------------
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 8001;
app.listen(PORT, () => console.log('Listening on ' + APP_URL));
