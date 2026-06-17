require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS categories (
      name TEXT PRIMARY KEY
    );
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS odbiorca TEXT;
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS comment TEXT;
  `);
  console.log('DB ready');
}

const app = express();

app.use(express.json());
app.use(express.text());

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
app.get('/api/transactions', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data FROM transactions');
    res.json(rows.map(r => r.data));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/transactions', requireAuth, async (req, res) => {
  try {
    const txn = { id: crypto.randomUUID(), ...req.body };
    await pool.query('INSERT INTO transactions(id, data) VALUES($1, $2)', [txn.id, txn]);
    res.status(201).json(txn);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/transactions/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM transactions WHERE id = $1', [req.params.id]);
    res.status(204).end();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/categories', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT name FROM categories ORDER BY name');
    res.json(rows.map(r => r.name));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/categories', requireAuth, async (req, res) => {
  try {
    await pool.query('INSERT INTO categories(name) VALUES($1) ON CONFLICT DO NOTHING', [req.body.name]);
    res.status(201).json(req.body);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/import', requireAuth, async (req, res) => {
  try {
    const lines = (req.body || '').split(/\r?\n/);

    // Auto-detect: CSV uses semicolons, TXT uses tabs
    let sep = '\t';
    for (const line of lines) {
      if (line.split(';').length >= 10) { sep = ';'; break; }
      if (line.split('\t').length >= 10) { sep = '\t'; break; }
    }
    const isCSV = sep === ';';

    let imported = 0, skipped = 0;
    for (const line of lines) {
      const cols = line.split(sep);
      if (cols.length < 10) continue;
      const dateRaw = cols[0].trim();
      if (!/^\d{2}\.\d{2}\.\d{4}$/.test(dateRaw)) continue;
      const [day, month, year] = dateRaw.split('.');
      const date = `${year}-${month}-${day}`;

      let amountStr, odbiorca, comment, refNum, category;
      if (isCSV) {
        // CSV: cols[2]=odbiorca, cols[3]=address(skip), cols[6]=comment, cols[7]=amount, cols[9]=refNum, no category
        odbiorca = (cols[2] || '').trim();
        comment  = (cols[6] || '').trim();
        amountStr = (cols[7] || '').trim().replace(/\s/g, '').replace(',', '.');
        refNum   = (cols[9] || '').trim().replace(/^'/, '');
        category = 'Inne';
      } else {
        // TXT: cols[2]=odbiorca, cols[5]=comment, cols[6]=amount, cols[8]=refNum, cols[10]=category
        odbiorca  = (cols[2] || '').trim();
        comment   = (cols[5] || '').trim();
        amountStr = (cols[6] || '').trim().replace(/\s/g, '').replace(',', '.');
        refNum    = (cols[8] || '').trim();
        category  = (cols[10] || '').trim() || 'Inne';
      }

      const amountFloat = parseFloat(amountStr);
      if (isNaN(amountFloat)) continue;
      const amountCents = Math.round(Math.abs(amountFloat) * 100);
      const type = amountFloat >= 0 ? 'income' : 'expense';
      const id = refNum || crypto.createHash('sha256').update(`${date}|${amountStr}`).digest('hex').slice(0, 36);
      const data = { id, date, amountCents, type, category, desc: comment, odbiorca, comment };
      const result = await pool.query(
        'INSERT INTO transactions(id, data, odbiorca, comment) VALUES($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING',
        [id, data, odbiorca, comment]
      );
      if (result.rowCount > 0) imported++; else skipped++;
    }
    res.json({ imported, skipped });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Main app
// ---------------------------------------------------------------------------
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 8001;
initDB().then(() => {
  app.listen(PORT, () => console.log('Listening on ' + APP_URL));
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
