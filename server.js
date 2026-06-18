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
    INSERT INTO categories(name) VALUES ('Wypłata'),('Jedzenie'),('Prąd'),('Leasing'),('Paliwo'),('Inne') ON CONFLICT DO NOTHING;
    CREATE TABLE IF NOT EXISTS budgets (
      category TEXT PRIMARY KEY,
      limit_cents INTEGER NOT NULL
    );
    ALTER TABLE budgets ADD COLUMN IF NOT EXISTS alerted_80 TEXT NOT NULL DEFAULT '';
    ALTER TABLE budgets ADD COLUMN IF NOT EXISTS alerted_90 TEXT NOT NULL DEFAULT '';
    ALTER TABLE budgets ADD COLUMN IF NOT EXISTS alerted_100 TEXT NOT NULL DEFAULT '';
  `);
  console.log('DB ready');
}

function fmtPLN(cents) {
  return (cents / 100).toFixed(2).replace('.', ',') + ' zł';
}

async function checkBudgetAlerts(category) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatIds = (process.env.TELEGRAM_CHAT_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!token || chatIds.length === 0) return;

  const now = new Date();
  const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const monthStart = monthKey + '-01';
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  const monthEnd = `${nextMonth.getFullYear()}-${String(nextMonth.getMonth() + 1).padStart(2, '0')}-01`;

  const { rows: budgets } = await pool.query(
    'SELECT category, limit_cents, alerted_80, alerted_90, alerted_100 FROM budgets WHERE category = $1',
    [category]
  );
  if (budgets.length === 0) return;

  const budget = budgets[0];
  const { rows: spending } = await pool.query(
    `SELECT COALESCE(SUM((data->>'amountCents')::int), 0) AS total
     FROM transactions
     WHERE data->>'category' = $1
       AND data->>'type' = 'expense'
       AND data->>'date' >= $2
       AND data->>'date' < $3`,
    [category, monthStart, monthEnd]
  );

  const spent = spending[0].total;
  const pct = spent / budget.limit_cents;

  const alerts = [];
  if (pct >= 1 && budget.alerted_100 !== monthKey) {
    alerts.push({ level: 100, emoji: '🔴', msg: 'Przekroczono budżet!' });
    await pool.query(
      'UPDATE budgets SET alerted_100 = $2, alerted_90 = $2, alerted_80 = $2 WHERE category = $1',
      [category, monthKey]
    );
  } else if (pct >= 0.9 && budget.alerted_90 !== monthKey) {
    alerts.push({ level: 90, emoji: '🟠', msg: 'Zostało tylko 10%' });
    await pool.query(
      'UPDATE budgets SET alerted_90 = $2, alerted_80 = $2 WHERE category = $1',
      [category, monthKey]
    );
  } else if (pct >= 0.8 && budget.alerted_80 !== monthKey) {
    alerts.push({ level: 80, emoji: '🟡', msg: 'Zbliżasz się do limitu' });
    await pool.query(
      'UPDATE budgets SET alerted_80 = $2 WHERE category = $1',
      [category, monthKey]
    );
  }

  for (const alert of alerts) {
    const text = `${alert.emoji} Budżet "${category}" — ${Math.round(pct * 100)}%\n${alert.msg}\nWydano: ${fmtPLN(spent)} z ${fmtPLN(budget.limit_cents)}`;
    for (const chatId of chatIds) {
      fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text })
      }).catch(() => {});
    }
  }
}

const app = express();

app.use(express.json());
app.use(express.text({ limit: '5mb' }));

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
// Transaction API routes
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
    if (txn.type === 'expense' && txn.category) {
      checkBudgetAlerts(txn.category).catch(() => {});
    }
    res.status(201).json(txn);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/transactions/:id', requireAuth, async (req, res) => {
  try {
    const updates = req.body;
    await pool.query(
      'UPDATE transactions SET data = data || $2::jsonb WHERE id = $1',
      [req.params.id, JSON.stringify(updates)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/transactions', requireAuth, async (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids required' });
  try {
    const result = await pool.query('DELETE FROM transactions WHERE id = ANY($1)', [ids]);
    res.json({ deleted: result.rowCount });
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
    const importedCategories = new Set();
    for (const line of lines) {
      const cols = line.split(sep);
      if (cols.length < 10) continue;
      const dateRaw = cols[0].trim();
      if (!/^\d{2}\.\d{2}\.\d{4}$/.test(dateRaw)) continue;
      const [day, month, year] = dateRaw.split('.');
      const date = `${year}-${month}-${day}`;

      let amountStr, odbiorca, comment, refNum, category;
      let zrodlowy, docelowy;
      if (isCSV) {
        // CSV: cols[2]=odbiorca, cols[3]=address(skip), cols[4]=zrodlowy, cols[5]=docelowy, cols[6]=comment, cols[7]=amount, cols[9]=refNum
        odbiorca  = (cols[2] || '').trim();
        zrodlowy  = (cols[4] || '').trim().replace(/^'/, '');
        docelowy  = (cols[5] || '').trim().replace(/^'/, '');
        comment   = (cols[6] || '').trim();
        amountStr = (cols[7] || '').trim().replace(/\s/g, '').replace(',', '.');
        refNum    = (cols[9] || '').trim().replace(/^'/, '');
        category  = 'Inne';
      } else {
        // TXT: cols[2]=odbiorca, cols[3]=zrodlowy, cols[4]=docelowy, cols[5]=comment, cols[6]=amount, cols[8]=refNum, cols[10]=category
        odbiorca  = (cols[2] || '').trim();
        zrodlowy  = (cols[3] || '').trim();
        docelowy  = (cols[4] || '').trim();
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
      if (!isCSV && category) {
        await pool.query('INSERT INTO categories(name) VALUES($1) ON CONFLICT DO NOTHING', [category]);
      }
      const data = { id, date, amountCents, type, category, desc: comment, odbiorca, comment, zrodlowy, docelowy };
      const result = await pool.query(
        'INSERT INTO transactions(id, data, odbiorca, comment) VALUES($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING',
        [id, data, odbiorca, comment]
      );
      if (result.rowCount > 0) {
        imported++;
        if (type === 'expense' && category) importedCategories.add(category);
      } else {
        skipped++;
      }
    }
    for (const cat of importedCategories) {
      checkBudgetAlerts(cat).catch(() => {});
    }
    res.json({ imported, skipped });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Budget API routes
// ---------------------------------------------------------------------------
app.get('/api/budgets', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT category, limit_cents AS "limitCents" FROM budgets ORDER BY category');
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/budgets', requireAuth, async (req, res) => {
  try {
    const { category, limitCents } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO budgets(category, limit_cents, alerted_80, alerted_90, alerted_100) VALUES($1, $2, '', '', '')
       ON CONFLICT (category) DO UPDATE SET limit_cents = $2, alerted_80 = '', alerted_90 = '', alerted_100 = ''
       RETURNING category, limit_cents AS "limitCents"`,
      [category, limitCents]
    );
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/budgets/:category', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM budgets WHERE category = $1', [req.params.category]);
    res.status(204).end();
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
