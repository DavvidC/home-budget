require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');

const app = express();

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: (process.env.APP_URL || 'http://localhost:' + (process.env.PORT || 8001)) + '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails[0].value;
  const allowed = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim());
  if (!allowed.includes(email)) return done(null, false);
  done(null, {
    id: profile.id,
    name: profile.displayName,
    email,
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
    .google-btn svg { flex-shrink: 0; }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>Domowy Budżet</h1>
    <p>Zaloguj się, aby zarządzać swoim budżetem.</p>
    <a href="/auth/google" class="google-btn">
      <svg width="20" height="20" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/><path fill="none" d="M0 0h48v48H0z"/></svg>
      Zaloguj się przez Google
    </a>
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
  res.json({ email: req.user.email, name: req.user.name });
});

app.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/login');
  });
});

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), {
    headers: { 'X-User-Id': req.user.id, 'X-User-Name': encodeURIComponent(req.user.name), 'X-User-Email': req.user.email }
  });
});

app.use(express.static(__dirname));

const PORT = process.env.PORT || 8001;
app.listen(PORT, () => console.log('Listening on http://localhost:' + PORT));
