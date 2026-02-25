#!/usr/bin/env node
'use strict';

/**
 * Security Review Agent — Dashboard (v2 with Google OAuth)
 *
 * Usage:
 *   node dashboard.js
 *   → Opens http://localhost:3847 in your browser
 *
 * Requires a .env file with:
 *   GOOGLE_CLIENT_ID=...
 *   GOOGLE_CLIENT_SECRET=...
 *   SESSION_SECRET=...
 */

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PORT = 3847;
const DATA_DIR = path.join(__dirname, 'data');
const REPORTS_BASE = path.join(__dirname, 'reports');

// Ensure base directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(REPORTS_BASE)) fs.mkdirSync(REPORTS_BASE, { recursive: true });

// ─── Per-user storage helpers ─────────────────────────────────
function userDir(userId) {
  const dir = path.join(DATA_DIR, String(userId).replace(/[^a-zA-Z0-9_-]/g, '_'));
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}
function userProjectsFile(userId) { return path.join(userDir(userId), 'projects.json'); }
function userReportsDir(userId) {
  const dir = path.join(REPORTS_BASE, String(userId).replace(/[^a-zA-Z0-9_-]/g, '_'));
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function loadProjects(userId) {
  try {
    const f = userProjectsFile(userId);
    if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf-8'));
  } catch (e) { /* ignore */ }
  return [];
}
function saveProjects(userId, projects) {
  fs.writeFileSync(userProjectsFile(userId), JSON.stringify(projects, null, 2), 'utf-8');
}

function getReportsForProject(userId, projectPath) {
  const name = path.basename(projectPath);
  const reportsDir = userReportsDir(userId);
  const reports = [];
  try {
    for (const f of fs.readdirSync(reportsDir)) {
      if (f.startsWith(name + '-') && f.endsWith('.html')) {
        const stat = fs.statSync(path.join(reportsDir, f));
        reports.push({ file: f, date: stat.mtime.toISOString(), size: stat.size });
      }
    }
  } catch (e) { /* ignore */ }
  return reports.sort((a, b) => b.date.localeCompare(a.date));
}

function scanProject(userId, projectPath) {
  const name = path.basename(projectPath);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportsDir = userReportsDir(userId);
  const reportFile = path.join(reportsDir, `${name}-${timestamp}.html`);

  try {
    const indexPath = path.join(__dirname, 'index.js');
    const output = execSync(`node "${indexPath}" "${projectPath}" --output "${reportFile}"`, {
      cwd: __dirname, timeout: 30000, encoding: 'utf-8',
    });
    console.log(output);

    let score = null, grade = null;
    if (fs.existsSync(reportFile)) {
      const html = fs.readFileSync(reportFile, 'utf-8');
      const sm = html.match(/class="score-value"[^>]*>(\d+)/);
      const gm = html.match(/class="score-grade"[^>]*>([^<]+)/);
      if (sm) score = parseInt(sm[1]);
      if (gm) grade = gm[1].trim();
    }
    return { success: true, reportFile: path.relative(__dirname, reportFile), score, grade };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Passport / Google OAuth ──────────────────────────────────
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `http://localhost:${PORT}/auth/google/callback`,
}, (accessToken, refreshToken, profile, done) => {
  // Store the minimal profile info we need
  const user = {
    id: profile.id,
    name: profile.displayName,
    email: (profile.emails && profile.emails[0]) ? profile.emails[0].value : '',
    photo: (profile.photos && profile.photos[0]) ? profile.photos[0].value : '',
  };
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ─── Express App ──────────────────────────────────────────────
const app = express();
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }, // 7 days
}));

app.use(passport.initialize());
app.use(passport.session());

// ─── Auth middleware ──────────────────────────────────────────
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated' });
  res.redirect('/login');
}

// ─── Auth routes ──────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.send(loginPageHTML());
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/')
);

app.get('/auth/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/login');
  });
});

// ─── API: current user ────────────────────────────────────────
app.get('/api/me', isAuthenticated, (req, res) => {
  res.json({ user: req.user });
});

// ─── Serve report files (user-scoped) ─────────────────────────
app.get('/reports/:userId/:file', isAuthenticated, (req, res) => {
  // Only the owning user may view their reports
  if (req.params.userId !== req.user.id) {
    return res.status(403).send('Forbidden');
  }
  const fileName = path.basename(req.params.file);
  const reportsDir = userReportsDir(req.user.id);
  const filePath = path.join(reportsDir, fileName);
  if (fs.existsSync(filePath)) {
    res.type('text/html').send(fs.readFileSync(filePath, 'utf-8'));
  } else {
    res.status(404).send('Report not found');
  }
});

// Backwards-compat: handle old /reports/:file paths if the file ends up in root reports dir
app.get('/reports/:file', isAuthenticated, (req, res) => {
  const fileName = path.basename(req.params.file);
  const filePath = path.join(userReportsDir(req.user.id), fileName);
  if (fs.existsSync(filePath)) {
    res.type('text/html').send(fs.readFileSync(filePath, 'utf-8'));
  } else {
    res.status(404).send('Report not found');
  }
});

// ─── API: Browse folder (macOS) ───────────────────────────────
app.get('/api/browse', isAuthenticated, (req, res) => {
  try {
    const cmd = `osascript -e 'try' -e 'return POSIX path of (choose folder with prompt "Select a project to scan:")' -e 'end try'`;
    const result = execSync(cmd, { encoding: 'utf-8' }).trim();
    res.json({ path: result });
  } catch (e) {
    res.json({ path: '' });
  }
});

// ─── API: List projects ───────────────────────────────────────
app.get('/api/projects', isAuthenticated, (req, res) => {
  const projects = loadProjects(req.user.id);
  for (const p of projects) {
    p.reports = getReportsForProject(req.user.id, p.path);
  }
  res.json({ projects });
});

// ─── API: Add project ─────────────────────────────────────────
app.post('/api/projects', isAuthenticated, (req, res) => {
  try {
    const { path: projPath } = req.body;
    const resolved = path.resolve(projPath);
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
      return res.status(400).json({ error: 'Directory not found: ' + resolved });
    }

    const userId = req.user.id;
    const projects = loadProjects(userId);
    if (!projects.find(p => p.path === resolved)) {
      projects.push({ path: resolved, addedAt: new Date().toISOString() });
      saveProjects(userId, projects);
    }

    const scan = scanProject(userId, resolved);
    if (scan.success && scan.score != null) {
      const updated = loadProjects(userId);
      const proj = updated.find(p => p.path === resolved);
      if (proj) { proj.lastScore = scan.score; saveProjects(userId, updated); }
    }

    res.json({ ok: true, scan });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── API: Remove project ──────────────────────────────────────
app.delete('/api/projects', isAuthenticated, (req, res) => {
  try {
    const { path: projPath } = req.body;
    const userId = req.user.id;
    const projects = loadProjects(userId).filter(p => p.path !== projPath);
    saveProjects(userId, projects);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── API: Scan project ────────────────────────────────────────
app.post('/api/scan', isAuthenticated, (req, res) => {
  try {
    const { path: projPath } = req.body;
    const userId = req.user.id;
    const projects = loadProjects(userId);
    if (!projects.find(p => p.path === projPath)) {
      return res.status(403).json({ error: 'Unauthorized project path' });
    }

    const scan = scanProject(userId, projPath);
    if (scan.success && scan.score != null) {
      const updated = loadProjects(userId);
      const proj = updated.find(p => p.path === projPath);
      if (proj) { proj.lastScore = scan.score; saveProjects(userId, updated); }
    }
    res.json(scan);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Dashboard page ───────────────────────────────────────────
app.get('/', isAuthenticated, (req, res) => {
  res.send(dashboardHTML(req.user));
});

// 404
app.use((req, res) => res.status(404).send('Not found'));

// ─── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  const c = {
    reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
    magenta: '\x1b[35m', cyan: '\x1b[36m',
  };

  if (!process.env.GOOGLE_CLIENT_ID) {
    console.log(`\n  \x1b[33m⚠  No GOOGLE_CLIENT_ID found in .env\x1b[0m`);
    console.log(`  \x1b[2mCreate a .env file — see .env.example for instructions.\x1b[0m\n`);
  }

  console.log('');
  console.log(`${c.bold}${c.magenta}  🛡️  Security Review Agent — Dashboard${c.reset}`);
  console.log(`${c.dim}  ─────────────────────────────────────────${c.reset}`);
  console.log(`  ${c.cyan}Running at:${c.reset} http://localhost:${PORT}`);
  console.log('');
  console.log(`${c.dim}  Press Ctrl+C to stop${c.reset}`);
  console.log('');

  try { execSync('open http://localhost:' + PORT); } catch (e) { /* ignore */ }
});

// ─── Login page HTML ──────────────────────────────────────────
function loginPageHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — Security Review Agent</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background: #0a0a0f;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }
    .bg-effects { position: fixed; inset: 0; pointer-events: none; z-index: 0; }
    .blob { position: absolute; border-radius: 50%; filter: blur(140px); opacity: 0.35; }
    .blob-1 { width:700px;height:700px; background:radial-gradient(circle,rgba(102,126,234,0.25),transparent); top:-200px;left:-200px; }
    .blob-2 { width:600px;height:600px; background:radial-gradient(circle,rgba(118,75,162,0.2),transparent); bottom:-150px;right:-150px; }
    .blob-3 { width:400px;height:400px; background:radial-gradient(circle,rgba(34,197,94,0.1),transparent); top:50%;left:50%;transform:translate(-50%,-50%); }

    .card {
      position:relative; z-index:1;
      background: rgba(26, 26, 46, 0.85);
      backdrop-filter: blur(24px);
      border: 1px solid rgba(255,255,255,0.07);
      border-radius: 28px;
      padding: 56px 48px;
      width: 100%;
      max-width: 420px;
      text-align: center;
      box-shadow: 0 32px 80px rgba(0,0,0,0.5), 0 0 0 1px rgba(102,126,234,0.1);
      animation: fadeIn 0.5s ease;
    }
    @keyframes fadeIn { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }

    .shield { font-size: 3rem; margin-bottom: 20px; display: block; filter: drop-shadow(0 0 24px rgba(102,126,234,0.6)); }

    h1 {
      font-size: 1.6rem; font-weight: 800; letter-spacing: -0.02em;
      background: linear-gradient(135deg, #667eea, #764ba2);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text; margin-bottom: 8px;
    }
    p { color: #64748b; font-size: 0.88rem; margin-bottom: 40px; line-height: 1.6; }

    .google-btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 12px;
      width: 100%; padding: 14px 24px;
      background: #fff; color: #1a1a2e;
      border: none; border-radius: 14px;
      font-family: 'Inter', sans-serif; font-size: 0.95rem; font-weight: 600;
      cursor: pointer; text-decoration: none;
      transition: all 0.2s;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    .google-btn:hover { transform: translateY(-2px); box-shadow: 0 8px 32px rgba(0,0,0,0.4); background: #f8f8f8; }
    .google-btn:active { transform: translateY(0); }

    .google-logo { width: 20px; height: 20px; flex-shrink: 0; }

    .divider { margin: 28px 0; border: none; border-top: 1px solid rgba(255,255,255,0.06); }

    .footer-note { color: #475569; font-size: 0.78rem; }
    .footer-note strong { color: #64748b; }
  </style>
</head>
<body>
  <div class="bg-effects">
    <div class="blob blob-1"></div>
    <div class="blob blob-2"></div>
    <div class="blob blob-3"></div>
  </div>
  <div class="card">
    <span class="shield">🛡️</span>
    <h1>Security Review Agent</h1>
    <p>Sign in to access your project dashboard,<br>scan history, and security reports.</p>

    <a href="/auth/google" class="google-btn">
      <svg class="google-logo" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
      Continue with Google
    </a>

    <hr class="divider">
    <p class="footer-note">
      Your projects and reports are <strong>private to your account</strong>.<br>
      No one else can see your data.
    </p>
  </div>
</body>
</html>`;
}

// ─── Dashboard HTML ───────────────────────────────────────────
function dashboardHTML(user) {
  // We inject the user info server-side so the dashboard can show the avatar/name
  const userJSON = JSON.stringify({ name: user.name, email: user.email, photo: user.photo });
  // Read the original dashboardHTML content and inject the user data + user-nav
  return buildDashboard(userJSON);
}

function buildDashboard(userJSON) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Review Agent — Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.9/purify.min.js" integrity="sha512-9+rVhVEXO/8ekbg3x5xJb10sX2OQkQz3Sok120W+A5yGncsqHng16P1810U09iT1BvFP+X5sTz//S3o/JkRz6Q==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg-primary: #0a0a0f;
      --bg-secondary: #12121a;
      --bg-card: #1a1a2e;
      --bg-card-hover: #1e1e35;
      --border: rgba(255,255,255,0.06);
      --text-primary: #e2e8f0;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      --accent-solid: #667eea;
    }

    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      min-height: 100vh;
    }

    .bg-effects { position: fixed; top: 0; left: 0; right: 0; bottom: 0; pointer-events: none; z-index: 0; overflow: hidden; }
    .bg-blob { position: absolute; border-radius: 50%; filter: blur(120px); opacity: 0.4; }
    .bg-blob.one { width: 600px; height: 600px; background: radial-gradient(circle, rgba(102,126,234,0.2), transparent); top: -200px; left: -100px; }
    .bg-blob.two { width: 500px; height: 500px; background: radial-gradient(circle, rgba(118,75,162,0.15), transparent); bottom: -150px; right: -100px; }

    .container { position: relative; z-index: 1; max-width: 800px; margin: 0 auto; padding: 48px 24px 80px; }

    /* ── User nav bar ─────────────────── */
    .user-nav {
      position: fixed; top: 0; left: 0; right: 0; z-index: 100;
      background: rgba(10,10,15,0.85); backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: flex-end;
      padding: 10px 24px; gap: 12px;
    }
    .user-avatar {
      width: 32px; height: 32px; border-radius: 50%;
      border: 2px solid rgba(102,126,234,0.5);
      object-fit: cover;
    }
    .user-name { font-size: 0.85rem; font-weight: 500; color: var(--text-secondary); }
    .logout-btn {
      background: rgba(255,255,255,0.05); border: 1px solid var(--border);
      color: var(--text-muted); border-radius: 8px; padding: 5px 12px;
      font-size: 0.8rem; cursor: pointer; text-decoration: none;
      transition: all 0.2s;
    }
    .logout-btn:hover { background: rgba(255,255,255,0.08); color: var(--text-secondary); }

    /* push content below nav bar */
    .container { padding-top: 80px; }

    header { text-align: center; margin-bottom: 48px; }
    header h1 {
      font-size: 2.2rem; font-weight: 800;
      background: var(--accent-gradient);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text; margin-bottom: 8px; letter-spacing: -0.02em;
    }
    header p { color: var(--text-secondary); font-size: 0.9rem; }

    .add-section {
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: 20px; padding: 28px; margin-bottom: 32px;
      position: relative; overflow: hidden;
    }
    .add-section::before {
      content: ''; position: absolute; top: 0; left: 0; right: 0;
      height: 2px; background: var(--accent-gradient);
    }
    .add-section h2 { font-size: 1rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }

    .input-row { display: flex; gap: 12px; }

    .path-input {
      flex: 1; background: var(--bg-secondary); border: 1px solid var(--border);
      border-radius: 12px; padding: 12px 16px; color: var(--text-primary);
      font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; outline: none; transition: border-color 0.2s;
    }
    .path-input::placeholder { color: var(--text-muted); }
    .path-input:focus { border-color: var(--accent-solid); }

    .add-btn, .scan-btn, .scan-now-btn, .browse-btn {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 12px 24px; border: none; border-radius: 12px;
      font-family: 'Inter', sans-serif; font-size: 0.85rem; font-weight: 600;
      cursor: pointer; transition: all 0.2s; white-space: nowrap;
    }
    .browse-btn { background: var(--bg-secondary); color: var(--text-primary); border: 1px solid var(--border); box-shadow: 0 4px 16px rgba(0,0,0,0.1); }
    .browse-btn:hover { background: rgba(255,255,255,0.05); transform: translateY(-1px); }
    .add-btn { background: var(--accent-gradient); color: #fff; box-shadow: 0 4px 20px rgba(102,126,234,0.35); }
    .add-btn:hover { transform: translateY(-1px); box-shadow: 0 8px 28px rgba(102,126,234,0.45); }
    .add-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

    .projects-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
    .projects-header h2 { font-size: 1rem; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .project-count { background: rgba(102,126,234,0.15); color: var(--accent-solid); border-radius: 20px; padding: 2px 10px; font-size: 0.75rem; font-weight: 600; }

    .projects-list { display: flex; flex-direction: column; gap: 12px; }

    .project-card {
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: 16px; padding: 20px 24px; transition: all 0.2s;
    }
    .project-card:hover { background: var(--bg-card-hover); border-color: rgba(255,255,255,0.1); transform: translateY(-1px); }
    .project-top { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .project-info { flex: 1; min-width: 0; }
    .project-name { font-size: 0.95rem; font-weight: 600; margin-bottom: 4px; }
    .project-path { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .project-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }

    .score-badge {
      font-size: 0.8rem; font-weight: 700; padding: 4px 12px; border-radius: 20px;
    }
    .scan-btn { padding: 8px 16px; font-size: 0.8rem; background: rgba(102,126,234,0.12); color: var(--accent-solid); border: 1px solid rgba(102,126,234,0.2); }
    .scan-btn:hover { background: rgba(102,126,234,0.2); transform: translateY(-1px); }
    .scan-now-btn { padding: 8px 16px; font-size: 0.8rem; background: var(--accent-gradient); color: #fff; box-shadow: 0 4px 16px rgba(102,126,234,0.3); }
    .scan-now-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(102,126,234,0.4); }
    .remove-btn {
      background: transparent; border: 1px solid rgba(239,68,68,0.2); color: rgba(239,68,68,0.5);
      border-radius: 8px; padding: 6px 10px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s; flex-shrink: 0;
    }
    .remove-btn:hover { background: rgba(239,68,68,0.1); color: #ef4444; border-color: rgba(239,68,68,0.4); }

    .history-toggle { background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 0.78rem; padding: 4px 8px; border-radius: 6px; transition: color 0.2s; display: flex; align-items: center; gap: 4px; }
    .history-toggle:hover { color: var(--text-secondary); }

    .history-section { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); display: none; }
    .history-section.open { display: block; }
    .history-section h4 { font-size: 0.78rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 10px; }
    .history-list { display: flex; flex-direction: column; gap: 6px; }
    .history-item { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: var(--bg-secondary); border-radius: 8px; font-size: 0.8rem; }
    .history-item-date { color: var(--text-muted); }
    .history-item-actions { display: flex; align-items: center; gap: 8px; }
    .view-report-btn { background: rgba(102,126,234,0.1); border: 1px solid rgba(102,126,234,0.2); color: var(--accent-solid); border-radius: 6px; padding: 4px 10px; font-size: 0.75rem; cursor: pointer; text-decoration: none; transition: all 0.2s; }
    .view-report-btn:hover { background: rgba(102,126,234,0.2); }

    .empty-state { text-align: center; padding: 64px 24px; color: var(--text-muted); }
    .empty-state .icon { font-size: 3rem; margin-bottom: 16px; opacity: 0.4; }
    .empty-state h3 { font-size: 1.1rem; font-weight: 600; margin-bottom: 8px; color: var(--text-secondary); }
    .empty-state p { font-size: 0.88rem; }

    .toast {
      position: fixed; bottom: 24px; right: 24px; z-index: 1000;
      background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
      padding: 14px 20px; font-size: 0.85rem; box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      transform: translateY(100px); opacity: 0; transition: all 0.3s;
    }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast.success { border-color: rgba(34,197,94,0.3); color: #22c55e; }
    .toast.error   { border-color: rgba(239,68,68,0.3);  color: #ef4444; }

    .overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px);
      z-index: 200; display: flex; align-items: center; justify-content: center; opacity: 0; visibility: hidden; transition: all 0.3s;
    }
    .overlay.show { opacity: 1; visibility: visible; }
    .overlay-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 20px; padding: 32px; text-align: center; min-width: 280px; }
    .overlay-card .spinner { font-size: 2rem; animation: spin 1s linear infinite; display: block; margin-bottom: 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .overlay-card p { color: var(--text-secondary); font-size: 0.9rem; }
    .overlay-card strong { color: var(--text-primary); font-weight: 600; }
  </style>
</head>
<body>
  <div class="bg-effects">
    <div class="bg-blob one"></div>
    <div class="bg-blob two"></div>
  </div>

  <!-- User nav bar -->
  <nav class="user-nav" id="userNav"></nav>

  <div class="container">
    <header>
      <h1>🛡️ Security Review Agent</h1>
      <p>Scan your projects for vulnerabilities and track fixes over time.</p>
    </header>

    <div class="add-section">
      <h2>➕ Add Project</h2>
      <div class="input-row">
        <input type="text" class="path-input" id="pathInput" placeholder="/Users/you/projects/my-app" />
        <button class="browse-btn" onclick="browseFolder()">📂 Browse</button>
        <button class="add-btn" id="addBtn" onclick="addProject()">Scan & Add</button>
      </div>
    </div>

    <div class="projects-header">
      <h2>📁 Projects <span class="project-count" id="projectCount">0</span></h2>
    </div>

    <div class="projects-list" id="projectsList">
      <div class="empty-state">
        <div class="icon">🔍</div>
        <h3>Loading…</h3>
      </div>
    </div>
  </div>

  <div class="toast" id="toast"></div>
  <div class="overlay" id="overlay">
    <div class="overlay-card">
      <span class="spinner">⚙️</span>
      <p>Scanning <strong id="overlayName">project</strong>…<br><span style="font-size:0.78rem;color:var(--text-muted)">This may take a few seconds</span></p>
    </div>
  </div>

  <script>
    const _CURRENT_USER = ${userJSON};

    // Build user nav
    (function() {
      const nav = document.getElementById('userNav');
      const img = _CURRENT_USER.photo
        ? \`<img class="user-avatar" src="\${_CURRENT_USER.photo}" alt="">\`
        : \`<span style="font-size:1.4rem">👤</span>\`;
      nav.innerHTML = img
        + \`<span class="user-name">\${_CURRENT_USER.name || _CURRENT_USER.email}</span>\`
        + \`<a href="/auth/logout" class="logout-btn">Sign out</a>\`;
    })();

    function showToast(msg, isError) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.className = 'toast show ' + (isError ? 'error' : 'success');
      setTimeout(() => t.className = 'toast', 3000);
    }

    function showOverlay(name) {
      document.getElementById('overlayName').textContent = name;
      document.getElementById('overlay').classList.add('show');
    }

    function hideOverlay() { document.getElementById('overlay').classList.remove('show'); }

    async function loadProjects() {
      try {
        const data = await fetch('/api/projects').then(r => r.json());
        renderProjects(data.projects || []);
      } catch(e) { showToast('Failed to load projects', true); }
    }

    async function browseFolder() {
      try {
        const data = await fetch('/api/browse').then(r => r.json());
        if (data.path) document.getElementById('pathInput').value = data.path;
      } catch(e) { /* ignore */ }
    }

    async function addProject() {
      const val = document.getElementById('pathInput').value.trim();
      if (!val) return showToast('Please enter a project path', true);
      const btn = document.getElementById('addBtn');
      btn.disabled = true;
      showOverlay(val.split('/').pop() || val);
      try {
        const data = await fetch('/api/projects', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ path: val })
        }).then(r => r.json());
        if (data.error) { showToast(data.error, true); }
        else {
          showToast('Project added and scanned! ✓');
          document.getElementById('pathInput').value = '';
          if (data.scan?.reportFile) {
            const reportName = data.scan.reportFile.split('/').pop();
            window.open('/reports/' + reportName, '_blank', 'noopener,noreferrer');
          }
          loadProjects();
        }
      } catch(e) { showToast('Error: ' + e.message, true); }
      finally { btn.disabled = false; hideOverlay(); }
    }

    async function scanProjectNow(projectPath) {
      showOverlay(projectPath.split('/').pop());
      try {
        const data = await fetch('/api/scan', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ path: projectPath })
        }).then(r => r.json());
        if (data.error) { showToast(data.error, true); }
        else {
          showToast('Scan complete! ✓');
          if (data.reportFile) {
            const reportName = data.reportFile.split('/').pop();
            window.open('/reports/' + reportName, '_blank', 'noopener,noreferrer');
          }
          loadProjects();
        }
      } catch(e) { showToast('Scan failed: ' + e.message, true); }
      finally { hideOverlay(); }
    }

    async function removeProject(projectPath) {
      if (!confirm('Remove this project from your dashboard?')) return;
      try {
        await fetch('/api/projects', {
          method: 'DELETE', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ path: projectPath })
        });
        showToast('Project removed');
        loadProjects();
      } catch(e) { showToast('Error removing project', true); }
    }

    function toggleHistory(id) {
      const el = document.getElementById('history-' + id);
      if (el) el.classList.toggle('open');
    }

    function getScoreColor(score) {
      if (score == null) return '#64748b';
      if (score >= 90) return '#22c55e';
      if (score >= 75) return '#84cc16';
      if (score >= 60) return '#eab308';
      if (score >= 40) return '#f97316';
      return '#ef4444';
    }

    function renderProjects(projects) {
      const container = document.getElementById('projectsList');
      const counter   = document.getElementById('projectCount');
      counter.textContent = projects.length;

      if (projects.length === 0) {
        container.innerHTML = \`<div class="empty-state"><div class="icon">📂</div><h3>No projects yet</h3><p>Add a project path above to start scanning.</p></div>\`;
        return;
      }

      container.innerHTML = projects.map((p, i) => {
        const name  = p.path.split('/').pop();
        const score = p.lastScore;
        const color = getScoreColor(score);
        const scoreBadge = score != null
          ? \`<span class="score-badge" style="background:rgba(\${score>=75?'34,197,94':score>=50?'234,179,8':'239,68,68'},0.12);color:\${color}">\${score}/100</span>\`
          : \`<span class="score-badge" style="background:rgba(148,163,184,0.1);color:#64748b">Not scanned</span>\`;

        const reportsHTML = p.reports && p.reports.length > 0
          ? p.reports.map(r => \`<div class="history-item">
              <span class="history-item-date">\${new Date(r.date).toLocaleString()}</span>
              <div class="history-item-actions">
                <a href="/reports/\${encodeURIComponent(r.file)}" target="_blank" rel="noopener noreferrer" class="view-report-btn">View Report →</a>
              </div>
            </div>\`).join('')
          : \`<p style="color:var(--text-muted);font-size:0.8rem">No reports yet.</p>\`;

        return \`<div class="project-card">
          <div class="project-top">
            <div class="project-info">
              <div class="project-name">\${DOMPurify.sanitize(name)}</div>
              <div class="project-path">\${DOMPurify.sanitize(p.path)}</div>
            </div>
            <div class="project-actions">
              \${scoreBadge}
              <button class="scan-now-btn" onclick="scanProjectNow('\${DOMPurify.sanitize(p.path).replace(/'/g,\"\\\\'\")}')">⚡ Scan</button>
              <button class="history-toggle" onclick="toggleHistory(\${i})">🕘 History</button>
              <button class="remove-btn" onclick="removeProject('\${DOMPurify.sanitize(p.path).replace(/'/g,\"\\\\'\")}')">✕</button>
            </div>
          </div>
          <div class="history-section" id="history-\${i}">
            <h4>Scan History</h4>
            <div class="history-list">\${reportsHTML}</div>
          </div>
        </div>\`;
      }).join('');
    }

    loadProjects();
  </script>
</body>
</html>`;
}
