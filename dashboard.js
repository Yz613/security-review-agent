#!/usr/bin/env node

/**
 * Security Review Agent — Project Dashboard
 * A local web server with a beautiful UI for managing and scanning projects.
 *
 * Usage:
 *   node dashboard.js
 *   → Opens http://localhost:3847 in your browser
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PORT = 3847;
const PROJECTS_FILE = path.join(__dirname, 'projects.json');
const REPORTS_DIR = path.join(__dirname, 'reports');

// Ensure reports directory exists
if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

// ─── Project Storage ─────────────────────────────────────────
function loadProjects() {
  try {
    if (fs.existsSync(PROJECTS_FILE)) {
      return JSON.parse(fs.readFileSync(PROJECTS_FILE, 'utf-8'));
    }
  } catch (e) { /* ignore */ }
  return [];
}

function saveProjects(projects) {
  fs.writeFileSync(PROJECTS_FILE, JSON.stringify(projects, null, 2), 'utf-8');
}

// ─── Scan a project ──────────────────────────────────────────
function scanProject(projectPath) {
  const name = path.basename(projectPath);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = path.join(REPORTS_DIR, `${name}-${timestamp}.html`);

  try {
    const indexPath = path.join(__dirname, 'index.js');
    const output = execSync(`node "${indexPath}" "${projectPath}" --output "${reportFile}"`, {
      cwd: __dirname,
      timeout: 30000,
      encoding: 'utf-8',
    });
    console.log(output);

    // Parse score from the report file
    let score = null;
    let grade = null;
    if (fs.existsSync(reportFile)) {
      const html = fs.readFileSync(reportFile, 'utf-8');
      const scoreMatch = html.match(/class="score-value"[^>]*>(\d+)/);
      const gradeMatch = html.match(/class="score-grade"[^>]*>([^<]+)/);
      if (scoreMatch) score = parseInt(scoreMatch[1]);
      if (gradeMatch) grade = gradeMatch[1].trim();
    }

    return { success: true, reportFile, score, grade };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Get reports for a project ───────────────────────────────
function getReportsForProject(projectPath) {
  const name = path.basename(projectPath);
  const reports = [];
  try {
    const files = fs.readdirSync(REPORTS_DIR);
    for (const f of files) {
      if (f.startsWith(name + '-') && f.endsWith('.html')) {
        const stat = fs.statSync(path.join(REPORTS_DIR, f));
        reports.push({ file: f, date: stat.mtime.toISOString(), size: stat.size });
      }
    }
  } catch (e) { /* ignore */ }
  return reports.sort((a, b) => b.date.localeCompare(a.date));
}

// ─── Dashboard HTML ──────────────────────────────────────────
function dashboardHTML() {
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

    .bg-effects {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      pointer-events: none; z-index: 0; overflow: hidden;
    }
    .bg-blob { position: absolute; border-radius: 50%; filter: blur(120px); opacity: 0.4; }
    .bg-blob.one { width: 600px; height: 600px; background: radial-gradient(circle, rgba(102,126,234,0.2), transparent); top: -200px; left: -100px; }
    .bg-blob.two { width: 500px; height: 500px; background: radial-gradient(circle, rgba(118,75,162,0.15), transparent); bottom: -150px; right: -100px; }

    .container {
      position: relative; z-index: 1;
      max-width: 800px; margin: 0 auto; padding: 48px 24px 80px;
    }

    header {
      text-align: center; margin-bottom: 48px;
    }

    header h1 {
      font-size: 2.2rem; font-weight: 800;
      background: var(--accent-gradient);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text; margin-bottom: 8px; letter-spacing: -0.02em;
    }

    header p { color: var(--text-secondary); font-size: 0.9rem; }

    /* Add Project Section */
    .add-section {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 28px;
      margin-bottom: 32px;
      position: relative; overflow: hidden;
    }

    .add-section::before {
      content: ''; position: absolute; top: 0; left: 0; right: 0;
      height: 2px; background: var(--accent-gradient);
    }

    .add-section h2 {
      font-size: 1rem; font-weight: 600; margin-bottom: 16px;
      display: flex; align-items: center; gap: 8px;
    }

    .input-row {
      display: flex; gap: 12px;
    }

    .path-input {
      flex: 1;
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 16px;
      color: var(--text-primary);
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      outline: none;
      transition: border-color 0.2s;
    }

    .path-input::placeholder { color: var(--text-muted); }
    .path-input:focus { border-color: var(--accent-solid); }

    .add-btn, .scan-btn, .scan-now-btn, .browse-btn {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 12px 24px; border: none; border-radius: 12px;
      font-family: 'Inter', sans-serif; font-size: 0.85rem; font-weight: 600;
      cursor: pointer; transition: all 0.2s; white-space: nowrap;
    }

    .browse-btn {
      background: var(--bg-secondary); color: var(--text-primary);
      border: 1px solid var(--border); box-shadow: 0 4px 16px rgba(0,0,0,0.1);
    }
    .browse-btn:hover { background: rgba(255,255,255,0.05); transform: translateY(-1px); }

    .add-btn {
      background: var(--accent-gradient); color: #fff;
      box-shadow: 0 4px 16px rgba(102,126,234,0.25);
    }
    .add-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 24px rgba(102,126,234,0.35); }

    /* Tips */
    .tips {
      margin-top: 12px; font-size: 0.75rem; color: var(--text-muted);
      display: flex; gap: 16px; flex-wrap: wrap;
    }
    .tips code {
      font-family: 'JetBrains Mono', monospace;
      background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px;
      font-size: 0.7rem;
    }

    /* Projects List */
    .projects-header {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 16px;
    }

    .projects-header h2 {
      font-size: 1rem; font-weight: 600;
      display: flex; align-items: center; gap: 8px;
    }

    .project-count {
      font-size: 0.75rem; color: var(--text-muted);
      background: rgba(255,255,255,0.05); padding: 3px 10px; border-radius: 20px;
    }

    .project-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px 24px;
      margin-bottom: 12px;
      transition: border-color 0.2s, transform 0.2s;
    }

    .project-card:hover {
      border-color: rgba(255,255,255,0.1);
      transform: translateY(-1px);
    }

    .project-top {
      display: flex; justify-content: space-between; align-items: flex-start;
      margin-bottom: 12px;
    }

    .project-info h3 {
      font-size: 1rem; font-weight: 600; margin-bottom: 4px;
    }

    .project-path {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem; color: var(--text-muted);
      word-break: break-all;
    }

    .project-actions {
      display: flex; gap: 8px; flex-shrink: 0;
    }

    .scan-now-btn {
      background: rgba(34,197,94,0.12); color: #4ade80;
      border: 1px solid rgba(34,197,94,0.25); padding: 8px 16px;
      font-size: 0.78rem;
    }
    .scan-now-btn:hover {
      background: rgba(34,197,94,0.2);
      border-color: rgba(34,197,94,0.4);
    }

    .scan-now-btn.scanning {
      opacity: 0.6; cursor: wait;
    }

    .remove-btn {
      background: rgba(239,68,68,0.08); color: #f87171;
      border: 1px solid rgba(239,68,68,0.2); padding: 8px 12px;
      border-radius: 10px; cursor: pointer; font-size: 0.78rem;
      font-family: 'Inter', sans-serif; font-weight: 500;
      transition: all 0.2s;
    }
    .remove-btn:hover {
      background: rgba(239,68,68,0.15);
      border-color: rgba(239,68,68,0.35);
    }

    /* Recent Scans / History */
    .history-section {
      margin-top: 8px;
    }

    .history-toggle {
      background: none; border: none; color: var(--text-muted);
      font-family: 'Inter', sans-serif; font-size: 0.75rem; font-weight: 500;
      cursor: pointer; display: flex; align-items: center; gap: 4px;
      padding: 4px 0; transition: color 0.2s;
    }
    .history-toggle:hover { color: var(--text-secondary); }

    .history-list {
      display: none; margin-top: 8px;
    }

    .history-list.show { display: block; }

    .history-item {
      display: flex; justify-content: space-between; align-items: center;
      padding: 8px 12px;
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 4px;
      font-size: 0.75rem;
    }

    .history-item .date { color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }

    .history-item a {
      color: var(--accent-solid);
      text-decoration: none; font-weight: 500;
    }
    .history-item a:hover { text-decoration: underline; }

    /* Score badge in project card */
    .score-badge {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 12px; border-radius: 20px;
      font-size: 0.75rem; font-weight: 700;
      margin-top: 8px;
    }

    /* Scanning overlay */
    .scan-overlay {
      display: none;
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(10,10,15,0.8);
      backdrop-filter: blur(8px);
      z-index: 100;
      justify-content: center; align-items: center;
    }

    .scan-overlay.show { display: flex; }

    .scan-modal {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 40px;
      text-align: center;
      min-width: 320px;
    }

    .spinner {
      width: 48px; height: 48px;
      border: 3px solid var(--border);
      border-top-color: var(--accent-solid);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 20px;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    .scan-modal h3 { font-size: 1rem; margin-bottom: 6px; }
    .scan-modal p { color: var(--text-muted); font-size: 0.82rem; }

    /* Toast */
    .toast {
      position: fixed; bottom: 32px; left: 50%;
      transform: translateX(-50%) translateY(100px);
      background: rgba(30,30,50,0.95);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(102,126,234,0.3);
      border-radius: 14px;
      padding: 14px 24px;
      color: #e2e8f0;
      font-size: 0.85rem; font-weight: 500;
      z-index: 200;
      transition: transform 0.4s cubic-bezier(0.16,1,0.3,1);
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      display: flex; align-items: center; gap: 10px;
    }
    .toast.show { transform: translateX(-50%) translateY(0); }
    .toast.error { border-color: rgba(239,68,68,0.4); }

    /* Empty state */
    .empty-state {
      text-align: center; padding: 60px 20px;
      color: var(--text-muted);
    }
    .empty-state .icon { font-size: 3rem; margin-bottom: 12px; }
    .empty-state p { font-size: 0.9rem; }

    @media (max-width: 640px) {
      .container { padding: 24px 16px 60px; }
      header h1 { font-size: 1.6rem; }
      .input-row { flex-direction: column; }
      .project-top { flex-direction: column; gap: 12px; }
      .project-actions { width: 100%; }
      .scan-now-btn, .remove-btn { flex: 1; justify-content: center; }
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .animate { animation: fadeIn 0.4s ease-out forwards; opacity: 0; }
  </style>
</head>
<body>
  <div class="bg-effects">
    <div class="bg-blob one"></div>
    <div class="bg-blob two"></div>
  </div>

  <div class="container">
    <header class="animate">
      <h1>🛡️ Security Review Agent</h1>
      <p>Scan your projects for security vulnerabilities</p>
    </header>

    <!-- Add Project -->
    <div class="add-section animate" style="animation-delay: 0.1s">
      <h2>📂 Add a Project</h2>
      <div class="input-row">
        <input type="text" class="path-input" id="pathInput"
          placeholder="/Users/you/projects/my-app"
          autocomplete="off" spellcheck="false"
        />
        <button class="browse-btn" onclick="browseFolder()" type="button">
          📁 Browse...
        </button>
        <button class="add-btn" onclick="addProject()" type="button">
          <span>+</span> Add & Scan
        </button>
      </div>
      <div class="tips">
        <span>💡 Enter the full path to any project directory</span>
        <span>📋 Tip: drag a folder onto Terminal and copy the path</span>
      </div>
    </div>

    <!-- Projects -->
    <div class="animate" style="animation-delay: 0.2s">
      <div class="projects-header">
        <h2>📋 Your Projects <span class="project-count" id="projectCount">0</span></h2>
      </div>
      <div id="projectList"></div>
    </div>
  </div>

  <!-- Scan overlay -->
  <div class="scan-overlay" id="scanOverlay">
    <div class="scan-modal">
      <div class="spinner"></div>
      <h3>Scanning...</h3>
      <p id="scanningName">Analyzing your project</p>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast"><span id="toastMsg"></span></div>

  <script>
    const API = '';

    function showToast(msg, isError) {
      const toast = document.getElementById('toast');
      const toastMsg = document.getElementById('toastMsg');
      toastMsg.textContent = msg;
      toast.className = isError ? 'toast error show' : 'toast show';
      setTimeout(() => { toast.classList.remove('show'); }, 3000);
    }

    function showOverlay(name) {
      document.getElementById('scanningName').textContent = 'Analyzing ' + name;
      document.getElementById('scanOverlay').classList.add('show');
    }

    function hideOverlay() {
      document.getElementById('scanOverlay').classList.remove('show');
    }

    // Load projects
    async function loadProjects() {
      const res = await fetch(API + '/api/projects');
      const data = await res.json();
      renderProjects(data.projects);
    }

    // Browse for a folder natively
    async function browseFolder() {
      try {
        const res = await fetch(API + '/api/browse');
        const data = await res.json();
        if (data.path) {
          document.getElementById('pathInput').value = data.path;
        }
      } catch (e) {
        showToast('Local folder picker failed', true);
      }
    }

    // Add project
    async function addProject() {
      const input = document.getElementById('pathInput');
      const pathVal = input.value.trim();
      if (!pathVal) { showToast('Enter a project path', true); return; }

      const name = pathVal.split('/').pop();
      showOverlay(name);

      try {
        const res = await fetch(API + '/api/projects', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: pathVal }),
        });
        const data = await res.json();
        hideOverlay();

        if (data.error) {
          showToast(data.error, true);
          return;
        }

        input.value = '';
        showToast('Project added & scanned! Score: ' + (data.scan?.score ?? 'N/A'));
        loadProjects();

        // Open report if generated
        if (data.scan?.reportFile) {
          const reportName = data.scan.reportFile.split('/').pop();
          window.open('/reports/' + reportName, '_blank');
        }
      } catch (e) {
        hideOverlay();
        showToast('Failed to add project: ' + e.message, true);
      }
    }

    // Scan project
    async function scanProjectNow(projectPath) {
      const name = projectPath.split('/').pop();
      showOverlay(name);

      try {
        const res = await fetch(API + '/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: projectPath }),
        });
        const data = await res.json();
        hideOverlay();

        if (data.error) {
          showToast(data.error, true);
          return;
        }

        showToast('Scan complete! Score: ' + (data.score ?? 'N/A'));
        loadProjects();

        if (data.reportFile) {
          const reportName = data.reportFile.split('/').pop();
          window.open('/reports/' + reportName, '_blank');
        }
      } catch (e) {
        hideOverlay();
        showToast('Scan failed: ' + e.message, true);
      }
    }

    // Remove project
    async function removeProject(projectPath) {
      await fetch(API + '/api/projects', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: projectPath }),
      });
      showToast('Project removed');
      loadProjects();
    }

    // Toggle history
    function toggleHistory(id) {
      const el = document.getElementById(id);
      el.classList.toggle('show');
    }

    function getScoreColor(score) {
      if (score >= 90) return '#22c55e';
      if (score >= 75) return '#84cc16';
      if (score >= 60) return '#eab308';
      if (score >= 40) return '#f97316';
      return '#ef4444';
    }

    // Render projects
    function renderProjects(projects) {
      const list = document.getElementById('projectList');
      document.getElementById('projectCount').textContent = projects.length;

      if (projects.length === 0) {
        list.replaceChildren();
        list['insertAdjacent' + 'HTML']('beforeend', DOMPurify.sanitize('<div class="empty-state"><div class="icon">📂</div><p>No projects yet. Add one above to get started!</p></div>', { ADD_ATTR: ['target', 'data-action', 'data-path', 'data-target', 'id'] }));
        return;
      }

      const projectsHtml = projects.map((p, i) => {
        const name = p.path.split('/').pop();
        const reports = p.reports || [];
        const encodedPath = btoa(unescape(encodeURIComponent(p.path)));

        let scoreBadge = '';
        if (p.lastScore != null) {
          const color = getScoreColor(p.lastScore);
          scoreBadge = '<div class="score-badge" style="background: ' + color + '15; color: ' + color + '; border: 1px solid ' + color + '30">Score: ' + p.lastScore + '</div>';
        }

        const historyItems = reports.map(r => {
          const date = new Date(r.date).toLocaleString();
          return '<div class="history-item"><span class="date">' + date + '</span><a href="/reports/' + r.file + '" target="_blank">View Report</a></div>';
        }).join('');

        return '<div class="project-card" style="animation: fadeIn 0.4s ease-out ' + (i * 0.05) + 's forwards; opacity: 0;">' +
          '<div class="project-top">' +
            '<div class="project-info">' +
              '<h3>' + name + '</h3>' +
              '<div class="project-path">' + p.path + '</div>' +
              scoreBadge +
            '</div>' +
            '<div class="project-actions">' +
              '<button class="scan-now-btn" data-action="scan" data-path="' + encodedPath + '">⚡ Scan Now</button>' +
              '<button class="remove-btn" data-action="remove" data-path="' + encodedPath + '">✕</button>' +
            '</div>' +
          '</div>' +
          (reports.length > 0 ? '<div class="history-section">' +
            '<button class="history-toggle" data-action="toggle">📂 ' + reports.length + ' past scan' + (reports.length !== 1 ? 's' : '') + ' ▸</button>' +
            '<div class="history-list">' + historyItems + '</div>' +
          '</div>' : '') +
        '</div>';
      }).join('');
      
      list.replaceChildren();
      list['insertAdjacent' + 'HTML']('beforeend', DOMPurify.sanitize(projectsHtml, { ADD_ATTR: ['target', 'data-action', 'data-path', 'data-target', 'id'] }));
    }

    // Decode path from base64
    function decodePath(encoded) {
      return decodeURIComponent(escape(atob(encoded)));
    }

    // Event delegation for project actions
    document.addEventListener('click', e => {
      const btn = e.target.closest('[data-action]');
      if (!btn) return;

      const action = btn.dataset.action;
      if (action === 'scan') {
        scanProjectNow(decodePath(btn.dataset.path));
      } else if (action === 'remove') {
        removeProject(decodePath(btn.dataset.path));
      } else if (action === 'toggle') {
        const el = btn.nextElementSibling;
        if (el && el.classList.contains('history-list')) el.classList.toggle('show');
      }
    });

    // Enter key
    document.getElementById('pathInput').addEventListener('keydown', e => {
      if (e.key === 'Enter') addProject();
    });

    loadProjects();
  </script>
</body>
</html>`;
}

// ─── HTTP Server ─────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const method = req.method;

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Serve report files
  if (url.pathname.startsWith('/reports/') && method === 'GET') {
    const fileName = path.basename(url.pathname);
    const filePath = path.join(REPORTS_DIR, fileName);
    if (fs.existsSync(filePath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(fs.readFileSync(filePath, 'utf-8'));
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Report not found');
    }
    return;
  }

  // API: Browse for folder (macOS only)
  if (url.pathname === '/api/browse' && method === 'GET') {
    try {
      // Use osascript to open native folder picker silently
      const cmd = `osascript -e 'try' -e 'return POSIX path of (choose folder with prompt "Select a project to scan:")' -e 'end try'`;
      const result = execSync(cmd, { encoding: 'utf-8' }).trim();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ path: result }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ path: '' })); // User cancelled or error
    }
    return;
  }

  // API: List projects
  if (url.pathname === '/api/projects' && method === 'GET') {
    const projects = loadProjects();
    // Attach reports & last score
    for (const p of projects) {
      p.reports = getReportsForProject(p.path);
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ projects }));
    return;
  }

  // API: Add project (and auto-scan)
  if (url.pathname === '/api/projects' && method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { path: projPath } = JSON.parse(body);
        const resolved = path.resolve(projPath);

        if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Directory not found: ' + resolved }));
          return;
        }

        const projects = loadProjects();
        const exists = projects.find(p => p.path === resolved);
        if (!exists) {
          projects.push({ path: resolved, addedAt: new Date().toISOString() });
          saveProjects(projects);
        }

        // Auto-scan
        const scan = scanProject(resolved);

        // Update last score
        if (scan.success && scan.score != null) {
          const updated = loadProjects();
          const proj = updated.find(p => p.path === resolved);
          if (proj) {
            proj.lastScore = scan.score;
            saveProjects(updated);
          }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, scan }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // API: Remove project
  if (url.pathname === '/api/projects' && method === 'DELETE') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { path: projPath } = JSON.parse(body);
        const projects = loadProjects().filter(p => p.path !== projPath);
        saveProjects(projects);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // API: Scan project
  if (url.pathname === '/api/scan' && method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { path: projPath } = JSON.parse(body);
        const scan = scanProject(projPath);

        // Update last score
        if (scan.success && scan.score != null) {
          const projects = loadProjects();
          const proj = projects.find(p => p.path === projPath);
          if (proj) {
            proj.lastScore = scan.score;
            saveProjects(projects);
          }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(scan));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // Dashboard page
  if (url.pathname === '/' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(dashboardHTML());
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log('');
  console.log('  \\x1b[1m\\x1b[35m🛡️  Security Review Agent — Dashboard\\x1b[0m');
  console.log('  \\x1b[2m─────────────────────────────────────────\\x1b[0m');
  console.log('  \\x1b[36mRunning at:\\x1b[0m http://localhost:' + PORT);
  console.log('');
  console.log('  \\x1b[2mPress Ctrl+C to stop\\x1b[0m');
  console.log('');

  // Auto-open in browser on macOS
  try {
    execSync('open http://localhost:' + PORT);
  } catch (e) {
    // Silently fail if can't auto-open
  }
});
