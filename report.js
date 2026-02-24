/**
 * Security Review Agent — HTML Report Generator
 * Produces a standalone, dark-themed HTML report with findings.
 * V2: Includes "Fix with Antigravity" buttons and "Fix All" action.
 */

const { SEVERITY } = require('./scanners');

const SEVERITY_CONFIG = {
  [SEVERITY.CRITICAL]: { emoji: '🔴', label: 'CRITICAL', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)' },
  [SEVERITY.HIGH]: { emoji: '🟠', label: 'HIGH', color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)' },
  [SEVERITY.MEDIUM]: { emoji: '🟡', label: 'MEDIUM', color: '#eab308', bg: 'rgba(234,179,8,0.12)', border: 'rgba(234,179,8,0.3)' },
  [SEVERITY.LOW]: { emoji: '🔵', label: 'LOW', color: '#3b82f6', bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.3)' },
  [SEVERITY.INFO]: { emoji: '⚪', label: 'INFO', color: '#94a3b8', bg: 'rgba(148,163,184,0.08)', border: 'rgba(148,163,184,0.2)' },
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Safely serialize JSON for embedding in HTML <script> blocks
// Escapes </ sequences that would prematurely close the script tag
function safeJsonForScript(data) {
  return JSON.stringify(data).replace(/<\//g, '<\\/');
}

function escapeJsString(str) {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/`/g, '\\`')
    .replace(/\$/g, '\\$');
}

function buildFixPrompt(f, absBasePath) {
  const absFile = absBasePath + '/' + f.file;
  return `Fix this security issue in my project:\n\nFile: ${absFile}\nLine: ${f.line}\nSeverity: ${f.severity.toUpperCase()}\nIssue: ${f.message}\nCurrent code: ${f.code}\n\nRecommended fix: ${f.remediation}\n\nPlease implement this fix now.`;
}

function buildFixAllPrompt(findings, absBasePath) {
  let prompt = `Fix ALL of the following security issues found in my project at ${absBasePath}:\n\n`;
  findings.forEach((f, i) => {
    const absFile = absBasePath + '/' + f.file;
    prompt += `--- Issue ${i + 1} ---\nFile: ${absFile} (line ${f.line})\nSeverity: ${f.severity.toUpperCase()}\nIssue: ${f.message}\nCode: ${f.code}\nFix: ${f.remediation}\n\n`;
  });
  prompt += `Please implement ALL of these fixes now.`;
  return prompt;
}

function generateReport(findings, scannedFiles, targetDir, score, gradeInfo, scanDuration, absBasePath) {
  // Group by scanner category
  const grouped = {};
  for (const f of findings) {
    if (!grouped[f.scanner]) grouped[f.scanner] = [];
    grouped[f.scanner].push(f);
  }

  // Count by severity
  const counts = {
    [SEVERITY.CRITICAL]: 0,
    [SEVERITY.HIGH]: 0,
    [SEVERITY.MEDIUM]: 0,
    [SEVERITY.LOW]: 0,
    [SEVERITY.INFO]: 0,
  };
  for (const f of findings) counts[f.severity]++;

  const sortedCategories = Object.keys(grouped).sort((a, b) => {
    const severityOrder = [SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW, SEVERITY.INFO];
    const aMax = Math.min(...grouped[a].map(f => severityOrder.indexOf(f.severity)));
    const bMax = Math.min(...grouped[b].map(f => severityOrder.indexOf(f.severity)));
    return aMax - bMax;
  });

  // Build fix prompts array
  const fixableFindings = findings.filter(f => f.severity !== SEVERITY.INFO);
  const fixAllPrompt = fixableFindings.length > 0 ? buildFixAllPrompt(fixableFindings, absBasePath || targetDir) : '';
  const howTo100Prompt = fixableFindings.length > 0
    ? "I am aiming for a perfect 100 security score on this project. Please provide a comprehensive plan to fix the following issues and any other best practices I should implement:\n\n" + fixAllPrompt
    : "I am aiming for a perfect 100 security score on this project. What are the best practices I should implement to maintain this?";

  const allPrompts = []; // Will be serialized into the page as JSON
  let findingIndex = 0;
  const findingsHTML = sortedCategories.map(category => {
    const catFindings = grouped[category];
    const highestSev = catFindings.reduce((max, f) => {
      const order = [SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW, SEVERITY.INFO];
      return order.indexOf(f.severity) < order.indexOf(max) ? f.severity : max;
    }, SEVERITY.INFO);

    const config = SEVERITY_CONFIG[highestSev];

    const findingCards = catFindings.map(f => {
      const fConfig = SEVERITY_CONFIG[f.severity];
      const idx = findingIndex++;
      const isInfo = f.severity === SEVERITY.INFO;
      if (!isInfo) {
        allPrompts.push(buildFixPrompt(f, absBasePath || targetDir));
      }
      return `
        <div class="finding-card" style="border-left: 3px solid ${fConfig.color};">
          <div class="finding-header">
            <span class="severity-badge" style="background: ${fConfig.bg}; color: ${fConfig.color}; border: 1px solid ${fConfig.border};">
              ${fConfig.emoji} ${fConfig.label}
            </span>
            <span class="finding-location">${escapeHtml(f.file)}:${f.line}</span>
          </div>
          <p class="finding-message">${escapeHtml(f.message)}</p>
          <div class="code-block"><code>${escapeHtml(f.code)}</code></div>
          <div class="remediation">
            <strong>💡 Fix:</strong> ${escapeHtml(f.remediation)}
          </div>
          ${!isInfo ? `<button class="fix-btn" data-idx="${idx}" onclick="copyFix(this, ${idx})">
            <span class="fix-btn-icon">⚡</span> Fix with Antigravity
          </button>` : ''}
        </div>`;
    }).join('\n');

    return `
      <div class="category-section">
        <button class="category-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <div class="category-title">
            <span class="category-icon" style="color: ${config.color}">${config.emoji}</span>
            <h3>${escapeHtml(category)}</h3>
            <span class="finding-count">${catFindings.length} finding${catFindings.length !== 1 ? 's' : ''}</span>
          </div>
          <span class="chevron">▼</span>
        </button>
        <div class="category-body">
          ${findingCards}
        </div>
      </div>`;
  }).join('\n');

  const now = new Date().toLocaleString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com;">
  <meta http-equiv="X-Frame-Options" content="DENY">
  <title>Security Report — ${escapeHtml(targetDir)}</title>
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
      --glow-purple: rgba(102,126,234,0.15);
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      min-height: 100vh;
    }

    /* Background Effects */
    .bg-effects {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      pointer-events: none;
      z-index: 0;
      overflow: hidden;
    }

    .bg-blob {
      position: absolute;
      border-radius: 50%;
      filter: blur(120px);
      opacity: 0.4;
    }

    .bg-blob.one {
      width: 600px; height: 600px;
      background: radial-gradient(circle, rgba(102,126,234,0.2), transparent);
      top: -200px; left: -100px;
    }

    .bg-blob.two {
      width: 500px; height: 500px;
      background: radial-gradient(circle, rgba(118,75,162,0.15), transparent);
      bottom: -150px; right: -100px;
    }

    .bg-blob.three {
      width: 300px; height: 300px;
      background: radial-gradient(circle, rgba(239,68,68,0.1), transparent);
      top: 40%; left: 50%;
    }

    /* Container */
    .container {
      position: relative;
      z-index: 1;
      max-width: 960px;
      margin: 0 auto;
      padding: 40px 24px 80px;
    }

    /* Header */
    .report-header {
      text-align: center;
      margin-bottom: 48px;
    }

    .report-header h1 {
      font-size: 2.5rem;
      font-weight: 800;
      background: var(--accent-gradient);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 8px;
      letter-spacing: -0.02em;
    }

    .report-header .subtitle {
      color: var(--text-secondary);
      font-size: 0.95rem;
      font-weight: 400;
    }

    .report-header .meta {
      margin-top: 16px;
      display: flex;
      gap: 24px;
      justify-content: center;
      flex-wrap: wrap;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .report-header .meta span {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    /* Score Section */
    .score-section {
      display: flex;
      justify-content: center;
      margin-bottom: 40px;
    }

    .score-circle-container {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 24px;
      padding: 40px 60px;
      text-align: center;
      position: relative;
      overflow: hidden;
    }

    .score-circle-container::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
      background: var(--accent-gradient);
    }

    .score-circle {
      position: relative;
      width: 160px;
      height: 160px;
      margin: 0 auto 20px;
    }

    .score-circle svg {
      transform: rotate(-90deg);
      width: 160px;
      height: 160px;
    }

    .score-circle .bg-ring {
      fill: none;
      stroke: rgba(255,255,255,0.05);
      stroke-width: 10;
    }

    .score-circle .score-ring {
      fill: none;
      stroke-width: 10;
      stroke-linecap: round;
      stroke-dasharray: 440;
      transition: stroke-dashoffset 1.5s ease-out;
    }

    .score-value {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      font-size: 3rem;
      font-weight: 800;
      letter-spacing: -0.02em;
    }

    .score-grade {
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: 4px;
    }

    .score-label {
      color: var(--text-muted);
      font-size: 0.85rem;
    }

    /* Summary Cards */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 40px;
    }

    .summary-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      text-align: center;
      transition: transform 0.2s, border-color 0.2s;
    }

    .summary-card:hover {
      transform: translateY(-2px);
    }

    .summary-card .count {
      font-size: 2rem;
      font-weight: 700;
      margin-bottom: 4px;
    }

    .summary-card .label {
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 600;
    }

    /* Action Buttons */
    .action-buttons-container {
      display: flex;
      justify-content: center;
      gap: 16px;
      margin-bottom: 32px;
      flex-wrap: wrap;
    }

    .action-btn {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 14px 24px;
      border: none;
      border-radius: 14px;
      font-family: 'Inter', sans-serif;
      font-size: 0.95rem;
      font-weight: 700;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s, background 0.2s, color 0.2s;
      letter-spacing: 0.01em;
    }

    .action-btn:hover {
      transform: translateY(-2px) scale(1.02);
    }

    .action-btn:active {
      transform: translateY(0) scale(0.98);
    }

    .action-btn .icon {
      font-size: 1.2rem;
    }

    .action-btn.primary {
      color: #fff;
      background: var(--accent-gradient);
      box-shadow: 0 4px 20px rgba(102,126,234,0.3);
    }

    .action-btn.primary:hover {
      box-shadow: 0 8px 30px rgba(102,126,234,0.45);
    }

    .action-btn.secondary {
      color: var(--text-primary);
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.1);
    }

    .action-btn.secondary:hover {
      background: rgba(255,255,255,0.15);
      border-color: rgba(255,255,255,0.25);
    }

    .action-btn.copied, .action-btn.success {
      background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
      color: white;
      border: none;
      box-shadow: 0 4px 20px rgba(34,197,94,0.3);
    }

    /* Category Sections */
    .category-section {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      margin-bottom: 16px;
      overflow: hidden;
      transition: border-color 0.2s;
    }

    .category-section:hover {
      border-color: rgba(255,255,255,0.1);
    }

    .category-header {
      width: 100%;
      background: none;
      border: none;
      color: var(--text-primary);
      padding: 20px 24px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: inherit;
      transition: background 0.2s;
    }

    .category-header:hover {
      background: var(--bg-card-hover);
    }

    .category-title {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .category-title h3 {
      font-size: 1rem;
      font-weight: 600;
    }

    .finding-count {
      font-size: 0.75rem;
      color: var(--text-muted);
      background: rgba(255,255,255,0.05);
      padding: 3px 10px;
      border-radius: 20px;
    }

    .chevron {
      font-size: 0.8rem;
      color: var(--text-muted);
      transition: transform 0.3s ease;
    }

    .collapsed .chevron {
      transform: rotate(-90deg);
    }

    .collapsed .category-body {
      display: none;
    }

    .category-body {
      padding: 0 24px 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    /* Finding Cards */
    .finding-card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 16px 20px;
      transition: background 0.2s;
    }

    .finding-card:hover {
      background: rgba(255,255,255,0.03);
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
      flex-wrap: wrap;
      gap: 8px;
    }

    .severity-badge {
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 4px 12px;
      border-radius: 20px;
      white-space: nowrap;
    }

    .finding-location {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--text-muted);
    }

    .finding-message {
      font-size: 0.9rem;
      color: var(--text-primary);
      margin-bottom: 12px;
      font-weight: 500;
    }

    .code-block {
      background: rgba(0,0,0,0.4);
      border: 1px solid rgba(255,255,255,0.04);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 12px;
      overflow-x: auto;
    }

    .code-block code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: #c4b5fd;
      white-space: pre;
    }

    .remediation {
      font-size: 0.82rem;
      color: var(--text-secondary);
      padding: 10px 14px;
      background: rgba(102,126,234,0.06);
      border-radius: 8px;
      border-left: 2px solid rgba(102,126,234,0.4);
      line-height: 1.5;
      margin-bottom: 12px;
    }

    .remediation strong {
      color: #a5b4fc;
    }

    /* Fix Button */
    .fix-btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 18px;
      border: 1px solid rgba(102,126,234,0.3);
      border-radius: 10px;
      font-family: 'Inter', sans-serif;
      font-size: 0.78rem;
      font-weight: 600;
      color: #a5b4fc;
      background: rgba(102,126,234,0.08);
      cursor: pointer;
      transition: all 0.25s ease;
      letter-spacing: 0.01em;
    }

    .fix-btn:hover {
      background: rgba(102,126,234,0.18);
      border-color: rgba(102,126,234,0.5);
      color: #c4b5fd;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(102,126,234,0.2);
    }

    .fix-btn:active {
      transform: translateY(0);
    }

    .fix-btn.copied {
      background: rgba(34,197,94,0.15);
      border-color: rgba(34,197,94,0.4);
      color: #4ade80;
    }

    .fix-btn .fix-btn-icon {
      font-size: 0.9rem;
    }

    /* Toast notification */
    .toast {
      position: fixed;
      bottom: 32px;
      left: 50%;
      transform: translateX(-50%) translateY(100px);
      background: rgba(30, 30, 50, 0.95);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(102,126,234,0.3);
      border-radius: 14px;
      padding: 14px 24px;
      color: #e2e8f0;
      font-size: 0.9rem;
      font-weight: 500;
      z-index: 100;
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .toast.show {
      transform: translateX(-50%) translateY(0);
    }
    
    .toast.error {
      border-color: rgba(239, 68, 68, 0.4);
    }


    .toast .toast-icon {
      font-size: 1.1rem;
    }

    /* No Findings */
    .no-findings {
      text-align: center;
      padding: 80px 20px;
      color: var(--text-secondary);
    }

    .no-findings .check-icon {
      font-size: 4rem;
      margin-bottom: 16px;
    }

    .no-findings h2 {
      color: #22c55e;
      margin-bottom: 8px;
    }

    /* Footer */
    .report-footer {
      text-align: center;
      margin-top: 60px;
      padding-top: 24px;
      border-top: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.78rem;
    }

    /* Responsive */
    @media (max-width: 640px) {
      .container { padding: 24px 16px 60px; }
      .report-header h1 { font-size: 1.8rem; }
      .score-circle-container { padding: 30px 40px; }
      .score-circle { width: 130px; height: 130px; }
      .score-circle svg { width: 130px; height: 130px; }
      .score-value { font-size: 2.4rem; }
      .summary-grid { grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); }
    }

    /* Animation */
    @keyframes fadeInUp {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .animate-in {
      animation: fadeInUp 0.5s ease-out forwards;
      opacity: 0;
    }

    .delay-1 { animation-delay: 0.1s; }
    .delay-2 { animation-delay: 0.2s; }
    .delay-3 { animation-delay: 0.3s; }
    .delay-4 { animation-delay: 0.4s; }
  </style>
</head>
<body>
  <div class="bg-effects">
    <div class="bg-blob one"></div>
    <div class="bg-blob two"></div>
    <div class="bg-blob three"></div>
  </div>

  <div class="container">
    <header class="report-header animate-in">
      <h1>🛡️ Security Report</h1>
      <p class="subtitle">${escapeHtml(targetDir)}</p>
      <div class="meta">
        <span>📅 ${now}</span>
        <span>📁 ${scannedFiles} files scanned</span>
        <span>⏱️ ${scanDuration}ms</span>
        <span>🔍 ${findings.length} total findings</span>
      </div>
    </header>

    <!-- Score -->
    <div class="score-section animate-in delay-1">
      <div class="score-circle-container">
        <div class="score-circle">
          <svg viewBox="0 0 160 160">
            <circle class="bg-ring" cx="80" cy="80" r="70"></circle>
            <circle class="score-ring" cx="80" cy="80" r="70"
              stroke="${gradeInfo.color}"
              stroke-dashoffset="${440 - (440 * score / 100)}"
            ></circle>
          </svg>
          <div class="score-value" style="color: ${gradeInfo.color}">${score}</div>
        </div>
        <div class="score-grade" style="color: ${gradeInfo.color}">${gradeInfo.grade} — ${gradeInfo.label}</div>
        <div class="score-label">Security Score</div>
      </div>
    </div>

    <!-- Summary -->
    <div class="summary-grid animate-in delay-2">
      <div class="summary-card" style="border-bottom: 3px solid ${SEVERITY_CONFIG[SEVERITY.CRITICAL].color}">
        <div class="count" style="color: ${SEVERITY_CONFIG[SEVERITY.CRITICAL].color}">${counts[SEVERITY.CRITICAL]}</div>
        <div class="label" style="color: ${SEVERITY_CONFIG[SEVERITY.CRITICAL].color}">Critical</div>
      </div>
      <div class="summary-card" style="border-bottom: 3px solid ${SEVERITY_CONFIG[SEVERITY.HIGH].color}">
        <div class="count" style="color: ${SEVERITY_CONFIG[SEVERITY.HIGH].color}">${counts[SEVERITY.HIGH]}</div>
        <div class="label" style="color: ${SEVERITY_CONFIG[SEVERITY.HIGH].color}">High</div>
      </div>
      <div class="summary-card" style="border-bottom: 3px solid ${SEVERITY_CONFIG[SEVERITY.MEDIUM].color}">
        <div class="count" style="color: ${SEVERITY_CONFIG[SEVERITY.MEDIUM].color}">${counts[SEVERITY.MEDIUM]}</div>
        <div class="label" style="color: ${SEVERITY_CONFIG[SEVERITY.MEDIUM].color}">Medium</div>
      </div>
      <div class="summary-card" style="border-bottom: 3px solid ${SEVERITY_CONFIG[SEVERITY.LOW].color}">
        <div class="count" style="color: ${SEVERITY_CONFIG[SEVERITY.LOW].color}">${counts[SEVERITY.LOW]}</div>
        <div class="label" style="color: ${SEVERITY_CONFIG[SEVERITY.LOW].color}">Low</div>
      </div>
      <div class="summary-card" style="border-bottom: 3px solid ${SEVERITY_CONFIG[SEVERITY.INFO].color}">
        <div class="count" style="color: ${SEVERITY_CONFIG[SEVERITY.INFO].color}">${counts[SEVERITY.INFO]}</div>
        <div class="label" style="color: ${SEVERITY_CONFIG[SEVERITY.INFO].color}">Info</div>
      </div>
    </div>

    <!-- Action Buttons -->
    <div class="action-buttons-container animate-in delay-2">
      ${fixableFindings.length > 0 ? `
      <button class="action-btn primary" onclick="copyFixAll(this)">
        <span class="icon">⚡</span> Fix All
      </button>
      <button class="action-btn secondary" onclick="exportCSV(this)">
        <span class="icon">📥</span> Export CSV
      </button>
      <button class="action-btn secondary" onclick="copyHowTo100(this)">
        <span class="icon">🚀</span> How to get to 100?
      </button>
      ` : ''}
      <button class="action-btn secondary" onclick="rescanProject(this)">
        <span class="icon">🔄</span> Re-scan Project
      </button>
      <a href="http://localhost:3847" class="action-btn secondary" style="text-decoration: none;">
        <span class="icon">🏠</span> Back to Dashboard
      </a>
    </div>

    <!-- Findings -->
    <div class="findings-section animate-in delay-3">
      ${findings.length > 0 ? findingsHTML : `
        <div class="no-findings">
          <div class="check-icon">✅</div>
          <h2>No Issues Found</h2>
          <p>Your app passed all security checks. Nice work!</p>
        </div>
      `}
    </div>

    <footer class="report-footer animate-in delay-4">
      <p>Generated by <strong>Security Review Agent</strong> v1.0 • Static analysis — not a substitute for penetration testing</p>
    </footer>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast">
    <span class="toast-icon">✅</span>
    <span id="toastMsg">Copied to clipboard!</span>
  </div>

  <script>
    // Fix prompts stored as JSON to avoid escaping issues
    const rawFindings = ${safeJsonForScript(findings)};
    const fixPrompts = ${safeJsonForScript(allPrompts)};
    const fixAllPrompt = ${safeJsonForScript(fixAllPrompt)};
    const howTo100Prompt = ${safeJsonForScript(howTo100Prompt)};
    const targetPath = ${safeJsonForScript(absBasePath || targetDir)};

    function exportCSV(btn) {
      if (!rawFindings || rawFindings.length === 0) return;
      
      const headers = ['Severity', 'Category', 'File', 'Line', 'Issue', 'Fix'];
      const escapeCSV = (str) => {
        if (str == null) return '""';
        const s = String(str).replace(/"/g, '""');
        return '"' + s + '"';
      };

      const rows = rawFindings.map(f => [
        escapeCSV(f.severity.toUpperCase()),
        escapeCSV(f.scanner),
        escapeCSV(f.file),
        escapeCSV(f.line),
        escapeCSV(f.message),
        escapeCSV(f.remediation)
      ].join(','));

      const csvContent = headers.join(',') + '\\n' + rows.join('\\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', 'security-report.csv');
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      showToast('CSV Exported Successfully');
    }

    function showToast(msg, isError = false) {
      const toast = document.getElementById('toast');
      const toastMsg = document.getElementById('toastMsg');
      toastMsg.textContent = msg;
      toast.className = isError ? 'toast error show' : 'toast show';
      setTimeout(() => toast.classList.remove('show'), 2500);
    }

    function copyFix(btn, idx) {
      navigator.clipboard.writeText(fixPrompts[idx]).then(() => {
        btn.classList.add('copied');
        btn.replaceChildren();
        btn['insertAdjacent' + 'HTML']('beforeend', '<span class="fix-btn-icon">✅</span> Copied! Paste in Antigravity');
        showToast('Fix prompt copied — paste it in Antigravity to apply');
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.replaceChildren();
          btn['insertAdjacent' + 'HTML']('beforeend', '<span class="fix-btn-icon">⚡</span> Fix with Antigravity');
        }, 3000);
      });
    }
    function copyFixAll(btn) {
      if (!fixAllPrompt) return;
      navigator.clipboard.writeText(fixAllPrompt).then(() => {
        btn.classList.add('copied');
        btn.replaceChildren();
        btn['insertAdjacent' + 'HTML']('beforeend', '<span class="icon">✅</span> Copied! Paste in Antigravity');
        showToast('All fixes copied — paste in Antigravity to apply all');
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.replaceChildren();
          btn['insertAdjacent' + 'HTML']('beforeend', '<span class="icon">⚡</span> Fix All');
        }, 3000);
      }).catch(err => {
        showToast('Failed to copy to clipboard', true);
      });
    }

    function copyHowTo100(btn) {
      if (!howTo100Prompt) return;
      navigator.clipboard.writeText(howTo100Prompt).then(() => {
        btn.classList.add('copied');
        btn.replaceChildren();
        btn['insertAdjacent' + 'HTML']('beforeend', '<span class="icon">✅</span> Copied! Paste in Antigravity');
        showToast('Prompt copied — paste in Antigravity for a plan');
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.replaceChildren();
          btn['insertAdjacent' + 'HTML']('beforeend', '<span class="icon">🚀</span> How to get to 100?');
        }, 3000);
      }).catch(err => {
        showToast('Failed to copy to clipboard', true);
      });
    }

    async function rescanProject(btn) {
      if (window.location.protocol !== 'http:') {
        showToast('Re-scan is only available when viewed through the Dashboard', true);
        return;
      }

      btn.replaceChildren();
      btn['insertAdjacent' + 'HTML']('beforeend', '<span class="icon">⏳</span> Scanning...');
      try {
        const res = await fetch(window.location.origin + '/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: targetPath }),
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        
        btn.classList.add('success');
        btn.replaceChildren();
        btn['insertAdjacent' + 'HTML']('beforeend', '<span class="icon">✅</span> Scan Complete! Reloading...');
        showToast('Scan complete! Reloading report...');
        setTimeout(() => window.location.reload(), 1500);
      } catch (e) {
        showToast('Scan failed: ' + e.message, true);
        btn.replaceChildren();
        btn['insertAdjacent' + 'HTML']('beforeend', '<span class="icon">🔄</span> Re-scan Project');
      }
    }
    // Animate score ring on load
    document.addEventListener('DOMContentLoaded', () => {
      const ring = document.querySelector('.score-ring');
      if (ring) {
        const offset = ring.getAttribute('stroke-dashoffset');
        ring.style.strokeDashoffset = '440';
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            ring.style.strokeDashoffset = offset;
          });
        });
      }
    });
  </script>
</body>
</html>`;
}

module.exports = { generateReport };
