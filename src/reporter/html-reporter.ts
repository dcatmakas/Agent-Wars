import fs from 'fs/promises';
import path from 'path';
import type { SecurityReport, Vulnerability, Fix, Severity } from '../types.js';

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function severityClass(s: Severity): string {
  return `severity-${s}`;
}

function renderVulnCard(v: Vulnerability, fix?: Fix): string {
  const fixBadge = fix?.verified
    ? '<span class="badge badge-fixed">FIXED</span>'
    : fix
      ? '<span class="badge badge-partial">PARTIAL FIX</span>'
      : '<span class="badge badge-open">OPEN</span>';

  return `
    <div class="vuln-card ${severityClass(v.severity)}">
      <div class="vuln-header">
        <span class="severity-badge ${severityClass(v.severity)}">${v.severity.toUpperCase()}</span>
        <span class="vuln-title">${escapeHtml(v.title)}</span>
        ${fixBadge}
      </div>
      <div class="vuln-meta">
        <span>${escapeHtml(v.file)}${v.line ? ':' + v.line : ''}</span>
        <span>${escapeHtml(v.category)}</span>
        ${v.cwe ? `<span>${escapeHtml(v.cwe)}</span>` : ''}
      </div>
      <div class="vuln-body">
        <p><strong>Description:</strong> ${escapeHtml(v.description)}</p>
        <p><strong>Impact:</strong> ${escapeHtml(v.impact)}</p>
        <details>
          <summary>Evidence</summary>
          <pre><code>${escapeHtml(v.evidence)}</code></pre>
        </details>
        ${
          fix
            ? `
        <details>
          <summary>Fix Applied</summary>
          <p>${escapeHtml(fix.description)}</p>
          <pre><code>${escapeHtml(fix.diff)}</code></pre>
        </details>`
            : ''
        }
      </div>
    </div>`;
}

function renderTimeline(report: SecurityReport): string {
  return report.iterations
    .map(
      (it) => `
    <div class="timeline-item timeline-${it.phase}">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <strong>Round ${it.round} - ${it.phase === 'red' ? 'Red Agent Attack' : it.phase === 'blue' ? 'Blue Agent Defense' : 'Verification'}</strong>
        <p>${it.phase === 'red' ? `Found ${it.vulnerabilitiesFound} vulnerabilities` : `Applied ${it.fixesApplied} fixes`} | ${it.remainingIssues} remaining</p>
      </div>
    </div>`
    )
    .join('');
}

function renderScoreGauge(score: number): string {
  const color =
    score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
  const rotation = (score / 100) * 180;
  return `
    <div class="score-gauge">
      <svg viewBox="0 0 200 120" width="200" height="120">
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#333" stroke-width="12" stroke-linecap="round"/>
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"
          stroke-dasharray="${(rotation / 180) * 251.2} 251.2"/>
        <text x="100" y="95" text-anchor="middle" font-size="32" font-weight="bold" fill="${color}">${score}</text>
        <text x="100" y="115" text-anchor="middle" font-size="12" fill="#888">/100</text>
      </svg>
    </div>`;
}

export async function generateHtmlReport(
  report: SecurityReport,
  outputDir: string
): Promise<string> {
  await fs.mkdir(outputDir, { recursive: true });

  const vulnCards = report.vulnerabilities
    .map((v) => {
      const fix = report.fixes.find((f) => f.vulnerabilityId === v.id);
      return renderVulnCard(v, fix);
    })
    .join('');

  const html = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agent Wars - Security Report: ${escapeHtml(report.projectName)}</title>
  <style>
    :root {
      --bg: #0a0a0f;
      --bg-card: #12121a;
      --bg-card-hover: #1a1a25;
      --text: #e4e4e7;
      --text-muted: #71717a;
      --border: #27272a;
      --red: #ef4444;
      --red-dim: #7f1d1d;
      --orange: #f97316;
      --orange-dim: #7c2d12;
      --yellow: #eab308;
      --yellow-dim: #713f12;
      --cyan: #06b6d4;
      --cyan-dim: #164e63;
      --green: #22c55e;
      --green-dim: #14532d;
      --gray: #71717a;
      --gray-dim: #27272a;
      --blue: #3b82f6;
      --purple: #a855f7;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }

    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

    header {
      text-align: center;
      padding: 3rem 0;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }

    header h1 {
      font-size: 2rem;
      background: linear-gradient(135deg, var(--red), var(--blue), var(--green));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 0.5rem;
    }

    header .subtitle { color: var(--text-muted); font-size: 0.9rem; }

    .dashboard {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      text-align: center;
    }

    .stat-card .stat-value { font-size: 2rem; font-weight: bold; }
    .stat-card .stat-label { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }

    .severity-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 0.5rem;
      margin-bottom: 2rem;
    }

    .severity-count {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }

    .severity-count.severity-critical { border-color: var(--red); }
    .severity-count.severity-high { border-color: var(--orange); }
    .severity-count.severity-medium { border-color: var(--yellow); }
    .severity-count.severity-low { border-color: var(--cyan); }
    .severity-count.severity-info { border-color: var(--gray); }

    .severity-count .count { font-size: 1.5rem; font-weight: bold; }
    .severity-count.severity-critical .count { color: var(--red); }
    .severity-count.severity-high .count { color: var(--orange); }
    .severity-count.severity-medium .count { color: var(--yellow); }
    .severity-count.severity-low .count { color: var(--cyan); }
    .severity-count.severity-info .count { color: var(--gray); }

    .section-title {
      font-size: 1.2rem;
      margin: 2rem 0 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }

    .score-section {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 2rem;
      margin: 2rem 0;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2rem;
    }

    .score-gauge { text-align: center; }

    .vuln-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1rem;
      overflow: hidden;
      transition: background 0.2s;
    }

    .vuln-card:hover { background: var(--bg-card-hover); }

    .vuln-card.severity-critical { border-left: 3px solid var(--red); }
    .vuln-card.severity-high { border-left: 3px solid var(--orange); }
    .vuln-card.severity-medium { border-left: 3px solid var(--yellow); }
    .vuln-card.severity-low { border-left: 3px solid var(--cyan); }
    .vuln-card.severity-info { border-left: 3px solid var(--gray); }

    .vuln-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 1rem 1.5rem;
      border-bottom: 1px solid var(--border);
    }

    .severity-badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: bold;
      text-transform: uppercase;
    }

    .severity-badge.severity-critical { background: var(--red-dim); color: var(--red); }
    .severity-badge.severity-high { background: var(--orange-dim); color: var(--orange); }
    .severity-badge.severity-medium { background: var(--yellow-dim); color: var(--yellow); }
    .severity-badge.severity-low { background: var(--cyan-dim); color: var(--cyan); }
    .severity-badge.severity-info { background: var(--gray-dim); color: var(--gray); }

    .vuln-title { font-weight: bold; flex: 1; }

    .badge {
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: bold;
    }

    .badge-fixed { background: var(--green-dim); color: var(--green); }
    .badge-partial { background: var(--yellow-dim); color: var(--yellow); }
    .badge-open { background: var(--red-dim); color: var(--red); }

    .vuln-meta {
      display: flex;
      gap: 1rem;
      padding: 0.5rem 1.5rem;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .vuln-body { padding: 1rem 1.5rem; font-size: 0.85rem; }
    .vuln-body p { margin-bottom: 0.5rem; }

    details { margin-top: 0.5rem; }
    summary { cursor: pointer; color: var(--blue); font-size: 0.85rem; }
    summary:hover { text-decoration: underline; }

    pre {
      background: #0d0d14;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 1rem;
      overflow-x: auto;
      margin-top: 0.5rem;
      font-size: 0.8rem;
    }

    code { font-family: inherit; }

    .timeline {
      position: relative;
      padding-left: 2rem;
      margin: 1rem 0 2rem;
    }

    .timeline::before {
      content: '';
      position: absolute;
      left: 8px;
      top: 0;
      bottom: 0;
      width: 2px;
      background: var(--border);
    }

    .timeline-item {
      position: relative;
      margin-bottom: 1rem;
      padding-left: 1rem;
    }

    .timeline-dot {
      position: absolute;
      left: -1.65rem;
      top: 0.35rem;
      width: 12px;
      height: 12px;
      border-radius: 50%;
      border: 2px solid var(--border);
    }

    .timeline-red .timeline-dot { background: var(--red); border-color: var(--red); }
    .timeline-blue .timeline-dot { background: var(--blue); border-color: var(--blue); }
    .timeline-verify .timeline-dot { background: var(--green); border-color: var(--green); }

    .timeline-content {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
    }

    .timeline-content p { color: var(--text-muted); margin-top: 0.25rem; }

    .recommendations {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
    }

    .recommendations ul { list-style: none; }
    .recommendations li {
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--border);
      font-size: 0.85rem;
    }
    .recommendations li:last-child { border-bottom: none; }
    .recommendations li::before { content: '> '; color: var(--green); font-weight: bold; }

    footer {
      text-align: center;
      padding: 2rem 0;
      color: var(--text-muted);
      font-size: 0.75rem;
      border-top: 1px solid var(--border);
      margin-top: 2rem;
    }

    .filter-bar {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }

    .filter-btn {
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.4rem 0.8rem;
      border-radius: 4px;
      cursor: pointer;
      font-family: inherit;
      font-size: 0.8rem;
    }

    .filter-btn:hover { background: var(--bg-card-hover); }
    .filter-btn.active { border-color: var(--blue); color: var(--blue); }

    @media (max-width: 768px) {
      .severity-grid { grid-template-columns: repeat(3, 1fr); }
      .dashboard { grid-template-columns: 1fr 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Agent Wars Security Report</h1>
      <div class="subtitle">
        ${escapeHtml(report.projectName)} | ${new Date(report.scanDate).toLocaleString()} | ${(report.duration / 1000).toFixed(1)}s | $${report.costUsd.toFixed(4)}
      </div>
    </header>

    <div class="score-section">
      ${renderScoreGauge(report.score)}
      <div>
        <div style="font-size:1.5rem;font-weight:bold;">Security Score</div>
        <div style="color:var(--text-muted)">
          ${report.vulnerabilities.length} found | ${report.fixes.filter((f) => f.verified).length} fixed | ${report.unfixed.length} remaining
        </div>
      </div>
    </div>

    <div class="severity-grid">
      <div class="severity-count severity-critical">
        <div class="count">${report.summary.critical}</div>
        <div style="color:var(--text-muted);font-size:0.75rem">Critical</div>
      </div>
      <div class="severity-count severity-high">
        <div class="count">${report.summary.high}</div>
        <div style="color:var(--text-muted);font-size:0.75rem">High</div>
      </div>
      <div class="severity-count severity-medium">
        <div class="count">${report.summary.medium}</div>
        <div style="color:var(--text-muted);font-size:0.75rem">Medium</div>
      </div>
      <div class="severity-count severity-low">
        <div class="count">${report.summary.low}</div>
        <div style="color:var(--text-muted);font-size:0.75rem">Low</div>
      </div>
      <div class="severity-count severity-info">
        <div class="count">${report.summary.info}</div>
        <div style="color:var(--text-muted);font-size:0.75rem">Info</div>
      </div>
    </div>

    <div class="dashboard">
      <div class="stat-card">
        <div class="stat-value">${report.totalIterations}</div>
        <div class="stat-label">Scan Rounds</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${report.vulnerabilities.length}</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${report.fixes.filter((f) => f.verified).length}</div>
        <div class="stat-label">Auto-Fixed</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">$${report.costUsd.toFixed(2)}</div>
        <div class="stat-label">API Cost</div>
      </div>
    </div>

    <h2 class="section-title">Attack/Defense Timeline</h2>
    <div class="timeline">
      ${renderTimeline(report)}
    </div>

    <h2 class="section-title">Vulnerabilities</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterVulns('all')">All</button>
      <button class="filter-btn" onclick="filterVulns('critical')">Critical</button>
      <button class="filter-btn" onclick="filterVulns('high')">High</button>
      <button class="filter-btn" onclick="filterVulns('medium')">Medium</button>
      <button class="filter-btn" onclick="filterVulns('low')">Low</button>
      <button class="filter-btn" onclick="filterVulns('open')">Open</button>
      <button class="filter-btn" onclick="filterVulns('fixed')">Fixed</button>
    </div>
    <div id="vuln-list">
      ${vulnCards}
    </div>

    <h2 class="section-title">Recommendations</h2>
    <div class="recommendations">
      <ul>
        ${report.recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}
      </ul>
    </div>

    <footer>
      Generated by Agent Wars - Multi-Agent Security Testing Tool<br>
      Powered by Claude Agent SDK | Red Team vs Blue Team vs Green Team
    </footer>
  </div>

  <script>
    function filterVulns(type) {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.querySelectorAll('.vuln-card').forEach(card => {
        if (type === 'all') { card.style.display = ''; return; }
        if (type === 'open') {
          card.style.display = card.querySelector('.badge-open') ? '' : 'none';
          return;
        }
        if (type === 'fixed') {
          card.style.display = card.querySelector('.badge-fixed') ? '' : 'none';
          return;
        }
        card.style.display = card.classList.contains('severity-' + type) ? '' : 'none';
      });
    }
  </script>
</body>
</html>`;

  const filePath = path.join(outputDir, 'report.html');
  await fs.writeFile(filePath, html, 'utf-8');
  return filePath;
}
