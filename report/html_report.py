import json
import html
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List
from core.issue import Issue, Severity, Category, compute_score


SEV_COLOR = {
    "critical": "#ff4d6d",
    "warning":  "#ffc107",
    "info":     "#4dabf7",
}

SEV_ICON = {
    "critical": "🔴",
    "warning":  "🟡",
    "info":     "🔵",
}

CAT_ICON = {
    "Sécurité":       "🔐",
    "Nommage":        "🏷️",
    "Style":          "🎨",
    "Architecture":   "🏗️",
    "Documentation":  "📖",
    "Performance":    "⚡",
    "Fiabilité":      "🛡️",
    "Convention":     "📏",
    "Complexité":     "🔀",
    "Syntaxe":        "⚠️",
    "Configuration":  "⚙️",
    "Maintenabilité": "🔧",
}


class HTMLReport:
    def __init__(self, root: Path, files: Dict[str, str], issues: List[Issue]):
        self.root = root
        self.files = files
        self.issues = issues
        self.score, self.grade = compute_score(issues)

    def generate(self, output_path: Path):
        html_content = self._build_html()
        output_path.write_text(html_content, encoding="utf-8")

    # ─────────────────────────────── HTML builder ─────────────────────────

    def _build_html(self) -> str:
        now = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
        n_files = len(self.files)
        n_issues = len(self.issues)
        n_critical = sum(1 for i in self.issues if i.severity == Severity.CRITICAL)
        n_warning  = sum(1 for i in self.issues if i.severity == Severity.WARNING)
        n_info     = sum(1 for i in self.issues if i.severity == Severity.INFO)

        # Category breakdown
        cat_counts = Counter(i.category.value for i in self.issues)
        cat_sev = defaultdict(lambda: {"critical": 0, "warning": 0, "info": 0})
        for i in self.issues:
            cat_sev[i.category.value][i.severity.value] += 1

        # Per-file breakdown
        file_issues = defaultdict(list)
        for issue in self.issues:
            file_issues[issue.file].append(issue)

        # Sort files by number of issues desc
        sorted_files = sorted(file_issues.items(), key=lambda x: len(x[1]), reverse=True)

        grade_color = self._grade_color(self.grade)

        # Build issues JSON for JS filtering
        issues_json = json.dumps([i.to_dict() for i in self.issues], ensure_ascii=False)

        # Chart data
        cat_labels = list(cat_counts.keys())
        cat_values = [cat_counts[k] for k in cat_labels]

        sev_labels = ["Critique", "Avertissement", "Info"]
        sev_values = [n_critical, n_warning, n_info]

        # File extension breakdown
        ext_counter = Counter(Path(f).suffix.lower() or "no-ext" for f in self.files)
        ext_labels = [k for k, _ in ext_counter.most_common(10)]
        ext_values = [ext_counter[k] for k in ext_labels]

        # Issues per file (top 10)
        top_files_data = sorted_files[:10]
        top_files_labels = [Path(f).name for f, _ in top_files_data]
        top_files_values = [len(issues) for _, issues in top_files_data]

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Codalyse — {html.escape(str(self.root.name))}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Outfit:wght@400;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {{
  --bg:       #0a0e1a;
  --bg2:      #0f1524;
  --bg3:      #151c30;
  --bg4:      #1c2438;
  --border:   #232d45;
  --border2:  #2d3a58;
  --text:     #c8d6f0;
  --text2:    #8899bb;
  --text3:    #5566880;
  --accent:   #00c896;
  --accent2:  #00a37a;
  --crit:     #ff4d6d;
  --warn:     #ffc107;
  --info:     #4dabf7;
  --green:    #40c983;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  --font-ui:   'Outfit', sans-serif;
  --radius:   8px;
  --radius-lg: 14px;
  --shadow:   0 4px 24px rgba(0,0,0,0.4);
}}

*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; }}

body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-ui);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}}

/* ── Layout ── */
.layout {{ display: grid; grid-template-columns: 260px 1fr; min-height: 100vh; }}

/* ── Sidebar ── */
.sidebar {{
  background: var(--bg2);
  border-right: 1px solid var(--border);
  padding: 24px 0;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  z-index: 10;
}}

.sidebar-logo {{
  padding: 0 20px 20px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 16px;
}}

.sidebar-logo h1 {{
  font-size: 15px;
  font-weight: 800;
  letter-spacing: 0.05em;
  color: var(--accent);
  text-transform: uppercase;
}}

.sidebar-logo .project-name {{
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text2);
  margin-top: 4px;
  word-break: break-all;
}}

.nav-section {{
  padding: 0 12px;
  margin-bottom: 8px;
}}

.nav-label {{
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text2);
  padding: 8px 8px 4px;
}}

.nav-item {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: var(--radius);
  font-size: 13px;
  font-weight: 500;
  color: var(--text2);
  text-decoration: none;
  cursor: pointer;
  transition: all 0.15s ease;
  border: 1px solid transparent;
}}

.nav-item:hover {{
  background: var(--bg3);
  color: var(--text);
  border-color: var(--border);
}}

.nav-item.active {{
  background: rgba(76, 159, 254, 0.12);
  color: var(--accent);
  border-color: rgba(76, 159, 254, 0.25);
}}

.nav-badge {{
  margin-left: auto;
  background: var(--bg4);
  border: 1px solid var(--border2);
  border-radius: 20px;
  padding: 1px 7px;
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text2);
}}

.nav-badge.crit {{ background: rgba(255,77,109,0.15); border-color: rgba(255,77,109,0.3); color: var(--crit); }}
.nav-badge.warn {{ background: rgba(255,193,7,0.12); border-color: rgba(255,193,7,0.3); color: var(--warn); }}

/* ── Main ── */
.main {{
  padding: 32px 36px;
  overflow: hidden;
}}

/* ── Sections ── */
.section {{ display: none; }}
.section.active {{ display: block; animation: fadeIn 0.25s ease; }}

@keyframes fadeIn {{
  from {{ opacity: 0; transform: translateY(6px); }}
  to   {{ opacity: 1; transform: translateY(0); }}
}}

.section-title {{
  font-size: 22px;
  font-weight: 800;
  color: var(--text);
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 10px;
}}

.section-title::after {{
  content: '';
  flex: 1;
  height: 1px;
  background: var(--border);
  margin-left: 12px;
}}

/* ── Cards ── */
.card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 20px 24px;
  box-shadow: var(--shadow);
}}

.grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
.grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }}
.grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }}

/* ── Stat cards ── */
.stat-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px 20px;
  position: relative;
  overflow: hidden;
}}

.stat-card::before {{
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
}}

.stat-card.blue::before  {{ background: var(--accent); }}
.stat-card.red::before   {{ background: var(--crit); }}
.stat-card.yellow::before {{ background: var(--warn); }}
.stat-card.green::before {{ background: var(--green); }}

.stat-label {{
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text2);
  margin-bottom: 8px;
}}

.stat-value {{
  font-family: var(--font-mono);
  font-size: 32px;
  font-weight: 700;
  line-height: 1;
}}

.stat-card.blue  .stat-value {{ color: var(--accent); }}
.stat-card.red   .stat-value {{ color: var(--crit); }}
.stat-card.yellow .stat-value {{ color: var(--warn); }}
.stat-card.green .stat-value {{ color: var(--green); }}

.stat-sub {{ font-size: 12px; color: var(--text2); margin-top: 4px; }}

/* ── Score gauge ── */
.score-section {{
  display: flex;
  align-items: center;
  gap: 32px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 28px 32px;
  margin-bottom: 24px;
}}

.score-gauge {{
  position: relative;
  width: 160px;
  height: 160px;
  flex-shrink: 0;
}}

.score-gauge canvas {{ width: 160px !important; height: 160px !important; }}

.score-center {{
  position: absolute;
  top: 70%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
  pointer-events: none;
}}

.score-number {{
  font-family: var(--font-mono);
  font-size: 38px;
  font-weight: 700;
  line-height: 1;
  color: {grade_color};
}}

.score-grade {{
  font-size: 14px;
  font-weight: 700;
  color: var(--text2);
  margin-top: 2px;
}}

.score-meta {{ flex: 1; }}
.score-meta h2 {{ font-size: 20px; font-weight: 800; margin-bottom: 12px; }}
.score-meta p  {{ font-size: 13px; color: var(--text2); line-height: 1.7; }}

/* ── Issues list ── */
.filters {{
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 16px;
  align-items: center;
}}

.filter-search {{
  flex: 1;
  min-width: 200px;
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: var(--radius);
  padding: 8px 12px;
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 13px;
  outline: none;
  transition: border-color 0.15s;
}}

.filter-search:focus {{ border-color: var(--accent); }}
.filter-search::placeholder {{ color: var(--text2); }}

.filter-btn {{
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: var(--radius);
  padding: 7px 14px;
  color: var(--text2);
  font-family: var(--font-ui);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
}}

.filter-btn:hover {{ border-color: var(--accent); color: var(--text); }}
.filter-btn.active {{ background: rgba(76,159,254,0.12); border-color: var(--accent); color: var(--accent); }}
.filter-btn.crit.active  {{ background: rgba(255,77,109,0.12); border-color: var(--crit); color: var(--crit); }}
.filter-btn.warn.active  {{ background: rgba(255,193,7,0.12); border-color: var(--warn); color: var(--warn); }}
.filter-btn.info.active  {{ background: rgba(77,171,247,0.12); border-color: var(--info); color: var(--info); }}

.issue-count {{
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text2);
  margin-left: auto;
}}

.issues-table-wrap {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}}

.issues-table {{ width: 100%; border-collapse: collapse; }}

.issues-table th {{
  background: var(--bg3);
  padding: 10px 14px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text2);
  text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}}

.issues-table td {{
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  font-size: 13px;
}}

.issues-table tr:last-child td {{ border-bottom: none; }}

.issues-table tr:hover td {{ background: rgba(255,255,255,0.02); }}

.badge {{
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}}

.badge-critical {{ background: rgba(255,77,109,0.15); border: 1px solid rgba(255,77,109,0.35); color: var(--crit); }}
.badge-warning  {{ background: rgba(255,193,7,0.12); border: 1px solid rgba(255,193,7,0.35); color: var(--warn); }}
.badge-info     {{ background: rgba(77,171,247,0.12); border: 1px solid rgba(77,171,247,0.3); color: var(--info); }}

.badge-cat {{
  background: var(--bg4);
  border: 1px solid var(--border2);
  color: var(--text2);
  font-size: 10px;
}}

.filepath {{
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--accent);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 250px;
  display: block;
}}

.line-badge {{
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text2);
  background: var(--bg4);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
}}

.issue-msg {{ font-weight: 500; color: var(--text); }}
.issue-sug {{ font-size: 12px; color: var(--text2); margin-top: 3px; }}
.rule-code  {{ font-family: var(--font-mono); font-size: 10px; color: var(--text2); }}

/* ── File tree ── */
.file-tree {{
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.8;
}}

.tree-folder {{
  color: var(--warn);
  font-weight: 600;
  cursor: pointer;
  user-select: none;
}}

.tree-file {{ color: var(--text2); padding-left: 16px; }}
.tree-file.has-issues {{ color: var(--crit); }}
.tree-file.has-warnings {{ color: var(--warn); }}
.tree-file a {{ color: inherit; text-decoration: none; }}
.tree-children {{ padding-left: 16px; border-left: 1px solid var(--border); margin-left: 8px; }}
.tree-count {{ font-size: 10px; padding: 1px 5px; border-radius: 4px; margin-left: 6px; }}

/* ── Category bars ── */
.cat-bar-row {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
}}

.cat-bar-row:last-child {{ border-bottom: none; }}
.cat-icon  {{ width: 24px; text-align: center; font-size: 16px; }}
.cat-name  {{ width: 150px; font-size: 13px; font-weight: 600; }}
.cat-bar-wrap {{ flex: 1; background: var(--bg4); border-radius: 4px; height: 6px; overflow: hidden; }}
.cat-bar {{ height: 100%; border-radius: 4px; background: var(--accent2); transition: width 0.6s ease; }}
.cat-num {{ font-family: var(--font-mono); font-size: 12px; color: var(--text2); width: 30px; text-align: right; }}

/* ── Charts grid ── */
.chart-wrap {{ position: relative; height: 240px; }}
.card-title {{ font-size: 13px; font-weight: 700; color: var(--text2); text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 16px; }}

/* ── Pagination ── */
.pagination {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-top: 1px solid var(--border);
  background: var(--bg3);
  font-size: 12px;
  color: var(--text2);
}}

.page-btns {{ display: flex; gap: 6px; }}
.page-btn {{
  background: var(--bg4);
  border: 1px solid var(--border2);
  border-radius: 6px;
  padding: 4px 10px;
  color: var(--text2);
  cursor: pointer;
  font-size: 12px;
  font-family: var(--font-ui);
  transition: all 0.15s;
}}
.page-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
.page-btn:disabled {{ opacity: 0.3; cursor: not-allowed; }}
.page-btn.active {{ background: rgba(76,159,254,0.15); border-color: var(--accent); color: var(--accent); }}

/* ── Summary table (per-file) ── */
.file-summary-table {{ width: 100%; border-collapse: collapse; }}
.file-summary-table th {{
  background: var(--bg3);
  padding: 9px 14px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text2);
  text-align: left;
  border-bottom: 1px solid var(--border);
}}
.file-summary-table td {{
  padding: 8px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}}
.file-summary-table tr:last-child td {{ border-bottom: none; }}
.file-summary-table tr:hover td {{ background: rgba(255,255,255,0.02); }}

/* ── Top bar ── */
.topbar {{
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 14px 36px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 12px;
  color: var(--text2);
  font-family: var(--font-mono);
  position: sticky;
  top: 0;
  z-index: 5;
  margin: -32px -36px 28px;
}}

.topbar-project {{ color: var(--accent); font-weight: 600; }}
.topbar-meta {{ display: flex; gap: 20px; }}
.topbar-meta span {{ display: flex; align-items: center; gap: 6px; }}

/* ── Scrollbar ── */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--accent); }}

/* ── No issues ── */
.empty-state {{
  text-align: center;
  padding: 48px 24px;
  color: var(--text2);
}}
.empty-state .big {{ font-size: 48px; margin-bottom: 12px; }}
.empty-state p {{ font-size: 14px; }}

@media (max-width: 900px) {{
  .layout {{ grid-template-columns: 1fr; }}
  .sidebar {{ position: relative; height: auto; }}
  .grid-4 {{ grid-template-columns: repeat(2, 1fr); }}
}}
</style>
</head>
<body>
<div class="layout">

<!-- ──────────────── SIDEBAR ──────────────── -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
      <div style="width:28px;height:28px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#0a0e1a;letter-spacing:-.02em;flex-shrink:0">C</div>
      <h1>Codalyse</h1>
    </div>
    <div class="project-name">📁 {html.escape(str(self.root.name))}</div>
    <div class="project-name" style="margin-top:4px;color:var(--text2);">{now}</div>
  </div>

  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <a class="nav-item active" onclick="showSection('dashboard')">
      <span>📊</span> Tableau de bord
    </a>
    <a class="nav-item" onclick="showSection('issues')">
      <span>⚠️</span> Observations
      <span class="nav-badge{' crit' if n_critical > 0 else ''}">{n_issues}</span>
    </a>
    <a class="nav-item" onclick="showSection('files')">
      <span>📁</span> Fichiers
      <span class="nav-badge">{n_files}</span>
    </a>
    <a class="nav-item" onclick="showSection('categories')">
      <span>🏷️</span> Catégories
    </a>
    <a class="nav-item" onclick="showSection('charts')">
      <span>📈</span> Graphiques
    </a>
  </div>

  <div class="nav-section" style="margin-top:16px;">
    <div class="nav-label">Sévérité</div>
    <a class="nav-item" onclick="showSection('issues'); filterBySeverity('critical')">
      <span>🔴</span> Critiques
      <span class="nav-badge crit">{n_critical}</span>
    </a>
    <a class="nav-item" onclick="showSection('issues'); filterBySeverity('warning')">
      <span>🟡</span> Avertissements
      <span class="nav-badge warn">{n_warning}</span>
    </a>
    <a class="nav-item" onclick="showSection('issues'); filterBySeverity('info')">
      <span>🔵</span> Infos
      <span class="nav-badge">{n_info}</span>
    </a>
  </div>
</aside>

<!-- ──────────────── MAIN ──────────────── -->
<main class="main">
  <div class="topbar">
    <span class="topbar-project"><span style="color:var(--accent);font-weight:800;margin-right:6px">Codalyse</span>{html.escape(str(self.root))}</span>
    <div class="topbar-meta">
      <span>🗂️ {n_files} fichiers</span>
      <span>⚠️ {n_issues} observations</span>
      <span>🕒 {now}</span>
    </div>
  </div>

  <!-- ═══════════════ DASHBOARD ═══════════════ -->
  <section id="sec-dashboard" class="section active">
    <div class="section-title">📊 Tableau de bord</div>

    <!-- Score -->
    <div class="score-section">
      <div class="score-gauge">
        <canvas id="gaugeChart"></canvas>
        <div class="score-center">
          <div class="score-number">{self.score}</div>
        </div>
      </div>
      <div class="score-meta">
        <h2>Score de qualité : <span style="color:{grade_color}">{self.score}/100 — {self.grade}</span></h2>
        <p>Analysé sur <strong>{n_files} fichiers</strong> — <strong>{n_issues} observations</strong> détectés.<br>
        {self._score_comment(self.score)}</p>
      </div>
    </div>

    <!-- Stats -->
    <div class="grid-4">
      <div class="stat-card blue">
        <div class="stat-label">Fichiers analysés</div>
        <div class="stat-value">{n_files}</div>
        <div class="stat-sub">{len(set(Path(f).suffix for f in self.files))} types différents</div>
      </div>
      <div class="stat-card red">
        <div class="stat-label">🔴 Critiques</div>
        <div class="stat-value">{n_critical}</div>
        <div class="stat-sub">Correction immédiate requise</div>
      </div>
      <div class="stat-card yellow">
        <div class="stat-label">🟡 Avertissements</div>
        <div class="stat-value">{n_warning}</div>
        <div class="stat-sub">À traiter en priorité</div>
      </div>
      <div class="stat-card green">
        <div class="stat-label">🔵 Infos</div>
        <div class="stat-value">{n_info}</div>
        <div class="stat-sub">Améliorations suggérées</div>
      </div>
    </div>

    <!-- Top issues files -->
    {self._top_files_card(sorted_files[:8])}
  </section>

  <!-- ═══════════════ ISSUES ═══════════════ -->
  <section id="sec-issues" class="section">
    <div class="section-title">⚠️ Tous les problèmes</div>
    <div class="filters">
      <input class="filter-search" id="issueSearch" type="text" placeholder="Rechercher… (fichier, message, règle)" oninput="filterIssues()">
      <button class="filter-btn active" id="btn-all"      onclick="setSevFilter('all')">Tous ({n_issues})</button>
      <button class="filter-btn crit"  id="btn-critical"  onclick="setSevFilter('critical')">🔴 Critiques ({n_critical})</button>
      <button class="filter-btn warn"  id="btn-warning"   onclick="setSevFilter('warning')">🟡 Warnings ({n_warning})</button>
      <button class="filter-btn"      id="btn-info"       onclick="setSevFilter('info')">🔵 Infos ({n_info})</button>
      <span class="issue-count" id="visibleCount">{n_issues} affichés</span>
    </div>
    <div class="issues-table-wrap">
      <table class="issues-table" id="issuesTable">
        <thead>
          <tr>
            <th style="width:90px">Sévérité</th>
            <th style="width:110px">Catégorie</th>
            <th style="width:220px">Fichier</th>
            <th>Problème</th>
            <th style="width:80px">Règle</th>
          </tr>
        </thead>
        <tbody id="issuesTbody">
          {self._issues_rows()}
        </tbody>
      </table>
      <div class="pagination" id="pagination"></div>
    </div>
  </section>

  <!-- ═══════════════ FILES ═══════════════ -->
  <section id="sec-files" class="section">
    <div class="section-title">📁 Fichiers du projet</div>
    <div class="grid-2">
      <div class="card">
        <div class="card-title">Arborescence</div>
        <div class="file-tree" id="fileTree">{self._build_file_tree_html(file_issues)}</div>
      </div>
      <div class="card">
        <div class="card-title">Par fichier — problèmes</div>
        <div style="overflow:auto;max-height:520px;">
          <table class="file-summary-table">
            <thead><tr><th>Fichier</th><th>🔴</th><th>🟡</th><th>🔵</th><th>Total</th></tr></thead>
            <tbody>
              {self._file_summary_rows(sorted_files)}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </section>

  <!-- ═══════════════ CATEGORIES ═══════════════ -->
  <section id="sec-categories" class="section">
    <div class="section-title">🏷️ Catégories</div>
    <div class="card">
      {self._category_bars(cat_counts, cat_sev)}
    </div>
  </section>

  <!-- ═══════════════ CHARTS ═══════════════ -->
  <section id="sec-charts" class="section">
    <div class="section-title">📈 Graphiques</div>
    <div class="grid-2">
      <div class="card">
        <div class="card-title">Répartition par sévérité</div>
        <div class="chart-wrap"><canvas id="severityChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">Problèmes par catégorie</div>
        <div class="chart-wrap"><canvas id="categoryChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">Types de fichiers analysés</div>
        <div class="chart-wrap"><canvas id="extChart"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title">Top 10 fichiers — problèmes</div>
        <div class="chart-wrap"><canvas id="topFilesChart"></canvas></div>
      </div>
    </div>
  </section>

</main>
</div>

<!-- ──────────────── SCRIPTS ──────────────── -->
<script>
const ALL_ISSUES = {issues_json};
const PAGE_SIZE  = 50;
let currentPage  = 1;
let filtered     = [...ALL_ISSUES];
let sevFilter    = 'all';

// ─── Navigation ───
function showSection(id) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.getElementById('sec-' + id).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => {{
    if (n.getAttribute('onclick') && n.getAttribute('onclick').includes(id)) n.classList.add('active');
  }});
  if (id === 'charts') renderCharts();
}}

function filterBySeverity(sev) {{
  setSevFilter(sev);
}}

// ─── Issues filtering ───
function setSevFilter(sev) {{
  sevFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + sev)?.classList.add('active');
  currentPage = 1;
  applyFilters();
}}

function filterIssues() {{
  currentPage = 1;
  applyFilters();
}}

function applyFilters() {{
  const q = document.getElementById('issueSearch').value.toLowerCase();
  filtered = ALL_ISSUES.filter(issue => {{
    const sevOk  = sevFilter === 'all' || issue.severity === sevFilter;
    const textOk = !q || issue.file.toLowerCase().includes(q) ||
                   issue.message.toLowerCase().includes(q) ||
                   (issue.rule || '').toLowerCase().includes(q) ||
                   (issue.category || '').toLowerCase().includes(q) ||
                   (issue.suggestion || '').toLowerCase().includes(q);
    return sevOk && textOk;
  }});
  renderPage();
}}

function renderPage() {{
  const tbody    = document.getElementById('issuesTbody');
  const start    = (currentPage - 1) * PAGE_SIZE;
  const pageData = filtered.slice(start, start + PAGE_SIZE);

  const SEV_BADGE = {{
    critical: '<span class="badge badge-critical">🔴 Critique</span>',
    warning:  '<span class="badge badge-warning">🟡 Warning</span>',
    info:     '<span class="badge badge-info">🔵 Info</span>',
  }};

  const CAT_ICONS = {json.dumps(CAT_ICON, ensure_ascii=False)};

  tbody.innerHTML = pageData.length === 0
    ? '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text2)">✅ Aucun problème trouvé pour ces filtres</td></tr>'
    : pageData.map(issue => `
      <tr>
        <td>${{SEV_BADGE[issue.severity] || issue.severity}}</td>
        <td><span class="badge badge-cat">${{CAT_ICONS[issue.category] || ''}} ${{issue.category}}</span></td>
        <td>
          <span class="filepath">${{escHtml(issue.file)}}</span>
          ${{issue.line ? `<span class="line-badge">L${{issue.line}}</span>` : ''}}
        </td>
        <td>
          <div class="issue-msg">${{escHtml(issue.message)}}</div>
          ${{issue.suggestion ? `<div class="issue-sug">💡 ${{escHtml(issue.suggestion)}}</div>` : ''}}
        </td>
        <td><span class="rule-code">${{escHtml(issue.rule || '—')}}</span></td>
      </tr>`).join('');

  document.getElementById('visibleCount').textContent = `${{filtered.length}} affiché(s)`;
  renderPagination();
}}

function renderPagination() {{
  const total = Math.ceil(filtered.length / PAGE_SIZE);
  const pg    = document.getElementById('pagination');
  if (total <= 1) {{ pg.innerHTML = `<span>${{filtered.length}} problème(s)</span><div></div>`; return; }}

  let pages = '';
  for (let p = Math.max(1, currentPage-2); p <= Math.min(total, currentPage+2); p++) {{
    pages += `<button class="page-btn ${{p===currentPage?'active':''}}" onclick="goPage(${{p}})">${{p}}</button>`;
  }}

  pg.innerHTML = `
    <span>${{filtered.length}} problème(s) — page ${{currentPage}}/${{total}}</span>
    <div class="page-btns">
      <button class="page-btn" onclick="goPage(1)" ${{currentPage===1?'disabled':''}}>«</button>
      <button class="page-btn" onclick="goPage(${{currentPage-1}})" ${{currentPage===1?'disabled':''}}>&lt;</button>
      ${{pages}}
      <button class="page-btn" onclick="goPage(${{currentPage+1}})" ${{currentPage===total?'disabled':''}}>></button>
      <button class="page-btn" onclick="goPage(${{total}})" ${{currentPage===total?'disabled':''}}>»</button>
    </div>`;
}}

function goPage(p) {{
  currentPage = p;
  renderPage();
  document.getElementById('sec-issues').scrollTo(0,0);
}}

function escHtml(str) {{
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

// ─── Charts ───
let chartsRendered = false;

function renderCharts() {{
  if (chartsRendered) return;
  chartsRendered = true;

  const defaults = {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{ legend: {{ labels: {{ color: '#8899bb', font: {{ family: 'JetBrains Mono', size: 11 }} }} }} }},
  }};

  Chart.defaults.color = '#8899bb';

  // Severity doughnut
  new Chart(document.getElementById('severityChart'), {{
    type: 'doughnut',
    data: {{
      labels: {json.dumps(sev_labels)},
      datasets: [{{ data: {json.dumps(sev_values)}, backgroundColor: ['#ff4d6d','#ffc107','#4dabf7'],
        borderColor: '#0f1524', borderWidth: 3, hoverOffset: 8 }}]
    }},
    options: {{ ...defaults, cutout: '65%' }}
  }});

  // Category bar
  new Chart(document.getElementById('categoryChart'), {{
    type: 'bar',
    data: {{
      labels: {json.dumps(cat_labels)},
      datasets: [{{ data: {json.dumps(cat_values)}, backgroundColor: 'rgba(124,108,255,0.7)',
        borderColor: 'rgba(124,108,255,1)', borderWidth: 1, borderRadius: 4 }}]
    }},
    options: {{ ...defaults, indexAxis: 'y',
      scales: {{
        x: {{ ticks: {{ color: '#8899bb' }}, grid: {{ color: '#1c2438' }} }},
        y: {{ ticks: {{ color: '#8899bb', font: {{ size: 10 }} }}, grid: {{ display: false }} }}
      }},
      plugins: {{ legend: {{ display: false }} }}
    }}
  }});

  // Extension pie
  new Chart(document.getElementById('extChart'), {{
    type: 'doughnut',
    data: {{
      labels: {json.dumps(ext_labels)},
      datasets: [{{ data: {json.dumps(ext_values)},
        backgroundColor: ['#4c9ffe','#7c6cff','#40c983','#ffc107','#ff4d6d','#c77dff','#48cae4','#80b918','#e63946','#f77f00'],
        borderColor: '#0f1524', borderWidth: 3 }}]
    }},
    options: {{ ...defaults, cutout: '50%' }}
  }});

  // Top files bar
  new Chart(document.getElementById('topFilesChart'), {{
    type: 'bar',
    data: {{
      labels: {json.dumps(top_files_labels)},
      datasets: [{{ data: {json.dumps(top_files_values)}, backgroundColor: 'rgba(255,77,109,0.65)',
        borderColor: 'rgba(255,77,109,1)', borderWidth: 1, borderRadius: 4 }}]
    }},
    options: {{ ...defaults, indexAxis: 'y',
      scales: {{
        x: {{ ticks: {{ color: '#8899bb' }}, grid: {{ color: '#1c2438' }} }},
        y: {{ ticks: {{ color: '#8899bb', font: {{ size: 10 }} }}, grid: {{ display: false }} }}
      }},
      plugins: {{ legend: {{ display: false }} }}
    }}
  }});
}}

// ─── Gauge (dashboard) ───
(function() {{
  const score = {self.score};
  const color = '{grade_color}';
  const ctx   = document.getElementById('gaugeChart');
  if (!ctx) return;

  new Chart(ctx, {{
    type: 'doughnut',
    data: {{
      datasets: [{{
        data: [score, 100 - score],
        backgroundColor: [color, '#1c2438'],
        borderColor: ['transparent', 'transparent'],
        borderWidth: 0,
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      cutout: '75%',
      rotation: -90,
      circumference: 180,
      plugins: {{ legend: {{ display: false }}, tooltip: {{ enabled: false }} }},
      animation: {{ animateRotate: true, duration: 800 }},
    }}
  }});
}})();

// ─── Init ───
renderPage();
</script>
</body>
</html>"""

    # ─────────────────────────── Helpers ───────────────────────────

    def _grade_color(self, grade: str) -> str:
        return {
            "A+": "#40c983", "A": "#40c983",
            "B+": "#4dabf7", "B": "#4dabf7",
            "C+": "#ffc107", "C": "#ffc107",
            "D": "#ff922b",  "F": "#ff4d6d",
        }.get(grade, "#8899bb")

    def _score_comment(self, score: int) -> str:
        if score >= 90:
            return "Excellent ! Le code est de très bonne qualité."
        elif score >= 75:
            return "Bonne qualité générale. Quelques points d'amélioration restent."
        elif score >= 60:
            return "Qualité correcte, mais des problèmes significatifs méritent attention."
        elif score >= 40:
            return "Qualité insuffisante. Plusieurs problèmes critiques à corriger."
        else:
            return "Code de mauvaise qualité. Refactorisation importante recommandée."

    def _issues_rows(self) -> str:
        """Pre-rendered server-side rows (JS will re-render with filtering)."""
        # We render a placeholder; JS handles the actual rendering
        return ""

    def _top_files_card(self, sorted_files) -> str:
        if not sorted_files:
            return '<div class="card"><div class="empty-state"><div class="big">✅</div><p>Aucun problème détecté !</p></div></div>'

        rows = ""
        for filepath, file_issue_list in sorted_files:
            crit = sum(1 for i in file_issue_list if i.severity == Severity.CRITICAL)
            warn = sum(1 for i in file_issue_list if i.severity == Severity.WARNING)
            info = sum(1 for i in file_issue_list if i.severity == Severity.INFO)
            total = len(file_issue_list)
            bar_pct = min(100, total * 5)
            rows += f"""
            <tr>
              <td><span class="filepath">{html.escape(filepath)}</span></td>
              <td><span style="color:var(--crit);font-family:var(--font-mono)">{crit}</span></td>
              <td><span style="color:var(--warn);font-family:var(--font-mono)">{warn}</span></td>
              <td><span style="color:var(--info);font-family:var(--font-mono)">{info}</span></td>
              <td>
                <div style="display:flex;align-items:center;gap:8px">
                  <div style="flex:1;background:var(--bg4);border-radius:4px;height:5px;overflow:hidden">
                    <div style="width:{bar_pct}%;height:100%;background:var(--crit);border-radius:4px"></div>
                  </div>
                  <span style="font-family:var(--font-mono);font-size:12px;color:var(--text2);width:24px">{total}</span>
                </div>
              </td>
            </tr>"""

        return f"""
        <div class="card">
          <div class="card-title" style="margin-bottom:14px">Top fichiers — Observations détectés</div>
          <div style="overflow:auto;">
            <table class="file-summary-table">
              <thead><tr><th>Fichier</th><th>🔴</th><th>🟡</th><th>🔵</th><th>Total</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""

    def _file_summary_rows(self, sorted_files) -> str:
        rows = ""
        for filepath, file_issue_list in sorted_files:
            crit = sum(1 for i in file_issue_list if i.severity == Severity.CRITICAL)
            warn = sum(1 for i in file_issue_list if i.severity == Severity.WARNING)
            info = sum(1 for i in file_issue_list if i.severity == Severity.INFO)
            total = len(file_issue_list)
            rows += f"""
            <tr>
              <td><span class="filepath" style="max-width:300px">{html.escape(filepath)}</span></td>
              <td style="color:var(--crit);font-family:var(--font-mono)">{crit}</td>
              <td style="color:var(--warn);font-family:var(--font-mono)">{warn}</td>
              <td style="color:var(--info);font-family:var(--font-mono)">{info}</td>
              <td style="font-family:var(--font-mono);font-weight:700">{total}</td>
            </tr>"""
        return rows

    def _category_bars(self, cat_counts, cat_sev) -> str:
        if not cat_counts:
            return '<div class="empty-state"><p>Aucune catégorie de problème</p></div>'
        max_val = max(cat_counts.values(), default=1)
        html_out = ""
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            icon = CAT_ICON.get(cat, "📌")
            pct = int(count / max_val * 100)
            cs = cat_sev[cat]
            html_out += f"""
            <div class="cat-bar-row">
              <div class="cat-icon">{icon}</div>
              <div class="cat-name">{html.escape(cat)}</div>
              <div class="cat-bar-wrap">
                <div class="cat-bar" style="width:{pct}%"></div>
              </div>
              <div style="display:flex;gap:6px;align-items:center">
                {f'<span class="badge badge-critical" style="font-size:10px">{cs["critical"]}</span>' if cs["critical"] else ''}
                {f'<span class="badge badge-warning" style="font-size:10px">{cs["warning"]}</span>' if cs["warning"] else ''}
                {f'<span class="badge badge-info" style="font-size:10px">{cs["info"]}</span>' if cs["info"] else ''}
              </div>
              <div class="cat-num">{count}</div>
            </div>"""
        return html_out

    def _build_file_tree_html(self, file_issues) -> str:
        tree: dict = {}
        for path in sorted(self.files.keys()):
            parts = path.replace("\\", "/").split("/")
            node = tree
            for part in parts:
                node = node.setdefault(part, {})

        def render_node(node: dict, path_prefix="") -> str:
            result = ""
            for name, children in sorted(node.items()):
                full_path = f"{path_prefix}/{name}".lstrip("/")
                if children:  # folder
                    result += f'<div class="tree-folder" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">📁 {html.escape(name)}</div>'
                    result += f'<div class="tree-children">{render_node(children, full_path)}</div>'
                else:  # file
                    issues_list = file_issues.get(full_path, [])
                    n_crit = sum(1 for i in issues_list if i.severity == Severity.CRITICAL)
                    n_warn = sum(1 for i in issues_list if i.severity == Severity.WARNING)
                    cls = "has-issues" if n_crit > 0 else ("has-warnings" if n_warn > 0 else "")
                    badge = ""
                    if n_crit: badge += f'<span class="tree-count badge-critical" style="background:rgba(255,77,109,.15);color:var(--crit);padding:1px 5px;border-radius:4px;font-size:10px">{n_crit}🔴</span>'
                    elif n_warn: badge += f'<span class="tree-count" style="color:var(--warn);font-size:10px">{n_warn}🟡</span>'
                    result += f'<div class="tree-file {cls}">📄 {html.escape(name)} {badge}</div>'
            return result

        return render_node(tree)
