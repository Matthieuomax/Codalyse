#!/usr/bin/env python3
"""
serve.py — Interface web locale Codalyse
Lance avec : python serve.py
Puis ouvre : http://localhost:5000
"""

import sys
import os
import uuid
import shutil
import zipfile
import tempfile
from pathlib import Path

# Ajoute le dossier du script au path Python pour les imports locaux
sys.path.insert(0, str(Path(__file__).parent))

from flask import Flask, request, jsonify, send_file, render_template_string
from core.scanner import ProjectScanner
from core.issue import Issue, Severity, compute_score
from core.issue import Category as Cat
from analyzers.python_analyzer      import PythonAnalyzer
from analyzers.c_cpp_analyzer       import CCppAnalyzer
from analyzers.shell_analyzer       import ShellAnalyzer
from analyzers.systemd_analyzer     import SystemdAnalyzer
from analyzers.desktop_analyzer     import DesktopAnalyzer
from analyzers.vhdl_analyzer        import VHDLAnalyzer
from analyzers.data_analyzer        import DataAnalyzer
from analyzers.markdown_analyzer    import MarkdownAnalyzer
from analyzers.js_ts_analyzer       import JsTsAnalyzer
from analyzers.dockerfile_analyzer  import DockerfileAnalyzer
from analyzers.makefile_analyzer    import MakefileAnalyzer
from analyzers.html_analyzer        import HtmlAnalyzer
from analyzers.security_analyzer    import SecurityAnalyzer
from analyzers.architecture_analyzer import ArchitectureAnalyzer
from report.html_report             import HTMLReport

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max upload

FILE_ANALYZERS = [
    PythonAnalyzer(),
    CCppAnalyzer(),
    ShellAnalyzer(),
    SystemdAnalyzer(),
    DesktopAnalyzer(),
    VHDLAnalyzer(),
    DataAnalyzer(),
    MarkdownAnalyzer(),
    JsTsAnalyzer(),
    DockerfileAnalyzer(),
    MakefileAnalyzer(),
    HtmlAnalyzer(),
    SecurityAnalyzer(),
]

# ─────────────────────────────────────────────────────────────────────────────
# Moteur d'analyse (identique au CLI)
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis_on_dir(root: Path, ignore=None) -> dict:
    """Analyse un répertoire et retourne un dict de résultats."""
    ignore = ignore or []
    scanner = ProjectScanner(root, ignore)
    files = scanner.scan()

    all_issues: list[Issue] = []

    for filepath, content in files.items():
        for analyzer in FILE_ANALYZERS:
            try:
                if analyzer.can_analyze(filepath):
                    all_issues.extend(analyzer.analyze(filepath, content))
            except Exception as ex:
                all_issues.append(Issue(
                    file=filepath, line=None,
                    severity=Severity.WARNING,
                    category=Cat.RELIABILITY,
                    message=f"[Erreur analyseur] {type(ex).__name__}: {ex}",
                    suggestion="Signalez ce bug.", rule="INT-ERR"))

    arch = ArchitectureAnalyzer(root)
    try:
        all_issues.extend(arch.analyze_project(files))
    except Exception:
        pass

    score, grade = compute_score(all_issues)
    n_crit = sum(1 for i in all_issues if i.severity == Severity.CRITICAL)
    n_warn = sum(1 for i in all_issues if i.severity == Severity.WARNING)
    n_info = sum(1 for i in all_issues if i.severity == Severity.INFO)

    return {
        "root":    root,
        "files":   files,
        "issues":  all_issues,
        "score":   score,
        "grade":   grade,
        "n_files": len(files),
        "n_crit":  n_crit,
        "n_warn":  n_warn,
        "n_info":  n_info,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Routes Flask
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/manifest.json")
def manifest():
    return app.send_static_file("manifest.json"), 200, {"Content-Type": "application/manifest+json"}


@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("icon-192.png"), 200, {"Content-Type": "image/png"}


@app.route("/")
def index():
    return render_template_string(HTML_INTERFACE)


@app.route("/analyze/zip", methods=["POST"])
def analyze_zip():
    """Reçoit un ZIP, l'extrait dans un dossier temp, lance l'analyse, retourne le HTML."""
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier reçu"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Nom de fichier vide"}), 400

    # Vérifie que c'est bien un ZIP
    if not (f.filename.endswith(".zip") or f.content_type in ("application/zip", "application/x-zip-compressed")):
        return jsonify({"error": "Seuls les fichiers .zip sont acceptés"}), 400

    tmp_dir = Path(tempfile.mkdtemp(prefix="analyzer_"))
    try:
        zip_path = tmp_dir / "upload.zip"
        f.save(str(zip_path))

        # Extraire le ZIP
        extract_dir = tmp_dir / "project"
        with zipfile.ZipFile(zip_path, "r") as z:
            # Sécurité : refuse les path traversal (../../etc)
            for member in z.namelist():
                if ".." in member or member.startswith("/"):
                    return jsonify({"error": "ZIP malformé (path traversal détecté)"}), 400
            z.extractall(extract_dir)

        # Si le ZIP contient un unique sous-dossier racine, on descend dedans
        children = list(extract_dir.iterdir())
        if len(children) == 1 and children[0].is_dir():
            root = children[0]
        else:
            root = extract_dir

        # Lancer l'analyse
        result = run_analysis_on_dir(root)

        # Générer le rapport HTML dans un fichier temporaire
        report_path = tmp_dir / "rapport.html"
        report = HTMLReport(root, result["files"], result["issues"])
        report.generate(report_path)

        # Retourner le rapport HTML directement
        html_content = report_path.read_text(encoding="utf-8")

        # Injecter un résumé JSON dans le header pour que la page de résumé l'affiche
        summary = {
            "project_name": root.name,
            "score":   result["score"],
            "grade":   result["grade"],
            "n_files": result["n_files"],
            "n_crit":  result["n_crit"],
            "n_warn":  result["n_warn"],
            "n_info":  result["n_info"],
        }

        return jsonify({
            "ok":      True,
            "summary": summary,
            "report":  html_content,
        })

    except zipfile.BadZipFile:
        return jsonify({"error": "Fichier ZIP invalide ou corrompu"}), 400
    except Exception as e:
        return jsonify({"error": f"Erreur lors de l'analyse : {e}"}), 500
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/analyze/text", methods=["POST"])
def analyze_text():
    """Reçoit du code texte + un nom de fichier, analyse et retourne les issues JSON."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON attendu"}), 400

    code     = data.get("code", "").strip()
    filename = data.get("filename", "fichier.py").strip() or "fichier.py"
    ignore   = data.get("ignore", [])

    if not code:
        return jsonify({"error": "Code vide"}), 400

    tmp_dir = Path(tempfile.mkdtemp(prefix="analyzer_text_"))
    try:
        file_path = tmp_dir / filename
        file_path.write_text(code, encoding="utf-8")

        result = run_analysis_on_dir(tmp_dir)

        issues_out = [i.to_dict() for i in result["issues"] if i.file == filename]

        return jsonify({
            "ok":      True,
            "score":   result["score"],
            "grade":   result["grade"],
            "n_files": result["n_files"],
            "n_crit":  result["n_crit"],
            "n_warn":  result["n_warn"],
            "n_info":  result["n_info"],
            "issues":  issues_out,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Interface HTML embarquée
# ─────────────────────────────────────────────────────────────────────────────

HTML_INTERFACE = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover">
<title>Codalyse — Analyseur de code</title>
<meta name="description" content="Analyseur de qualité de code local — 14 langages, 200+ règles">
<meta name="theme-color" content="#00c896">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Codalyse">
<link rel="manifest" href="/manifest.json">
<link rel="icon" type="image/png" sizes="192x192" href="/static/icon-192.png">
<link rel="apple-touch-icon" sizes="192x192" href="/static/icon-192.png">
<link rel="apple-touch-icon" sizes="512x512" href="/static/icon-512.png">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Outfit:wght@400;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root {
  --bg:     #0a0e1a; --bg2: #0f1524; --bg3: #151c30; --bg4: #1c2438;
  --border: #232d45; --border2: #2d3a58;
  --text:   #c8d6f0; --text2: #8899bb; --text3: #556;
  --accent: #00c896; --accent2: #00a37a;
  --crit:   #ff4d6d; --warn: #ffc107; --info: #4dabf7; --ok: #40c983;
  --font-mono: 'JetBrains Mono', monospace;
  --font-ui:   'Outfit', sans-serif;
  --r: 10px; --r-lg: 16px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--font-ui);font-size:14px;min-height:100vh}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

/* ── Layout ── */
.page{max-width:960px;margin:0 auto;padding:40px 24px}
h1{font-size:28px;font-weight:800;letter-spacing:-.01em;color:var(--text);margin-bottom:6px}
.subtitle{font-size:13px;color:var(--text2);margin-bottom:36px}

/* ── Tabs ── */
.tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:0}
.tab{padding:10px 20px;border:none;background:transparent;font-family:var(--font-ui);font-size:13px;font-weight:700;color:var(--text2);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none}.tab-content.active{display:block}

/* ── Drop zone ── */
.dropzone{
  border:2px dashed var(--border2);border-radius:var(--r-lg);
  padding:48px 24px;text-align:center;cursor:pointer;
  transition:all .2s;background:var(--bg2);margin-bottom:16px;
  position:relative;
}
.dropzone:hover,.dropzone.drag-over{border-color:var(--accent);background:rgba(76,159,254,.06)}
.dropzone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.dz-icon{font-size:40px;margin-bottom:12px;display:block}
.dz-title{font-size:16px;font-weight:700;margin-bottom:6px}
.dz-sub{font-size:12px;color:var(--text2)}
.dz-sub span{color:var(--accent);font-weight:600}

/* ── Options ── */
.options-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.ignore-input{flex:1;min-width:200px;padding:8px 12px;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);color:var(--text);font-family:var(--font-mono);font-size:12px;outline:none}
.ignore-input:focus{border-color:var(--accent)}
.ignore-input::placeholder{color:var(--text2)}

/* ── Code editor ── */
.file-type-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.ft-label{font-size:11px;color:var(--text2);white-space:nowrap}
.ft-btn{padding:4px 10px;border:1px solid var(--border2);border-radius:6px;background:transparent;font-size:11px;font-family:var(--font-mono);color:var(--text2);cursor:pointer;transition:all .12s}
.ft-btn:hover{border-color:var(--accent);color:var(--text)}
.ft-btn.active{background:rgba(76,159,254,.12);border-color:var(--accent);color:var(--accent)}
.filename-input{padding:7px 12px;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);color:var(--text);font-family:var(--font-mono);font-size:12px;outline:none;width:220px}
.filename-input:focus{border-color:var(--accent)}
.code-editor{width:100%;min-height:280px;resize:vertical;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);padding:14px;font-family:var(--font-mono);font-size:12px;color:var(--text);outline:none;transition:border-color .15s;line-height:1.6;margin-bottom:12px}
.code-editor:focus{border-color:var(--accent)}
.code-editor::placeholder{color:var(--text2)}

/* ── Buttons ── */
.btn{padding:10px 24px;border-radius:var(--r);font-family:var(--font-ui);font-size:13px;font-weight:700;cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:8px;border:none}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#3a8fe8}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
.btn-secondary{background:transparent;color:var(--text2);border:1px solid var(--border2)}
.btn-secondary:hover{border-color:var(--accent);color:var(--text)}

/* ── Progress ── */
.progress-wrap{display:none;margin:20px 0}
.progress-label{font-size:12px;color:var(--text2);margin-bottom:8px;font-family:var(--font-mono)}
.progress-bar-bg{background:var(--bg4);border-radius:4px;height:4px;overflow:hidden}
.progress-bar{height:100%;background:var(--accent);border-radius:4px;transition:width .3s;width:0%}

/* ── Summary cards ── */
.summary-wrap{display:none}
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.scard{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:16px 20px;position:relative;overflow:hidden}
.scard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.scard.blue::before{background:var(--accent)}
.scard.red::before{background:var(--crit)}
.scard.yellow::before{background:var(--warn)}
.scard.green::before{background:var(--ok)}
.scard-label{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text2);margin-bottom:6px}
.scard-val{font-family:var(--font-mono);font-size:28px;font-weight:700}
.scard.blue .scard-val{color:var(--accent)}
.scard.red .scard-val{color:var(--crit)}
.scard.yellow .scard-val{color:var(--warn)}
.scard.green .scard-val{color:var(--ok)}

/* ── Actions after analysis ── */
.action-row{display:flex;gap:10px;margin-bottom:24px;flex-wrap:wrap}

/* ── Inline issues (mode texte) ── */
.issues-section{margin-top:20px}
.issues-header{font-size:13px;font-weight:700;color:var(--text2);margin-bottom:12px;text-transform:uppercase;letter-spacing:.07em}
.issue-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:12px 14px;margin-bottom:8px;border-left:3px solid transparent}
.issue-card.critical{border-left-color:var(--crit)}
.issue-card.warning{border-left-color:var(--warn)}
.issue-card.info{border-left-color:var(--info)}
.ic-header{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;border:1px solid}
.badge-crit{background:rgba(255,77,109,.12);border-color:rgba(255,77,109,.35);color:var(--crit)}
.badge-warn{background:rgba(255,193,7,.1);border-color:rgba(255,193,7,.3);color:var(--warn)}
.badge-info{background:rgba(77,171,247,.1);border-color:rgba(77,171,247,.3);color:var(--info)}
.badge-cat{background:var(--bg4);border-color:var(--border2);color:var(--text2);font-size:10px}
.line-badge{font-family:var(--font-mono);font-size:10px;color:var(--text2);background:var(--bg4);border:1px solid var(--border);border-radius:4px;padding:1px 5px}
.rule-badge{margin-left:auto;font-family:var(--font-mono);font-size:10px;color:var(--text2)}
.ic-msg{font-size:13px;font-weight:600;color:var(--text)}
.ic-sug{font-size:12px;color:var(--text2);margin-top:3px}

/* ── Error ── */
.error-box{background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.3);border-radius:var(--r);padding:14px 16px;margin-top:16px;font-size:13px;color:var(--crit);display:none}

/* ── Iframe report ── */
.report-frame{width:100%;height:85vh;border:1px solid var(--border);border-radius:var(--r-lg);margin-top:16px;background:var(--bg2)}

@media(max-width:640px){.summary-grid{grid-template-columns:1fr 1fr}.action-row{flex-direction:column}}
</style>
</head>
<body>
<div class="page">

  <div style="display:flex;align-items:center;gap:14px;margin-bottom:8px">
    <div style="width:40px;height:40px;background:var(--accent);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:900;color:#0a0e1a;font-family:var(--font-ui);flex-shrink:0">C</div>
    <div>
      <h1 style="margin-bottom:0">Codalyse</h1>
      <p class="subtitle" style="margin-bottom:0">Analyseur de qualité de code — 14 langages, 200+ règles</p>
    </div>
  </div>
  <p style="font-size:11px;color:var(--text2);margin-bottom:36px;padding-left:54px">Aucune donnée envoyée sur internet — analyse 100% locale</p>

  <!-- ── Tabs ── -->
  <div class="tabs">
    <button class="tab active" onclick="switchTab('zip')">📦 Projet ZIP</button>
    <button class="tab" onclick="switchTab('text')">📝 Fichier unique</button>
  </div>

  <!-- ══════════ TAB ZIP ══════════ -->
  <div class="tab-content active" id="tab-zip">

    <div class="dropzone" id="dropzone">
      <input type="file" id="zipInput" accept=".zip" onchange="onZipSelected(this)">
      <span class="dz-icon">📂</span>
      <div class="dz-title">Glisse ton projet ici</div>
      <div class="dz-sub">ou <span>clique pour choisir un fichier</span> — format <strong>.zip</strong> uniquement</div>
      <div style="font-size:11px;color:var(--text2);margin-top:10px" id="dzFileName"></div>
    </div>

    <div class="options-row">
      <span style="font-size:12px;color:var(--text2)">Ignorer :</span>
      <input class="ignore-input" id="ignoreInput" placeholder="node_modules, dist, build, vendor, .git" value="node_modules,dist,build,.git,vendor">
      <button class="btn btn-primary" id="analyzeZipBtn" onclick="analyzeZip()" disabled>
        Analyser →
      </button>
    </div>

    <div class="progress-wrap" id="zipProgress">
      <div class="progress-label" id="progressLabel">Extraction du ZIP…</div>
      <div class="progress-bar-bg"><div class="progress-bar" id="progressBar"></div></div>
    </div>

    <div class="error-box" id="zipError"></div>

    <!-- Résumé + rapport embarqué -->
    <div class="summary-wrap" id="zipSummary">
      <div class="summary-grid" id="summaryCards"></div>
      <div class="action-row">
        <button class="btn btn-primary" onclick="openReportNewTab()">Ouvrir le rapport complet ↗</button>
        <button class="btn btn-secondary" onclick="downloadReport()">⬇ Télécharger HTML</button>
        <button class="btn btn-secondary" onclick="resetZip()">Nouvelle analyse</button>
      </div>
      <iframe class="report-frame" id="reportFrame" title="Rapport d'analyse"></iframe>
    </div>

  </div>

  <!-- ══════════ TAB TEXT ══════════ -->
  <div class="tab-content" id="tab-text">

    <div class="file-type-row">
      <span class="ft-label">Type :</span>
      <button class="ft-btn active" onclick="setFt(this,'fichier.py')">Python</button>
      <button class="ft-btn" onclick="setFt(this,'utils.c')">C/C++</button>
      <button class="ft-btn" onclick="setFt(this,'deploy.sh')">Shell</button>
      <button class="ft-btn" onclick="setFt(this,'counter.vhd')">VHDL</button>
      <button class="ft-btn" onclick="setFt(this,'app.js')">JS/TS</button>
      <button class="ft-btn" onclick="setFt(this,'Dockerfile')">Dockerfile</button>
      <button class="ft-btn" onclick="setFt(this,'Makefile')">Makefile</button>
      <button class="ft-btn" onclick="setFt(this,'config.yaml')">YAML/JSON</button>
      <button class="ft-btn" onclick="setFt(this,'app.service')">Systemd</button>
      <button class="ft-btn" onclick="setFt(this,'index.html')">HTML</button>
      <span style="margin-left:auto;font-size:11px;color:var(--text2)">Nom du fichier :</span>
      <input class="filename-input" id="filenameInput" value="fichier.py">
    </div>

    <textarea class="code-editor" id="codeEditor" placeholder="# Colle ton code ici…"></textarea>

    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-primary" id="analyzeTextBtn" onclick="analyzeText()">Analyser →</button>
      <button class="btn btn-secondary" onclick="loadTextExample()">Charger un exemple</button>
      <button class="btn btn-secondary" onclick="clearText()">Effacer</button>
    </div>

    <div class="progress-wrap" id="textProgress">
      <div class="progress-label">Analyse en cours…</div>
      <div class="progress-bar-bg"><div class="progress-bar" id="textProgressBar"></div></div>
    </div>

    <div class="error-box" id="textError"></div>

    <div class="summary-wrap" id="textSummary">
      <div class="summary-grid" id="textSummaryCards"></div>
      <div class="issues-section">
        <div class="issues-header" id="issuesHeader">Problèmes détectés</div>
        <div id="issuesList"></div>
      </div>
    </div>

  </div>

</div><!-- /page -->

<script>
let _reportHtml = "";
let _reportBlob = null;

// ── Tabs ──────────────────────────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  event.target.classList.add('active');
}

// ── Drag & drop visual feedback ───────────────────────────────────────────
const dz = document.getElementById('dropzone');
['dragenter','dragover'].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add('drag-over'); }));
['dragleave','drop'].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.remove('drag-over'); }));
dz.addEventListener('drop', ev => {
  const files = ev.dataTransfer.files;
  if (files.length > 0) handleZipFile(files[0]);
});

function onZipSelected(input) {
  if (input.files.length > 0) handleZipFile(input.files[0]);
}

function handleZipFile(file) {
  if (!file.name.endsWith('.zip')) {
    showError('zipError', 'Seuls les fichiers .zip sont acceptés. Compressez votre dossier avec "Envoyer vers → Dossier compressé" (Windows) ou "zip -r projet.zip projet/" (Linux/Mac).');
    return;
  }
  document.getElementById('dzFileName').textContent = '📦 ' + file.name + ' (' + (file.size / 1024).toFixed(0) + ' Ko)';
  document.getElementById('analyzeZipBtn').disabled = false;
  document.getElementById('analyzeZipBtn').dataset.file = '';
  window._selectedZipFile = file;
  hideError('zipError');
}

// ── ZIP analysis ──────────────────────────────────────────────────────────
async function analyzeZip() {
  if (!window._selectedZipFile) return;
  const btn = document.getElementById('analyzeZipBtn');
  btn.disabled = true;
  btn.textContent = 'Analyse en cours…';

  showProgress('zipProgress', 'Envoi et extraction du ZIP…', 20);
  hideError('zipError');
  document.getElementById('zipSummary').style.display = 'none';

  const formData = new FormData();
  formData.append('file', window._selectedZipFile);

  try {
    setProgress('zipProgress', 'Analyse des fichiers…', 60);
    const resp = await fetch('/analyze/zip', { method: 'POST', body: formData });
    setProgress('zipProgress', 'Génération du rapport…', 90);
    const data = await resp.json();

    if (!data.ok) {
      showError('zipError', data.error || 'Erreur inconnue');
      hideProgress('zipProgress');
      btn.disabled = false;
      btn.textContent = 'Analyser →';
      return;
    }

    setProgress('zipProgress', 'Terminé', 100);
    setTimeout(() => hideProgress('zipProgress'), 500);

    _reportHtml = data.report;
    _reportBlob = new Blob([_reportHtml], { type: 'text/html' });

    renderSummaryCards('summaryCards', data.summary);
    document.getElementById('zipSummary').style.display = 'block';

    // Injecter le rapport dans l'iframe
    const frame = document.getElementById('reportFrame');
    const blobUrl = URL.createObjectURL(_reportBlob);
    frame.src = blobUrl;

  } catch(e) {
    showError('zipError', 'Erreur réseau : ' + e.message);
    hideProgress('zipProgress');
  }

  btn.disabled = false;
  btn.textContent = 'Analyser →';
}

function openReportNewTab() {
  if (!_reportBlob) return;
  window.open(URL.createObjectURL(_reportBlob), '_blank');
}

function downloadReport() {
  if (!_reportBlob) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(_reportBlob);
  a.download = 'rapport_analyse.html';
  a.click();
}

function resetZip() {
  window._selectedZipFile = null;
  document.getElementById('dzFileName').textContent = '';
  document.getElementById('analyzeZipBtn').disabled = true;
  document.getElementById('zipSummary').style.display = 'none';
  document.getElementById('zipInput').value = '';
}

// ── Text analysis ─────────────────────────────────────────────────────────
const TEXT_EXAMPLES = {
  'fichier.py': `import os, subprocess\nDB_PASSWORD = "admin123"\n\ndef GetUserData(userId):\n    query = "SELECT * FROM users WHERE id = %s" % userId\n    result = eval(query)\n    return result\n\nclass userManager:\n    def create_user(self, name, password):\n        import hashlib\n        h = hashlib.md5(password.encode()).hexdigest()\n        print("User: " + name)\n        return h`,
  'utils.c': `#include <stdio.h>\n#include <string.h>\n\nvoid copyInput(char* dest, char* src) {\n    strcpy(dest, src);\n}\n\nint readLine(char* buffer) {\n    gets(buffer);\n    return strlen(buffer);\n}`,
  'deploy.sh': `#!/bin/bash\nSERVER=$1\ndeploy_dir=/opt/app\ncd $deploy_dir\ncurl -s https://example.com/install.sh | bash\nchmod 777 /opt/app/data`,
  'counter.vhd': `library IEEE;\nuse IEEE.STD_LOGIC_1164.ALL;\n\nentity COUNTER is\n    port(CLK : in std_logic; Q : out std_logic_vector(7 downto 0));\nend COUNTER;\n\narchitecture Behavioral of COUNTER is\n    signal count : std_logic_vector(7 downto 0);\nbegin\n    process(CLK)\n    begin\n        if rising_edge(CLK) then\n            count <= count + 255;\n        end if;\n    end process;\nend Behavioral;`,
  'app.js': `const password = "hardcoded_secret";\nvar globalData = [];\n\nfunction handleInput(input) {\n    document.getElementById('out').innerHTML = input;\n    eval('process(' + input + ')');\n}`,
  'Dockerfile': `FROM ubuntu\nRUN apt-get update && apt-get install -y nodejs\nENV DB_PASSWORD=secret123\nCOPY . .\nRUN chmod 777 /app\nCMD ["node", "server.js"]`,
  'Makefile': `CC=gcc\nprogram: main.c\n    $(CC) -o program main.c\nclean:\n    rm -f program`,
  'config.yaml': `app:\n  debug: True\n  secret_key: "hardcoded-jwt-secret-abc"\ndatabase:\n  url: postgresql://admin:password123@localhost/mydb`,
  'app.service': `[Unit]\nAfter=network.target\n\n[Service]\nExecStart=/opt/app/server\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target`,
  'index.html': `<html>\n<head>\n<title>T</title>\n</head>\n<body>\n<h1>Titre</h1>\n<h1>Second H1 !</h1>\n<h3>Saut de niveau</h3>\n<img src="photo.jpg">\n<a href="http://example.com" target="_blank">Lien</a>\n<iframe src="https://example.com"></iframe>\n<input type="text">\n<button></button>\n<font color="red">Déprécié</font>\n<center>Centré</center>\n<form><input type="email" placeholder="Email"></form>\n<script>eval('alert(1)')<\/script>\n<p id="d1">A</p><p id="d1">B</p>\n</body>\n</html>`,
};

function setFt(btn, filename) {
  document.querySelectorAll('.ft-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('filenameInput').value = filename;
}

function loadTextExample() {
  const fname = document.getElementById('filenameInput').value.trim() || 'fichier.py';
  const ex = TEXT_EXAMPLES[fname] || TEXT_EXAMPLES['fichier.py'];
  document.getElementById('codeEditor').value = ex;
}

function clearText() {
  document.getElementById('codeEditor').value = '';
  document.getElementById('textSummary').style.display = 'none';
  hideError('textError');
}

async function analyzeText() {
  const code = document.getElementById('codeEditor').value.trim();
  const filename = document.getElementById('filenameInput').value.trim() || 'fichier.py';
  if (!code) { showError('textError', 'Colle du code avant de lancer l\'analyse.'); return; }

  const btn = document.getElementById('analyzeTextBtn');
  btn.disabled = true;
  btn.textContent = 'Analyse…';
  showProgress('textProgress', 'Analyse en cours…', 50);
  hideError('textError');
  document.getElementById('textSummary').style.display = 'none';

  try {
    const resp = await fetch('/analyze/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, filename })
    });
    const data = await resp.json();

    if (!data.ok) {
      showError('textError', data.error || 'Erreur inconnue');
      hideProgress('textProgress');
      btn.disabled = false; btn.textContent = 'Analyser →';
      return;
    }

    hideProgress('textProgress');
    renderSummaryCards('textSummaryCards', data);
    renderIssues(data.issues);
    document.getElementById('textSummary').style.display = 'block';

  } catch(e) {
    showError('textError', 'Erreur réseau : ' + e.message);
    hideProgress('textProgress');
  }

  btn.disabled = false;
  btn.textContent = 'Analyser →';
}

// ── Render helpers ────────────────────────────────────────────────────────
function renderSummaryCards(containerId, data) {
  const gradeColor = {
    'A+':'#40c983','A':'#40c983','B+':'#4dabf7','B':'#4dabf7',
    'C+':'#ffc107','C':'#ffc107','D':'#ff922b','F':'#ff4d6d'
  }[data.grade] || '#8899bb';

  document.getElementById(containerId).innerHTML = `
    <div class="scard blue">
      <div class="scard-label">Score</div>
      <div class="scard-val" style="color:${gradeColor}">${data.score}<span style="font-size:14px;color:var(--text2)">/100 [${data.grade}]</span></div>
    </div>
    <div class="scard red">
      <div class="scard-label">🔴 Critiques</div>
      <div class="scard-val">${data.n_crit}</div>
    </div>
    <div class="scard yellow">
      <div class="scard-label">🟡 Warnings</div>
      <div class="scard-val">${data.n_warn}</div>
    </div>
    <div class="scard green">
      <div class="scard-label">🔵 Infos</div>
      <div class="scard-val">${data.n_info}</div>
    </div>`;
}

function renderIssues(issues) {
  const SEV_LABEL = { critical:'Critique', warning:'Warning', info:'Info' };
  const SEV_BADGE = { critical:'badge-crit', warning:'badge-warn', info:'badge-info' };
  document.getElementById('issuesHeader').textContent = `${issues.length} problème(s) détecté(s)`;
  if (!issues.length) {
    document.getElementById('issuesList').innerHTML = '<div style="text-align:center;padding:32px;color:var(--text2)">✅ Aucun problème détecté !</div>';
    return;
  }
  document.getElementById('issuesList').innerHTML = issues.map(i => `
    <div class="issue-card ${i.severity}">
      <div class="ic-header">
        <span class="badge ${SEV_BADGE[i.severity]}">${SEV_LABEL[i.severity]}</span>
        <span class="badge badge-cat">${esc(i.category)}</span>
        ${i.line ? `<span class="line-badge">L${i.line}</span>` : ''}
        <span class="rule-badge">${esc(i.rule||'')}</span>
      </div>
      <div class="ic-msg">${esc(i.message)}</div>
      ${i.suggestion ? `<div class="ic-sug">💡 ${esc(i.suggestion)}</div>` : ''}
    </div>`).join('');
}

// ── Progress & error ──────────────────────────────────────────────────────
function showProgress(id, label, pct) {
  const w = document.getElementById(id);
  w.style.display = 'block';
  w.querySelector('.progress-label').textContent = label;
  w.querySelector('.progress-bar').style.width = pct + '%';
}
function setProgress(id, label, pct) { showProgress(id, label, pct); }
function hideProgress(id) { document.getElementById(id).style.display = 'none'; }
function showError(id, msg) { const e = document.getElementById(id); e.style.display = 'block'; e.textContent = '⛔ ' + msg; }
function hideError(id) { document.getElementById(id).style.display = 'none'; }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Lancement
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║        ◆  CODALYSE — Interface Web Locale  ◆    ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║   Ouvre ton navigateur sur :                    ║")
    print(f"║   http://{host}:{port}                         ║")
    print("║                                                  ║")
    print("║   Arrêt : Ctrl+C                                 ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    app.run(host=host, port=port, debug=False)
