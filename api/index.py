"""
api/index.py — Point d'entrée Vercel pour Codalyse (Flask WSGI)

Différences avec serve.py (dev local) :
  - Pas de app.run() — Vercel appelle l'objet `app` directement via WSGI
  - sys.path ajusté pour que les imports core/, analyzers/, report/ fonctionnent
  - Fichiers temporaires dans /tmp (seul endroit accessible en écriture sur Vercel)
  - Taille max ZIP : ~4 MB (limite Vercel Hobby sur le request body)
"""

import sys
import os
from pathlib import Path

# ── Correction des imports ──────────────────────────────────────────────────
# Sur Vercel, le CWD est la racine du repo.
# On ajoute la racine explicitement pour que "from core.issue import ..."
# fonctionne depuis n'importe où.
ROOT = Path(__file__).parent.parent  # api/../  =  racine du repo
sys.path.insert(0, str(ROOT))

# ── Imports projet ──────────────────────────────────────────────────────────
import uuid
import shutil
import zipfile
import tempfile

from flask import Flask, request, jsonify, send_from_directory, render_template_string

from core.scanner               import ProjectScanner
from core.issue                 import Issue, Severity, compute_score
from core.issue                 import Category as Cat
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

# ── App Flask ───────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    static_folder=str(ROOT / "static"),   # /static/ servi depuis la racine
    static_url_path="/static",
)

# Sur Vercel, MAX_CONTENT_LENGTH est limité à ~4.5 MB (plan Hobby)
# On le fixe à 4 MB pour éviter une erreur 413 silencieuse
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024   # 4 MB

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
# Moteur d'analyse
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis_on_dir(root: Path, ignore=None) -> dict:
    """Analyse un répertoire, retourne un dict de résultats."""
    ignore = ignore or []
    scanner = ProjectScanner(root, ignore)
    files   = scanner.scan()

    all_issues: list = []
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

    try:
        arch = ArchitectureAnalyzer(root)
        all_issues.extend(arch.analyze_project(files))
    except Exception:
        pass

    score, grade = compute_score(all_issues)
    return {
        "root":    root,
        "files":   files,
        "issues":  all_issues,
        "score":   score,
        "grade":   grade,
        "n_files": len(files),
        "n_crit":  sum(1 for i in all_issues if i.severity == Severity.CRITICAL),
        "n_warn":  sum(1 for i in all_issues if i.severity == Severity.WARNING),
        "n_info":  sum(1 for i in all_issues if i.severity == Severity.INFO),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML_INTERFACE)


@app.route("/manifest.json")
def manifest():
    return send_from_directory(str(ROOT / "static"), "manifest.json",
                               mimetype="application/manifest+json")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(str(ROOT / "static"), "icon-192.png",
                               mimetype="image/png")


@app.route("/analyze/zip", methods=["POST"])
def analyze_zip():
    """
    Reçoit un ZIP (≤ 4 MB sur Vercel Hobby), l'extrait dans /tmp,
    analyse et retourne le rapport HTML + résumé JSON.
    """
    if "file" not in request.files:
        return jsonify({"error": "Aucun fichier reçu"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Nom de fichier vide"}), 400

    if not f.filename.lower().endswith(".zip"):
        return jsonify({"error": "Seuls les fichiers .zip sont acceptés"}), 400

    # /tmp est le seul répertoire accessible en écriture sur Vercel
    tmp_dir = Path(tempfile.mkdtemp(prefix="codalyse_", dir="/tmp"))
    try:
        zip_path = tmp_dir / "upload.zip"
        f.save(str(zip_path))

        # Vérification taille (double-check côté serveur)
        zip_size_mb = zip_path.stat().st_size / (1024 * 1024)
        if zip_size_mb > 4:
            return jsonify({
                "error": f"ZIP trop lourd ({zip_size_mb:.1f} MB). "
                         "Limite Vercel : 4 MB. "
                         "Conseil : excluez node_modules, .git, dist avec --ignore."
            }), 413

        extract_dir = tmp_dir / "project"
        with zipfile.ZipFile(zip_path, "r") as z:
            # Sécurité : refuse les path traversal
            for member in z.namelist():
                if ".." in member or member.startswith("/"):
                    return jsonify({"error": "ZIP malformé (path traversal détecté)"}), 400
            z.extractall(extract_dir)

        # Descend dans le sous-dossier racine si ZIP = un seul dossier
        children = list(extract_dir.iterdir())
        root = children[0] if len(children) == 1 and children[0].is_dir() else extract_dir

        result = run_analysis_on_dir(root)

        # Génération du rapport HTML dans /tmp
        report_path = tmp_dir / "rapport.html"
        report = HTMLReport(root, result["files"], result["issues"])
        report.generate(report_path)
        html_content = report_path.read_text(encoding="utf-8")

        return jsonify({
            "ok": True,
            "summary": {
                "project_name": root.name,
                "score":   result["score"],
                "grade":   result["grade"],
                "n_files": result["n_files"],
                "n_crit":  result["n_crit"],
                "n_warn":  result["n_warn"],
                "n_info":  result["n_info"],
            },
            "report": html_content,
        })

    except zipfile.BadZipFile:
        return jsonify({"error": "Fichier ZIP invalide ou corrompu"}), 400
    except Exception as e:
        return jsonify({"error": f"Erreur lors de l'analyse : {e}"}), 500
    finally:
        # Nettoyage impératif : /tmp est partagé entre les invocations sur Vercel
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/analyze/text", methods=["POST"])
def analyze_text():
    """Reçoit du code texte + nom de fichier, retourne les issues JSON."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON attendu"}), 400

    code     = data.get("code", "").strip()
    filename = data.get("filename", "fichier.py").strip() or "fichier.py"

    if not code:
        return jsonify({"error": "Code vide"}), 400

    tmp_dir = Path(tempfile.mkdtemp(prefix="codalyse_text_", dir="/tmp"))
    try:
        (tmp_dir / filename).write_text(code, encoding="utf-8")
        result  = run_analysis_on_dir(tmp_dir)
        issues  = [i.to_dict() for i in result["issues"] if i.file == filename]
        return jsonify({
            "ok":      True,
            "score":   result["score"],
            "grade":   result["grade"],
            "n_files": result["n_files"],
            "n_crit":  result["n_crit"],
            "n_warn":  result["n_warn"],
            "n_info":  result["n_info"],
            "issues":  issues,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Gestion des erreurs
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(e):
    return jsonify({
        "error": "Fichier trop volumineux (limite : 4 MB sur Vercel Hobby). "
                 "Compressez en excluant node_modules, .git, dist."
    }), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route introuvable"}), 404


# ─────────────────────────────────────────────────────────────────────────────
# Interface HTML (identique à serve.py)
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
  --bg:#0a0e1a;--bg2:#0f1524;--bg3:#151c30;--bg4:#1c2438;
  --border:#232d45;--border2:#2d3a58;
  --text:#c8d6f0;--text2:#8899bb;
  --accent:#00c896;--accent2:#00a37a;
  --crit:#ff4d6d;--warn:#ffc107;--info:#4dabf7;--ok:#00c896;
  --font-mono:'JetBrains Mono',monospace;--font-ui:'Outfit',sans-serif;
  --r:10px;--r-lg:16px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:var(--font-ui);font-size:14px;min-height:100vh}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.page{max-width:960px;margin:0 auto;padding:40px 24px}
h1{font-size:28px;font-weight:800;letter-spacing:-.01em;color:var(--text);margin-bottom:0}
.subtitle{font-size:13px;color:var(--text2);margin-bottom:0}
.tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:0}
.tab{padding:10px 20px;border:none;background:transparent;font-family:var(--font-ui);font-size:13px;font-weight:700;color:var(--text2);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none}.tab-content.active{display:block}
.dropzone{border:2px dashed var(--border2);border-radius:var(--r-lg);padding:48px 24px;text-align:center;cursor:pointer;transition:all .2s;background:var(--bg2);margin-bottom:16px;position:relative}
.dropzone:hover,.dropzone.drag-over{border-color:var(--accent);background:rgba(0,200,150,.06)}
.dropzone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.dz-icon{font-size:40px;margin-bottom:12px;display:block}
.dz-title{font-size:16px;font-weight:700;margin-bottom:6px}
.dz-sub{font-size:12px;color:var(--text2)}
.dz-sub span{color:var(--accent);font-weight:600}
.dz-limit{font-size:11px;color:var(--warn);margin-top:8px;padding:6px 12px;background:rgba(255,193,7,.08);border:1px solid rgba(255,193,7,.2);border-radius:6px;display:inline-block}
.options-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.ignore-input{flex:1;min-width:200px;padding:8px 12px;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);color:var(--text);font-family:var(--font-mono);font-size:12px;outline:none}
.ignore-input:focus{border-color:var(--accent)}
.ignore-input::placeholder{color:var(--text2)}
.file-type-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.ft-label{font-size:11px;color:var(--text2);white-space:nowrap}
.ft-btn{padding:4px 10px;border:1px solid var(--border2);border-radius:6px;background:transparent;font-size:11px;font-family:var(--font-mono);color:var(--text2);cursor:pointer;transition:all .12s}
.ft-btn:hover{border-color:var(--accent);color:var(--text)}
.ft-btn.active{background:rgba(0,200,150,.12);border-color:var(--accent);color:var(--accent)}
.filename-input{padding:7px 12px;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);color:var(--text);font-family:var(--font-mono);font-size:12px;outline:none;width:220px}
.filename-input:focus{border-color:var(--accent)}
.code-editor{width:100%;min-height:280px;resize:vertical;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);padding:14px;font-family:var(--font-mono);font-size:12px;color:var(--text);outline:none;transition:border-color .15s;line-height:1.6;margin-bottom:12px}
.code-editor:focus{border-color:var(--accent)}
.code-editor::placeholder{color:var(--text2)}
.btn{padding:10px 24px;border-radius:var(--r);font-family:var(--font-ui);font-size:13px;font-weight:700;cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:8px;border:none}
.btn-primary{background:var(--accent);color:#0a0e1a}
.btn-primary:hover{background:var(--accent2)}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
.btn-secondary{background:transparent;color:var(--text2);border:1px solid var(--border2)}
.btn-secondary:hover{border-color:var(--accent);color:var(--text)}
.progress-wrap{display:none;margin:20px 0}
.progress-label{font-size:12px;color:var(--text2);margin-bottom:8px;font-family:var(--font-mono)}
.progress-bar-bg{background:var(--bg4);border-radius:4px;height:4px;overflow:hidden}
.progress-bar{height:100%;background:var(--accent);border-radius:4px;transition:width .3s;width:0%}
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
.action-row{display:flex;gap:10px;margin-bottom:24px;flex-wrap:wrap}
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
.error-box{background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.3);border-radius:var(--r);padding:14px 16px;margin-top:16px;font-size:13px;color:var(--crit);display:none}
.report-frame{width:100%;height:85vh;border:1px solid var(--border);border-radius:var(--r-lg);margin-top:16px;background:var(--bg2)}
@media(max-width:640px){.summary-grid{grid-template-columns:1fr 1fr}.action-row{flex-direction:column}}
</style>
</head>
<body>
<div class="page">
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:8px">
    <div style="width:40px;height:40px;background:var(--accent);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:900;color:#0a0e1a;font-family:var(--font-ui);flex-shrink:0">C</div>
    <div>
      <h1>Codalyse</h1>
      <p class="subtitle">Analyseur de qualité de code — 14 langages, 200+ règles</p>
    </div>
  </div>
  <p style="font-size:11px;color:var(--text2);margin-bottom:36px;padding-left:54px">Analyse 100% locale — aucun code envoyé sur internet</p>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('zip',this)">📦 Projet ZIP</button>
    <button class="tab" onclick="switchTab('text',this)">📝 Fichier unique</button>
  </div>

  <!-- ══ ZIP ══ -->
  <div class="tab-content active" id="tab-zip">
    <div class="dropzone" id="dropzone">
      <input type="file" id="zipInput" accept=".zip" onchange="onZipSelected(this)">
      <span class="dz-icon">📂</span>
      <div class="dz-title">Glisse ton projet ici</div>
      <div class="dz-sub">ou <span>clique pour choisir un fichier</span> — format <strong>.zip</strong> uniquement</div>
      <div class="dz-limit">⚠️ Limite Vercel : 4 MB — excluez node_modules, .git, dist avant de zipper</div>
      <div style="font-size:11px;color:var(--text2);margin-top:8px" id="dzFileName"></div>
    </div>
    <div class="options-row">
      <span style="font-size:12px;color:var(--text2)">Ignorer :</span>
      <input class="ignore-input" id="ignoreInput" placeholder="node_modules, dist, build, .git" value="node_modules,dist,build,.git,vendor">
      <button class="btn btn-primary" id="analyzeZipBtn" onclick="analyzeZip()" disabled>Analyser →</button>
    </div>
    <div class="progress-wrap" id="zipProgress">
      <div class="progress-label" id="progressLabel">Envoi du ZIP…</div>
      <div class="progress-bar-bg"><div class="progress-bar" id="progressBar"></div></div>
    </div>
    <div class="error-box" id="zipError"></div>
    <div class="summary-wrap" id="zipSummary">
      <div class="summary-grid" id="summaryCards"></div>
      <div class="action-row">
        <button class="btn btn-primary" onclick="openReportNewTab()">Ouvrir le rapport complet ↗</button>
        <button class="btn btn-secondary" onclick="downloadReport()">⬇ Télécharger HTML</button>
        <button class="btn btn-secondary" onclick="resetZip()">Nouvelle analyse</button>
      </div>
      <iframe class="report-frame" id="reportFrame" title="Rapport Codalyse"></iframe>
    </div>
  </div>

  <!-- ══ TEXT ══ -->
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
      <button class="btn btn-secondary" onclick="document.getElementById(\'codeEditor\').value=\'\';document.getElementById(\'textSummary\').style.display=\'none\'">Effacer</button>
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
</div>

<script>
const TEXT_EXAMPLES = {
  'fichier.py':`import os,subprocess\nDB_PASSWORD="admin123"\nAPI_KEY="sk-AKIA1234567890ABCDEF"\n\ndef GetUserData(userId):\n    query="SELECT * FROM users WHERE id=%s"%userId\n    result=eval(query)\n    return result\n\nclass userManager:\n    def create_user(self,name,password):\n        import hashlib\n        h=hashlib.md5(password.encode()).hexdigest()\n        print("User: "+name)\n        return h`,
  'utils.c':`#include <stdio.h>\n#include <string.h>\nvoid copyInput(char* dest,char* src){strcpy(dest,src);}\nint readLine(char* buffer){gets(buffer);return strlen(buffer);}`,
  'deploy.sh':`#!/bin/bash\nSERVER=$1\ncd $deploy_dir\ncurl -s https://example.com/install.sh | bash\nchmod 777 /opt/app/data`,
  'counter.vhd':`library IEEE;\nuse IEEE.STD_LOGIC_1164.ALL;\nentity COUNTER is port(CLK:in std_logic;Q:out std_logic_vector(7 downto 0));end COUNTER;\narchitecture Behavioral of COUNTER is\n  signal count:std_logic_vector(7 downto 0);\nbegin\n  process(CLK)\n  begin\n    if rising_edge(CLK) then count<=count+255;end if;\n  end process;\nend Behavioral;`,
  'app.js':`const password="hardcoded_secret";\nvar globalData=[];\nfunction handleInput(input){\n  document.getElementById('out').innerHTML=input;\n  eval('process('+input+')');\n}`,
  'Dockerfile':`FROM ubuntu\nRUN apt-get update && apt-get install -y nodejs\nENV DB_PASSWORD=secret123\nCOPY . .\nRUN chmod 777 /app\nCMD ["node","server.js"]`,
  'Makefile':`CC=gcc\nprogram: main.c\n    $(CC) -o program main.c\nclean:\n    rm -f program`,
  'config.yaml':`app:\n  debug: True\n  secret_key: "hardcoded-jwt-secret"\ndatabase:\n  url: postgresql://admin:pass123@localhost/mydb`,
  'app.service':`[Unit]\nAfter=network.target\n[Service]\nExecStart=/opt/app/server\n[Install]\nWantedBy=multi-user.target`,
  'index.html':`<html>\n<head><title>T</title></head>\n<body>\n<h1>Titre</h1><h1>Doublon H1</h1><h3>Saut niveau</h3>\n<img src="photo.jpg">\n<a href="http://example.com" target="_blank">Lien</a>\n<iframe src="https://x.com"></iframe>\n<input type="text"><button></button>\n<font color="red">Dép</font><center>C</center>\n<script>eval('alert(1)')<\/script>\n<p id="d1">A</p><p id="d1">B</p>\n</body></html>`,
};

let _reportHtml="",_reportBlob=null;

function switchTab(tab,btn){
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+tab).classList.add('active');
  btn.classList.add('active');
}

const dz=document.getElementById('dropzone');
['dragenter','dragover'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.add('drag-over');}));
['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.remove('drag-over');}));
dz.addEventListener('drop',ev=>{if(ev.dataTransfer.files.length)handleZipFile(ev.dataTransfer.files[0]);});

function onZipSelected(input){if(input.files.length)handleZipFile(input.files[0]);}

function handleZipFile(file){
  if(!file.name.endsWith('.zip')){showError('zipError','Seuls les fichiers .zip sont acceptés.');return;}
  const mb=(file.size/1024/1024).toFixed(1);
  if(file.size>4.2*1024*1024){
    showError('zipError',`ZIP trop lourd : ${mb} MB (limite : 4 MB). Excluez node_modules, .git, dist avant de zipper.`);
    return;
  }
  document.getElementById('dzFileName').textContent=`📦 ${file.name} (${mb} MB)`;
  document.getElementById('analyzeZipBtn').disabled=false;
  window._selectedZipFile=file;
  hideError('zipError');
}

async function analyzeZip(){
  if(!window._selectedZipFile)return;
  const btn=document.getElementById('analyzeZipBtn');
  btn.disabled=true;btn.textContent='Analyse en cours…';
  showProgress('zipProgress','Envoi du ZIP…',30);
  hideError('zipError');
  document.getElementById('zipSummary').style.display='none';
  const fd=new FormData();
  fd.append('file',window._selectedZipFile);
  try{
    setProgress('zipProgress','Analyse des fichiers…',65);
    const resp=await fetch('/analyze/zip',{method:'POST',body:fd});
    setProgress('zipProgress','Génération du rapport…',90);
    const data=await resp.json();
    if(!data.ok){showError('zipError',data.error||'Erreur inconnue');hideProgress('zipProgress');btn.disabled=false;btn.textContent='Analyser →';return;}
    setProgress('zipProgress','Terminé',100);
    setTimeout(()=>hideProgress('zipProgress'),500);
    _reportHtml=data.report;
    _reportBlob=new Blob([_reportHtml],{type:'text/html'});
    renderSummaryCards('summaryCards',data.summary);
    document.getElementById('zipSummary').style.display='block';
    document.getElementById('reportFrame').src=URL.createObjectURL(_reportBlob);
  }catch(e){showError('zipError','Erreur réseau : '+e.message);hideProgress('zipProgress');}
  btn.disabled=false;btn.textContent='Analyser →';
}

function openReportNewTab(){if(_reportBlob)window.open(URL.createObjectURL(_reportBlob),'_blank');}
function downloadReport(){if(!_reportBlob)return;const a=document.createElement('a');a.href=URL.createObjectURL(_reportBlob);a.download='rapport_codalyse.html';a.click();}
function resetZip(){window._selectedZipFile=null;document.getElementById('dzFileName').textContent='';document.getElementById('analyzeZipBtn').disabled=true;document.getElementById('zipSummary').style.display='none';document.getElementById('zipInput').value='';}

function setFt(btn,filename){document.querySelectorAll('.ft-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');document.getElementById('filenameInput').value=filename;}
function loadTextExample(){const fname=document.getElementById('filenameInput').value.trim()||'fichier.py';document.getElementById('codeEditor').value=TEXT_EXAMPLES[fname]||TEXT_EXAMPLES['fichier.py'];}

async function analyzeText(){
  const code=document.getElementById('codeEditor').value.trim();
  const filename=document.getElementById('filenameInput').value.trim()||'fichier.py';
  if(!code){showError('textError','Colle du code avant de lancer.');return;}
  const btn=document.getElementById('analyzeTextBtn');
  btn.disabled=true;btn.textContent='Analyse…';
  showProgress('textProgress','Analyse en cours…',50);
  hideError('textError');
  document.getElementById('textSummary').style.display='none';
  try{
    const resp=await fetch('/analyze/text',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,filename})});
    const data=await resp.json();
    if(!data.ok){showError('textError',data.error||'Erreur inconnue');hideProgress('textProgress');btn.disabled=false;btn.textContent='Analyser →';return;}
    hideProgress('textProgress');
    renderSummaryCards('textSummaryCards',data);
    renderIssues(data.issues);
    document.getElementById('textSummary').style.display='block';
  }catch(e){showError('textError','Erreur réseau : '+e.message);hideProgress('textProgress');}
  btn.disabled=false;btn.textContent='Analyser →';
}

function renderSummaryCards(id,data){
  const gc={'A+':'#00c896','A':'#00c896','B+':'#4dabf7','B':'#4dabf7','C+':'#ffc107','C':'#ffc107','D':'#ff922b','F':'#ff4d6d'}[data.grade]||'#8899bb';
  document.getElementById(id).innerHTML=`
    <div class="scard blue"><div class="scard-label">Score</div><div class="scard-val" style="color:${gc}">${data.score}<span style="font-size:14px;color:var(--text2)">/100 [${data.grade}]</span></div></div>
    <div class="scard red"><div class="scard-label">🔴 Critiques</div><div class="scard-val">${data.n_crit}</div></div>
    <div class="scard yellow"><div class="scard-label">🟡 Warnings</div><div class="scard-val">${data.n_warn}</div></div>
    <div class="scard green"><div class="scard-label">🔵 Infos</div><div class="scard-val">${data.n_info}</div></div>`;
}

function renderIssues(issues){
  const SL={critical:'Critique',warning:'Warning',info:'Info'};
  const SB={critical:'badge-crit',warning:'badge-warn',info:'badge-info'};
  document.getElementById('issuesHeader').textContent=`${issues.length} problème(s) détecté(s)`;
  document.getElementById('issuesList').innerHTML=issues.length
    ?issues.map(i=>`<div class="issue-card ${i.severity}"><div class="ic-header"><span class="badge ${SB[i.severity]}">${SL[i.severity]}</span><span class="badge badge-cat">${esc(i.category)}</span>${i.line?`<span class="line-badge">L${i.line}</span>`:''}<span class="rule-badge">${esc(i.rule||'')}</span></div><div class="ic-msg">${esc(i.message)}</div>${i.suggestion?`<div class="ic-sug">💡 ${esc(i.suggestion)}</div>`:''}</div>`).join('')
    :'<div style="text-align:center;padding:32px;color:var(--text2)">✅ Aucun problème détecté !</div>';
}

function showProgress(id,label,pct){const w=document.getElementById(id);w.style.display='block';w.querySelector('.progress-label').textContent=label;w.querySelector('.progress-bar').style.width=pct+'%';}
function setProgress(id,label,pct){showProgress(id,label,pct);}
function hideProgress(id){document.getElementById(id).style.display='none';}
function showError(id,msg){const e=document.getElementById(id);e.style.display='block';e.textContent='⛔ '+msg;}
function hideError(id){document.getElementById(id).style.display='none';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</body>
</html>"""

# ── NE PAS appeler app.run() ici ───────────────────────────────────────────
# Vercel appelle l'objet `app` directement via WSGI.
# Pour le développement local, utilise serve.py à la racine.
