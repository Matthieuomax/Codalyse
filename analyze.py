#!/usr/bin/env python3
"""
Codalyse — Analyseur de qualité de code multi-fichiers
Usage: python analyze.py [PROJECT_PATH] [--output rapport.html] [--ignore dir1,dir2]
"""

import sys
import argparse
import time
from pathlib import Path
from typing import List

# Ensure local imports work regardless of cwd
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import ProjectScanner
from core.issue import Issue, Severity, compute_score
from analyzers.python_analyzer   import PythonAnalyzer
from analyzers.c_cpp_analyzer     import CCppAnalyzer
from analyzers.shell_analyzer     import ShellAnalyzer
from analyzers.systemd_analyzer   import SystemdAnalyzer
from analyzers.desktop_analyzer   import DesktopAnalyzer
from analyzers.vhdl_analyzer      import VHDLAnalyzer
from analyzers.data_analyzer      import DataAnalyzer
from analyzers.markdown_analyzer  import MarkdownAnalyzer
from analyzers.security_analyzer  import SecurityAnalyzer
from analyzers.js_ts_analyzer       import JsTsAnalyzer
from analyzers.dockerfile_analyzer  import DockerfileAnalyzer
from analyzers.makefile_analyzer    import MakefileAnalyzer
from analyzers.html_analyzer        import HtmlAnalyzer
from analyzers.architecture_analyzer import ArchitectureAnalyzer
from report.html_report           import HTMLReport


ANSI = {
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "green":  "\033[92m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}

def c(text, *colors):
    code = "".join(ANSI.get(col, "") for col in colors)
    return f"{code}{text}{ANSI['reset']}"


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
    SecurityAnalyzer(),   # Must be last (scans everything)
]


def banner():
    print()
    print(c("╔══════════════════════════════════════════════════════╗", "cyan"))
    print(c("║", "cyan") + c("         ◆  CODALYSE — Code Analyzer v2.0  ◆        ", "bold") + c("  ║", "cyan"))
    print(c("║", "cyan") + c("   Sécurité · Qualité · Architecture · Conventions  ", "dim")  + c("  ║", "cyan"))
    print(c("╚══════════════════════════════════════════════════════╝", "cyan"))
    print()


def print_progress(current, total, filepath):
    pct  = int(current / total * 30)
    bar  = "█" * pct + "░" * (30 - pct)
    name = Path(filepath).name[:40].ljust(40)
    print(f"\r  {c(bar, 'cyan')}  {c(f'{current}/{total}', 'dim')}  {name}", end="", flush=True)





def _print_summary(issues, n_files, n_crit, n_warn, n_info, score, grade, elapsed):
    grade_color = {
        "A+": "green", "A": "green",
        "B+": "cyan",  "B": "cyan",
        "C+": "yellow","C": "yellow",
        "D":  "yellow","F": "red",
    }.get(grade, "dim")

    total = len(issues)
    print()
    print(c("  ─────────────────────────────────────────────────", "dim"))
    print(c("  RÉSULTATS D'ANALYSE", "bold"))
    print(c("  ─────────────────────────────────────────────────", "dim"))
    print(f"  Fichiers analysés  :  {c(str(n_files), 'cyan', 'bold')}")
    print(f"  Problèmes total    :  {c(str(total), 'bold')}")
    print(f"  🔴 Critiques       :  {c(str(n_crit), 'red', 'bold')}")
    print(f"  🟡 Avertissements  :  {c(str(n_warn), 'yellow')}")
    print(f"  🔵 Infos           :  {c(str(n_info), 'blue')}")
    print(f"  Score              :  {c(f'{score}/100  [{grade}]', grade_color, 'bold')}")
    print(f"  Durée              :  {c(f'{elapsed:.2f}s', 'dim')}")
    print(c("  ─────────────────────────────────────────────────", "dim"))

    # Top 5 most problematic files
    from collections import Counter
    file_counts = Counter(i.file for i in issues)
    top5 = file_counts.most_common(5)
    if top5:
        print(c("\n  Top fichiers problématiques :", "bold"))
        for filepath, count in top5:
            crit_n = sum(1 for i in issues if i.file == filepath and i.severity == Severity.CRITICAL)
            warn_n = sum(1 for i in issues if i.file == filepath and i.severity == Severity.WARNING)
            badges = ""
            if crit_n: badges += f" {c(f'{crit_n}🔴', 'red')}"
            if warn_n: badges += f" {c(f'{warn_n}🟡', 'yellow')}"
            print(f"    {c(filepath, 'cyan')} — {count} problèmes{badges}")

    # Critical issues preview
    crits = [i for i in issues if i.severity == Severity.CRITICAL][:5]
    if crits:
        print(c("\n  ⛔ Problèmes critiques :", "red", "bold"))
        for issue in crits:
            loc = f"L{issue.line}" if issue.line else "—"
            print(f"    {c(issue.file, 'cyan')}:{c(loc, 'dim')}  {c(issue.message, 'red')}")
            if issue.suggestion:
                print(f"    {c('💡 ' + issue.suggestion, 'dim')}")
        if n_crit > 5:
            print(f"    {c(f'… et {n_crit - 5} autres critiques dans le rapport HTML.', 'dim')}")


def run_analysis(root, output, ignore, fmt="html", quiet=False):
    from core.issue import Category as Cat
    import json as _json
    import datetime

    if not quiet:
        banner()
        print(c(f"  📁 Projet : {root}", "bold"))
        print(c(f"  📂 Scan des fichiers…", "dim"))
    t0 = time.time()

    scanner = ProjectScanner(root, ignore)
    files   = scanner.scan()
    n_files = len(files)

    if n_files == 0:
        print(c("\n  ❌ Aucun fichier trouvé ! Vérifiez le chemin.", "red"))
        return 1

    if not quiet:
        print(c(f"  ✅ {n_files} fichiers trouvés\n", "green"))
        print(c("  🔎 Analyse des fichiers…", "bold"))

    all_issues = []
    for idx, (filepath, content) in enumerate(files.items(), 1):
        if not quiet:
            print_progress(idx, n_files, filepath)
        for analyzer in FILE_ANALYZERS:
            try:
                if analyzer.can_analyze(filepath):
                    all_issues.extend(analyzer.analyze(filepath, content))
            except Exception as ex:
                all_issues.append(Issue(
                    file=filepath, line=None, severity=Severity.WARNING,
                    category=Cat.RELIABILITY,
                    message=f"[Erreur interne] {type(ex).__name__}: {ex}",
                    suggestion="Signalez ce bug.", rule="INT-ERR"))

    if not quiet:
        print()

    arch = ArchitectureAnalyzer(root)
    try:
        all_issues.extend(arch.analyze_project(files))
    except Exception:
        pass

    t_elapsed = time.time() - t0
    n_crit = sum(1 for i in all_issues if i.severity == Severity.CRITICAL)
    n_warn = sum(1 for i in all_issues if i.severity == Severity.WARNING)
    n_info = sum(1 for i in all_issues if i.severity == Severity.INFO)
    score, grade = compute_score(all_issues)

    if not quiet:
        _print_summary(all_issues, n_files, n_crit, n_warn, n_info, score, grade, t_elapsed)

    if fmt in ("html", "both"):
        if not quiet:
            print(c(f"\n  📄 Génération du rapport HTML…", "dim"))
        report = HTMLReport(root, files, all_issues)
        html_out = output if fmt == "html" else output.with_suffix(".html")
        report.generate(html_out)
        if not quiet:
            print(c(f"  ✅ Rapport HTML : {html_out}", "green", "bold"))

    if fmt in ("json", "both"):
        json_out = output if fmt == "json" else output.with_suffix(".json")
        payload = {
            "project": str(root),
            "generated": datetime.datetime.now().isoformat(),
            "score": score, "grade": grade,
            "stats": {"files": n_files, "total": len(all_issues),
                      "critical": n_crit, "warning": n_warn, "info": n_info},
            "issues": [i.to_dict() for i in all_issues],
        }
        json_out.write_text(_json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if not quiet:
            print(c(f"  ✅ Rapport JSON : {json_out}", "green", "bold"))

    if not quiet:
        print()

    return 0 if n_crit == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="Codalyse — Analyseur de qualité de code multi-fichiers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python analyze.py .
  python analyze.py /mon/projet --output rapport.html
  python analyze.py ~/projet --ignore dist,build,vendor --format json
  python analyze.py . --format both --quiet
        """
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Chemin du projet à analyser (défaut : répertoire courant)"
    )
    parser.add_argument(
        "--output", "-o",
        default="rapport_analyse.html",
        help="Fichier de sortie (défaut : rapport_analyse.html)"
    )
    parser.add_argument(
        "--ignore", "-i",
        default="",
        help="Dossiers à ignorer, séparés par des virgules (ex: dist,build)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "json", "both"],
        default="html",
        help="Format de sortie : html (défaut), json, ou both"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Mode silencieux — pas de sortie console (utile pour CI/CD)"
    )

    args = parser.parse_args()

    root   = Path(args.path).resolve()
    # Auto-adjust default output extension for JSON
    output_default = args.output
    if args.format == "json" and output_default == "rapport_analyse.html":
        output_default = "rapport_analyse.json"
    output = Path(output_default).resolve()
    ignore = [x.strip() for x in args.ignore.split(",") if x.strip()]

    if not root.exists():
        print(c(f"\n  ❌ Chemin introuvable : {root}", "red"))
        sys.exit(1)

    if not root.is_dir():
        print(c(f"\n  ❌ Ce n'est pas un dossier : {root}", "red"))
        sys.exit(1)

    exit_code = run_analysis(root, output, ignore, fmt=args.format, quiet=args.quiet)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

