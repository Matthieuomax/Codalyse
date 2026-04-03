# Codalyse

**Analyseur de qualité de code multi-fichiers** — génère un rapport HTML interactif avec score, grade et suggestions de correction.

> Code + Analyse = Codalyse

## Installation

```bash
pip install pyyaml         # Analyse YAML (requis)
pip install flask          # Interface web drag & drop (optionnel)
```

Python **3.9+** requis. Aucune autre dépendance.

## Utilisation

### CLI — Rapport HTML

```bash
# Analyser le répertoire courant
python analyze.py .

# Analyser un projet spécifique
python analyze.py /chemin/vers/projet --output rapport.html

# Sortie JSON (CI/CD, scripts)
python analyze.py . --format json

# Les deux formats simultanément
python analyze.py . --format both

# Mode silencieux (exit code 0=ok, 1=critiques)
python analyze.py . --quiet --format json

# Ignorer des dossiers
python analyze.py . --ignore dist,build,node_modules,vendor
```

### Interface web — Drag & Drop

```bash
python serve.py
# Ouvre http://localhost:5000
```

Dépose un `.zip` de ton projet dans le navigateur → rapport HTML complet généré en quelques secondes.

## Types de fichiers analysés (14 analyseurs)

| Type | Extensions | Règles clés |
|------|-----------|-------------|
| Python | `.py` | AST, PEP8, sécurité (eval, pickle, subprocess), docstrings |
| C / C++ | `.c` `.h` `.cpp` `.hpp` | gets(), strcpy, malloc, include guards, naming |
| Shell | `.sh` `.bash` `.zsh` | set -euo pipefail, quoting, curl\|bash, chmod 777 |
| Systemd | `.service` `.timer` `.socket` | User=, PrivateTmp, NoNewPrivileges, Restart= |
| Desktop | `.desktop` | Freedesktop spec, champs requis/recommandés |
| VHDL | `.vhd` `.vhdl` | IEEE, process labels, signal naming |
| JavaScript/TS | `.js` `.ts` `.jsx` `.tsx` | var, ==, innerHTML, eval, any, XSS |
| HTML | `.html` `.htm` | Accessibilité, SEO, sécurité, balises dépréciées |
| Dockerfile | `Dockerfile` | FROM:latest, USER root, secrets ENV, layers |
| Makefile | `Makefile` `.mk` | .PHONY, tabs, all/clean/help, CC= |
| YAML/JSON | `.yaml` `.yml` `.json` | Syntaxe, secrets, profondeur, debug=true |
| INI/TOML | `.ini` `.cfg` `.conf` `.toml` | Syntaxe, format clé=valeur |
| Markdown | `.md` `.rst` | Titres H1, blocs de code, TODO |
| Sécurité | tous | Clés AWS/GitHub, JWT, passwords, SSL verify=False |
| Architecture | projet | README, .gitignore, requirements.txt, naming mixte |

## Score et grade

| Score | Grade | Signification |
|-------|-------|---------------|
| 95–100 | A+ | Code exemplaire |
| 90–94  | A  | Très bon |
| 85–89  | B+ | Bon+ |
| 80–84  | B  | Bon |
| 75–79  | C+ | Correct+ |
| 70–74  | C  | Correct |
| 60–69  | D  | Insuffisant |
| 0–59   | F  | Critique |

Formule (plafonnée par catégorie) :
```
score = 100 − min(critiques × 15, 60) − min(warnings × 3, 25) − min(infos × 0.3, 10)
```

## Structure du projet

```
codalyse/
├── analyze.py                    ← CLI
├── serve.py                      ← Serveur web Flask
├── requirements.txt
├── README.md
├── core/
│   ├── issue.py                  ← Issue, Score, Grade
│   └── scanner.py                ← Détection des fichiers
├── analyzers/                    ← 14 analyseurs
│   ├── python_analyzer.py
│   ├── c_cpp_analyzer.py
│   ├── shell_analyzer.py
│   ├── systemd_analyzer.py
│   ├── desktop_analyzer.py
│   ├── vhdl_analyzer.py
│   ├── html_analyzer.py
│   ├── data_analyzer.py
│   ├── markdown_analyzer.py
│   ├── js_ts_analyzer.py
│   ├── dockerfile_analyzer.py
│   ├── makefile_analyzer.py
│   ├── security_analyzer.py
│   └── architecture_analyzer.py
└── report/
    └── html_report.py            ← Dashboard HTML interactif
```
