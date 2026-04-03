import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category

# ─────────────────────────────────────────────────────────────────────────────
# RÈGLES : chaque tuple = (pattern, message, suggestion, rule_id)
# Le pattern est testé sur chaque ligne (pas multiline).
# On teste d'abord si la ligne est dans un commentaire avant d'appliquer.
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # Mot de passe explicitement assigné à une valeur non-vide non-variable
    # Exclut : password = "" / password = None / password = os.environ / password = config[...]
    # Exclut : les champs de formulaire HTML type="password"
    (
        r'(?i)\b(password|passwd|db_pass|db_password|secret_key|auth_secret)\s*=\s*'
        r'["\'](?!<|{{|\$\{|\$\(|%|your_|changeme|xxx|placeholder|example|test|demo|dummy|todo|\s*$)[^\s"\']{5,}["\']',
        "Mot de passe potentiellement codé en dur.",
        "Utilisez une variable d'environnement : os.environ['DB_PASSWORD']",
        "SEC-CRED-001"
    ),
    # Clé AWS Access Key ID (format très spécifique → peu de faux positifs)
    (
        r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
        "Clé AWS Access Key ID détectée — révocation immédiate requise.",
        "Révoquez sur AWS IAM et utilisez les rôles IAM ou AWS Secrets Manager.",
        "SEC-CRED-002"
    ),
    # Tokens GitHub/GitLab (patterns très spécifiques)
    (
        r'(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9_\-]{20,})',
        "Token GitHub/GitLab détecté.",
        "Révoquez ce token immédiatement depuis les paramètres du compte.",
        "SEC-CRED-003"
    ),
    # Clé privée RSA/SSH
    (
        r'-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----',
        "Clé privée dans le code source — danger critique.",
        "Ne committez JAMAIS de clés privées. Ajoutez *.pem, *.key à .gitignore.",
        "SEC-CRED-004"
    ),
    # Clé API Google
    (
        r'AIza[0-9A-Za-z\-_]{35}',
        "Clé API Google détectée.",
        "Révoquez depuis Google Cloud Console et stockez dans une variable d'env.",
        "SEC-CRED-005"
    ),
    # Token Slack
    (
        r'xox[baprs]-[0-9A-Za-z\-]{10,48}',
        "Token Slack détecté.",
        "Révoquez depuis votre workspace Slack.",
        "SEC-CRED-006"
    ),
    # Chaîne de connexion BDD avec credentials dans l'URL
    # Exclut : les URLs sans mot de passe (user@host) et les exemples
    (
        r'(?i)(mysql|postgresql|postgres|mongodb|redis)\+?\w*://[^:@\s]{1,40}:[^@\s"\']{4,}@(?!localhost:?/(test|dev|example))',
        "Chaîne de connexion BDD avec credentials intégrés.",
        "Externalisez dans DATABASE_URL=... dans .env (jamais dans le code).",
        "SEC-CRED-007"
    ),
    # JWT secret codé en dur (pattern précis : clé nommée + valeur longue non-variable)
    (
        r'(?i)(jwt_secret|jwt_key|jwt[_\-]?signing[_\-]?key)\s*=\s*["\'][a-zA-Z0-9_\-\.]{12,}["\']',
        "Secret JWT codé en dur.",
        "Stockez dans JWT_SECRET=... dans les variables d'environnement.",
        "SEC-CRED-008"
    ),
]

INSECURE_LINE_PATTERNS = [
    # SSL/TLS désactivé — très peu de faux positifs
    (
        r'\bverify\s*=\s*False\b',
        "Vérification SSL/TLS désactivée (verify=False).",
        "Ne désactivez jamais la vérification SSL en production.",
        "SEC-TLS-001",
        Severity.CRITICAL
    ),
    # Mode debug activé (Python/Django settings)
    # Exclut les fichiers de test et les commentaires
    (
        r'(?i)^(?!.*#.*DEBUG)\s*DEBUG\s*=\s*True\b',
        "Mode DEBUG activé — ne jamais utiliser en production.",
        "Passez DEBUG à False en production, idéalement via variable d'env.",
        "SEC-CFG-001",
        Severity.WARNING
    ),
    # eval() dans du code (pas dans les commentaires)
    (
        r'\beval\s*\(',
        "eval() détecté — exécution de code arbitraire possible.",
        "Évitez eval(). Alternatives : ast.literal_eval(), json.loads(), dict/map.",
        "SEC-CODE-001",
        Severity.CRITICAL
    ),
    # chmod 777
    (
        r'\bchmod\s+(777|a\+rwx|ugo\+rwx)\b',
        "Permissions 777 (monde-accessible en écriture).",
        "Appliquez le moindre privilège : 755 pour les exécutables, 644 pour les fichiers.",
        "SEC-PERM-001",
        Severity.WARNING
    ),
    # curl | bash / wget | bash
    (
        r'\b(curl|wget)\b[^|#\n]{0,80}\|\s*(ba)?sh\b',
        "Exécution de script distant sans vérification (curl|bash).",
        "Téléchargez d'abord, vérifiez le hash, puis exécutez séparément.",
        "SEC-NET-001",
        Severity.CRITICAL
    ),
    # HTTP non-HTTPS sur des URLs contenant des chemins d'API (pas localhost)
    (
        r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|example\.com|test\.)[a-zA-Z0-9]',
        "URL HTTP non chiffrée (pas HTTPS).",
        "Utilisez HTTPS pour toutes les communications réseau.",
        "SEC-NET-002",
        Severity.WARNING
    ),
    # pickle.loads sur variable (risque RCE si données non fiables)
    (
        r'\bpickle\.loads?\s*\(',
        "pickle.load(s)() — risque d'exécution de code si les données sont non fiables.",
        "N'utilisez jamais pickle sur des données venant d'un réseau ou utilisateur.",
        "SEC-CODE-002",
        Severity.WARNING
    ),
    # subprocess shell=True avec variable (injection possible)
    (
        r'\bsubprocess\.\w+\([^)]*shell\s*=\s*True',
        "subprocess avec shell=True — injection de commande possible.",
        "Passez une liste d'arguments et shell=False.",
        "SEC-CODE-003",
        Severity.WARNING
    ),
]

# Extensions binaires ou non-texte à ne pas analyser
SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".so", ".o", ".a", ".dll", ".exe", ".bin", ".elf",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".wav",
    ".db", ".sqlite", ".sqlite3",
}

# Fichiers à analyser avec prudence réduite (tests, fixtures, exemples)
TEST_PATH_MARKERS = {
    "test", "tests", "spec", "specs", "fixture", "fixtures",
    "example", "examples", "demo", "sample", "mock", "mocks",
    "fake", "stub", "dummy",
}


def _is_test_file(filepath: str) -> bool:
    """Détermine si le fichier est un fichier de test/exemple (moins strict)."""
    parts = filepath.lower().replace("\\", "/").split("/")
    fname = parts[-1]
    for marker in TEST_PATH_MARKERS:
        if marker in parts or fname.startswith("test_") or fname.startswith("spec_"):
            return True
    return False


def _strip_comment(line: str, ext: str) -> str:
    """Retourne la partie non-commentaire d'une ligne."""
    # Pour les langages avec # comme commentaire
    if ext in ("py", "sh", "bash", "zsh", "yaml", "yml", "toml",
               "conf", "cfg", "ini", "service", "timer", "socket",
               "desktop", "rb", "r"):
        idx = line.find("#")
        if idx >= 0:
            # Évite de couper à l'intérieur d'une string
            in_str = False
            str_char = None
            for i, ch in enumerate(line):
                if not in_str and ch in ('"', "'"):
                    in_str = True
                    str_char = ch
                elif in_str and ch == str_char and (i == 0 or line[i-1] != "\\"):
                    in_str = False
                elif not in_str and ch == "#":
                    return line[:i]
        return line

    # Pour les langages avec // comme commentaire
    if ext in ("c", "h", "cpp", "hpp", "cc", "cxx", "js", "ts",
               "jsx", "tsx", "java", "cs", "go", "swift", "kt",
               "vhd", "vhdl"):
        idx = line.find("//")
        if idx >= 0:
            # Vérification grossière qu'on n'est pas dans une string
            before = line[:idx]
            if before.count('"') % 2 == 0 and before.count("'") % 2 == 0:
                return before
        return line

    return line


class SecurityAnalyzer(BaseAnalyzer):
    EXTENSIONS = set()  # Gère tous les fichiers via can_analyze()

    def can_analyze(self, filepath: str) -> bool:
        from pathlib import Path
        ext = Path(filepath).suffix.lower()
        return ext not in SKIP_EXTENSIONS

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues: List[Issue] = []
        from pathlib import Path
        ext = Path(filepath).suffix.lower().lstrip(".")
        is_test = _is_test_file(filepath)
        lines = content.splitlines()

        for i, raw_line in enumerate(lines, 1):
            line = _strip_comment(raw_line, ext)

            # ── Patterns de secrets ──────────────────────────────────
            for pattern, message, suggestion, rule in SECRET_PATTERNS:
                # En fichier de test, on passe les secrets en WARNING au lieu de CRITICAL
                m = re.search(pattern, line)
                if m:
                    sev = Severity.WARNING if is_test else Severity.CRITICAL
                    issues.append(self._make_issue(
                        filepath, i, sev, Category.SECURITY,
                        message, suggestion, rule))
                    break  # Une seule issue de secret par ligne

            # ── Patterns de mauvaises pratiques ─────────────────────
            for pattern, message, suggestion, rule, base_sev in INSECURE_LINE_PATTERNS:
                # eval() : toujours critique sauf dans les tests
                # Les autres : downgrade d'un niveau en contexte de test
                m = re.search(pattern, line)
                if m:
                    if is_test:
                        sev = Severity.INFO if base_sev == Severity.WARNING else Severity.WARNING
                    else:
                        sev = base_sev
                    issues.append(self._make_issue(
                        filepath, i, sev, Category.SECURITY,
                        message, suggestion, rule))

        return issues
