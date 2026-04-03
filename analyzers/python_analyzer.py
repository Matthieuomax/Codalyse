import ast
import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class PythonAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".py"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues: List[Issue] = []
        lines = content.splitlines()

        issues += self._check_ast(filepath, content)
        issues += self._check_style(filepath, lines)
        issues += self._check_naming_lines(filepath, lines)
        issues += self._check_imports(filepath, lines)
        return issues

    # ──────────────────────────── AST analysis ────────────────────────────

    def _check_ast(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError as e:
            issues.append(self._make_issue(
                filepath, e.lineno, Severity.CRITICAL, Category.SYNTAX,
                f"Erreur de syntaxe Python : {e.msg}",
                "Corrigez l'erreur de syntaxe avant toute chose.", "PY-SYN-001"))
            return issues

        issues += self._visit_functions(filepath, tree)
        issues += self._visit_classes(filepath, tree)
        issues += self._visit_calls(filepath, tree)
        issues += self._check_module_docstring(filepath, tree)
        return issues

    def _visit_functions(self, filepath, tree):
        issues = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name

            # Naming: must be snake_case (allow __ dunder __)
            if not re.match(r'^_{0,2}[a-z][a-z0-9_]*_{0,2}$', name):
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.WARNING, Category.NAMING,
                    f"Fonction '{name}' n'est pas en snake_case.",
                    f"Renommez en '{self._to_snake(name)}'.", "PY-NAM-001"))

            # Missing docstring
            if not (node.body and isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, ast.Constant)):
                if not name.startswith("__"):
                    issues.append(self._make_issue(
                        filepath, node.lineno, Severity.INFO, Category.DOCUMENTATION,
                        f"Fonction '{name}' sans docstring.",
                        "Ajoutez un docstring décrivant le but, les paramètres et le retour.", "PY-DOC-001"))

            # Too long (>60 lines)
            end = getattr(node, "end_lineno", node.lineno)
            length = end - node.lineno
            if length > 60:
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.WARNING, Category.COMPLEXITY,
                    f"Fonction '{name}' trop longue : {length} lignes (max recommandé : 60).",
                    "Découpez en sous-fonctions.", "PY-CPLX-001"))

            # Mutable default arguments
            for default in node.args.defaults + node.args.kw_defaults:
                if default and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    issues.append(self._make_issue(
                        filepath, node.lineno, Severity.WARNING, Category.RELIABILITY,
                        f"Argument mutable par défaut dans '{name}' ([], {{}}, set()).",
                        "Utilisez None comme défaut et initialisez dans le corps.", "PY-REL-001"))
                    break

        return issues

    def _visit_classes(self, filepath, tree):
        issues = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            name = node.name
            if not re.match(r'^[A-Z][a-zA-Z0-9]*$', name):
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.WARNING, Category.NAMING,
                    f"Classe '{name}' n'est pas en PascalCase.",
                    f"Renommez en '{self._to_pascal(name)}'.", "PY-NAM-002"))

            if not (node.body and isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, ast.Constant)):
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.INFO, Category.DOCUMENTATION,
                    f"Classe '{name}' sans docstring.",
                    "Ajoutez un docstring de classe.", "PY-DOC-002"))
        return issues

    def _visit_calls(self, filepath, tree):
        issues = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func

            fname = None
            if isinstance(func, ast.Name):
                fname = func.id
            elif isinstance(func, ast.Attribute):
                fname = func.attr

            if fname == "eval":
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.CRITICAL, Category.SECURITY,
                    "Utilisation de eval() — risque d'exécution de code arbitraire.",
                    "Évitez eval(). Utilisez ast.literal_eval() pour des données.", "PY-SEC-001"))

            elif fname == "exec":
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.CRITICAL, Category.SECURITY,
                    "Utilisation de exec() — risque de sécurité majeur.",
                    "Refactorisez pour éviter exec().", "PY-SEC-002"))

            elif fname in ("system",) and isinstance(func, ast.Attribute):
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.WARNING, Category.SECURITY,
                    "os.system() détecté — préférez subprocess.",
                    "Utilisez subprocess.run() avec shell=False.", "PY-SEC-003"))

            # subprocess shell=True
            elif fname in ("run", "call", "Popen", "check_output", "check_call"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        issues.append(self._make_issue(
                            filepath, node.lineno, Severity.WARNING, Category.SECURITY,
                            f"subprocess.{fname}() avec shell=True — injection possible.",
                            "Passez une liste d'arguments et shell=False.", "PY-SEC-004"))

            # pickle.loads
            elif fname == "loads" and isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name) and func.value.id == "pickle":
                    issues.append(self._make_issue(
                        filepath, node.lineno, Severity.CRITICAL, Category.SECURITY,
                        "pickle.loads() sur des données non fiables — RCE possible.",
                        "N'utilisez jamais pickle sur des données externes.", "PY-SEC-005"))

            # Weak hash functions for passwords (md5/sha1)
            elif fname in ("md5", "sha1", "sha") and isinstance(func, ast.Attribute):
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.WARNING, Category.SECURITY,
                    f"Algorithme de hachage faible : {fname}().",
                    "Utilisez bcrypt, argon2 ou sha256+ pour les mots de passe.", "PY-SEC-006"))

            # print() calls (info only)
            elif fname == "print" and isinstance(func, ast.Name):
                issues.append(self._make_issue(
                    filepath, node.lineno, Severity.INFO, Category.STYLE,
                    "print() détecté — pensez à utiliser le module logging.",
                    "Remplacez par logging.debug() / logging.info().", "PY-STYL-001"))

        return issues

    def _check_module_docstring(self, filepath, tree):
        issues = []
        if not (tree.body and isinstance(tree.body[0], ast.Expr) and
                isinstance(tree.body[0].value, ast.Constant) and
                isinstance(tree.body[0].value.value, str)):
            issues.append(self._make_issue(
                filepath, 1, Severity.INFO, Category.DOCUMENTATION,
                "Module sans docstring.",
                "Ajoutez un docstring en tête de fichier décrivant le module.", "PY-DOC-003"))
        return issues

    # ──────────────────────────── Line-based style ─────────────────────────

    def _check_style(self, filepath, lines):
        issues = []
        for i, line in enumerate(lines, 1):
            stripped = line.rstrip("\n")

            # Line too long (>120)
            if len(stripped) > 120:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    f"Ligne trop longue : {len(stripped)} caractères (PEP8 recommande ≤ 79, max 120).",
                    "Découpez la ligne.", "PY-STYL-002"))

            # Trailing whitespace
            if stripped != stripped.rstrip():
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "Espace(s) en fin de ligne.",
                    "Supprimez les espaces de fin.", "PY-STYL-003"))

            # Bare except
            if re.match(r'^\s*except\s*:', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.RELIABILITY,
                    "Clause 'except:' nue — capture toutes les exceptions.",
                    "Spécifiez le type : 'except Exception as e:'.", "PY-REL-002"))

            # TODO/FIXME/HACK/XXX
            m = re.search(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', stripped, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                    f"Commentaire '{m.group(1)}' non résolu.",
                    "Tracez dans un issue tracker et résolvez ou supprimez.", "PY-MAINT-001"))

            # Magic numbers (heuristic: bare integer literal not 0/1/-1 in expression)
            if re.search(r'(?<!["\'\w.])(?<!def )(?<!\[)\b([2-9]\d{2,}|\d{4,})\b(?!\s*[=\]])', stripped):
                if not stripped.strip().startswith("#"):
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                        "Nombre magique détecté.",
                        "Définissez une constante nommée en majuscules.", "PY-MAINT-002"))

        return issues

    def _check_naming_lines(self, filepath, lines):
        """Check UPPER_CASE for constants at module level (basic heuristic)."""
        issues = []
        const_pattern = re.compile(r'^([a-z_][a-z0-9_]*)\s*=\s*["\'\d\[\{(True|False|None]')
        for i, line in enumerate(lines, 1):
            if const_pattern.match(line.strip()):
                name = const_pattern.match(line.strip()).group(1)
                if name.startswith("_") or len(name) <= 2:
                    continue
                # This is a heuristic – not flagging inside functions
                # Skip – too many false positives at module level
        return issues

    def _check_imports(self, filepath, lines):
        issues = []
        in_imports = False
        last_import_line = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                in_imports = True
                last_import_line = i
                if re.match(r'^import\s+\S+,', stripped):
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.STYLE,
                        "Imports multiples sur une ligne.",
                        "Un import par ligne (PEP8).", "PY-IMP-001"))
            elif stripped and in_imports and not stripped.startswith("#"):
                if last_import_line and i - last_import_line > 3:
                    in_imports = False

        return issues

    # ──────────────────────────── Helpers ──────────────────────────────────

    @staticmethod
    def _to_snake(name: str) -> str:
        s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
        s = re.sub(r'([a-z\d])([A-Z])', r'\1_\2', s)
        return s.lower()

    @staticmethod
    def _to_pascal(name: str) -> str:
        return "".join(w.capitalize() for w in name.split("_"))
