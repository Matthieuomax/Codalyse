import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class JsTsAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        lines = content.splitlines()
        is_ts = filepath.endswith((".ts", ".tsx"))

        issues += self._check_style(filepath, lines)
        issues += self._check_security(filepath, lines)
        issues += self._check_quality(filepath, lines, is_ts)
        issues += self._check_naming(filepath, content)
        return issues

    def _check_style(self, filepath, lines):
        issues = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            # Line too long
            if len(line.rstrip()) > 120:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    f"Ligne trop longue : {len(line.rstrip())} caractères.",
                    "Limitez à 100-120 caractères.", "JS-STYL-001"))

            # var usage (prefer let/const)
            if re.match(r'^\s*var\s+', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.STYLE,
                    "'var' utilisé — portée imprévisible (function scope).",
                    "Utilisez 'const' (défaut) ou 'let' (si réassigné).", "JS-STYL-002"))

            # == instead of ===
            if re.search(r'(?<![=!<>])={2}(?!=)', stripped) and not re.search(r'=>{2}', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.RELIABILITY,
                    "Comparaison == (égalité laxiste) — risque de coercition de type.",
                    "Utilisez === (égalité stricte).", "JS-REL-001"))

            # != instead of !==
            if re.search(r'!={1}(?!=)', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.RELIABILITY,
                    "Comparaison != — préférez !==.",
                    "Utilisez !== pour l'inégalité stricte.", "JS-REL-002"))

            # console.log in prod code
            if re.search(r'\bconsole\.(log|debug|info|warn)\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "console.log/debug détecté — pensez à le retirer en production.",
                    "Utilisez un logger (winston, pino) ou supprimez avant build.", "JS-STYL-003"))

            # Trailing comma issues / semicolons (ESLint-style)
            if stripped and not stripped.startswith("//") and not stripped.endswith((";", "{", "}", "(", ")", ",", "=>", ":", "[", "]", "`", "&&", "||", "?", "+")):
                # Heuristic: statement-like lines without semicolon
                if re.match(r'^(const|let|return|throw|import|export)\s', stripped) and not stripped.endswith("\\"):
                    if not stripped.endswith(";") and not stripped.endswith("{") and not stripped.endswith("("):
                        pass  # Too noisy without a proper parser

            # TODO/FIXME
            m = re.search(r'\b(TODO|FIXME|HACK|XXX)\b', stripped, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                    f"Commentaire '{m.group(1)}' non résolu.", "", "JS-MAINT-001"))

            # Trailing whitespace
            if line != line.rstrip("\n") and line.rstrip("\n") != line.rstrip():
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "Espace(s) en fin de ligne.", "", "JS-STYL-004"))

        return issues

    def _check_security(self, filepath, lines):
        issues = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            # eval()
            if re.search(r'\beval\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SECURITY,
                    "eval() détecté — exécution de code arbitraire.",
                    "Refactorisez pour éviter eval().", "JS-SEC-001"))

            # innerHTML injection
            if re.search(r'\.innerHTML\s*=', stripped) and not re.search(r'textContent', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "innerHTML affecté — risque de XSS.",
                    "Utilisez textContent ou une lib de sanitisation (DOMPurify).", "JS-SEC-002"))

            # document.write
            if re.search(r'\bdocument\.write\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "document.write() — déconseillé et vecteur XSS.",
                    "Utilisez les méthodes DOM modernes.", "JS-SEC-003"))

            # dangerouslySetInnerHTML (React)
            if re.search(r'dangerouslySetInnerHTML', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "dangerouslySetInnerHTML — risque XSS React.",
                    "Sanitisez avec DOMPurify avant injection.", "JS-SEC-004"))

            # Hardcoded secrets in JS
            if re.search(r'(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*["\'][^"\']{8,}["\']', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SECURITY,
                    "Secret potentiellement hardcodé dans le JS.",
                    "Utilisez des variables d'environnement (process.env) ou un vault.", "JS-SEC-005"))

            # prototype pollution
            if re.search(r'__proto__', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "__proto__ détecté — risque de prototype pollution.",
                    "Évitez la manipulation du prototype. Utilisez Object.create(null).", "JS-SEC-006"))

        return issues

    def _check_quality(self, filepath, lines, is_ts):
        issues = []
        content = "\n".join(lines)

        # Functions without JSDoc (basic heuristic)
        func_pattern = re.compile(
            r'(?:^|\n)\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(',
            re.MULTILINE
        )
        for m in func_pattern.finditer(content):
            fname = m.group(1)
            lineno = content[:m.start()].count("\n") + 1
            # Check if preceding 3 lines have /** */
            start = max(0, lineno - 4)
            preceding = "\n".join(lines[start:lineno - 1])
            if not re.search(r'/\*\*|@param|@returns', preceding):
                issues.append(self._make_issue(
                    filepath, lineno, Severity.INFO, Category.DOCUMENTATION,
                    f"Fonction '{fname}' sans JSDoc.",
                    "Ajoutez un commentaire JSDoc (/** @param ... @returns ... */).", "JS-DOC-001"))

        # TypeScript: any type usage
        if is_ts:
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if re.search(r':\s*any\b', stripped) and not stripped.startswith("//"):
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.STYLE,
                        "Type 'any' utilisé — perd le bénéfice de TypeScript.",
                        "Définissez un type précis ou utilisez 'unknown'.", "TS-TYPE-001"))

                # Non-null assertion
                if re.search(r'\w+!\.', stripped) and not stripped.startswith("//"):
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.RELIABILITY,
                        "Opérateur non-null '!' utilisé — peut masquer des erreurs.",
                        "Ajoutez une vérification explicite (if (x !== null)).", "TS-TYPE-002"))

        # Deeply nested callbacks (callback hell heuristic)
        max_indent = max((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
        if max_indent > 32:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.COMPLEXITY,
                f"Indentation profonde ({max_indent} espaces) — possible callback hell.",
                "Refactorisez avec async/await ou des promesses chaînées.", "JS-CPLX-001"))

        # Missing error handling in promises
        promise_without_catch = len(re.findall(r'\.then\s*\(', content))
        catch_count = len(re.findall(r'\.catch\s*\(|try\s*\{', content))
        if promise_without_catch > 0 and catch_count == 0:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.RELIABILITY,
                f"{promise_without_catch} promise(s) sans .catch() ni try/catch.",
                "Ajoutez une gestion d'erreur sur chaque promesse.", "JS-REL-003"))

        return issues

    def _check_naming(self, filepath, content):
        issues = []
        # Classes should be PascalCase
        for m in re.finditer(r'\bclass\s+(\w+)', content):
            name = m.group(1)
            lineno = content[:m.start()].count("\n") + 1
            if not re.match(r'^[A-Z][a-zA-Z0-9]*$', name):
                issues.append(self._make_issue(
                    filepath, lineno, Severity.WARNING, Category.NAMING,
                    f"Classe '{name}' n'est pas en PascalCase.",
                    f"Renommez en PascalCase.", "JS-NAM-001"))
        return issues
