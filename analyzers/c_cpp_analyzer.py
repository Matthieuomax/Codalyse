import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class CCppAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        lines = content.splitlines()
        ext = filepath.split(".")[-1].lower()
        is_header = ext in ("h", "hpp")

        issues += self._check_include_guard(filepath, content, is_header)
        issues += self._check_line_issues(filepath, lines, is_header)
        issues += self._check_functions(filepath, content, lines)
        return issues

    def _check_include_guard(self, filepath, content, is_header):
        issues = []
        if not is_header:
            return issues

        has_pragma_once = "#pragma once" in content
        has_ifndef = bool(re.search(r'#ifndef\s+\w+_H', content))
        if not has_pragma_once and not has_ifndef:
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.CONVENTION,
                "Header sans include guard ni '#pragma once'.",
                "Ajoutez '#pragma once' en tête de fichier.", "C-GUARD-001"))
        return issues

    def _check_line_issues(self, filepath, lines, is_header):
        issues = []
        func_pattern = re.compile(
            r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{'
        )
        in_comment = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track block comments
            if "/*" in stripped:
                in_comment = True
            if "*/" in stripped:
                in_comment = False
                continue
            if in_comment or stripped.startswith("//"):
                continue

            # Line length > 100
            if len(line.rstrip()) > 100:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    f"Ligne trop longue : {len(line.rstrip())} caractères.",
                    "Limitez à 80-100 caractères.", "C-STYL-001"))

            # Magic numbers (not in #define, not 0/1/2)
            if not stripped.startswith("#define") and not stripped.startswith("#include"):
                nums = re.findall(r'(?<!\w)([3-9]\d{2,}|\d{4,})(?!\w)', stripped)
                if nums:
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                        f"Nombre(s) magique(s) : {', '.join(nums)}.",
                        "Utilisez des constantes (#define ou const).", "C-MAINT-001"))

            # gets() - dangerous
            if re.search(r'\bgets\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SECURITY,
                    "Utilisation de gets() — buffer overflow garanti.",
                    "Utilisez fgets() avec une taille explicite.", "C-SEC-001"))

            # strcpy / strcat without size
            if re.search(r'\b(strcpy|strcat)\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "strcpy/strcat sans contrôle de taille — risque de buffer overflow.",
                    "Utilisez strncpy/strncat ou les variantes _s.", "C-SEC-002"))

            # sprintf without size
            if re.search(r'\bsprintf\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "sprintf() sans contrôle de taille.",
                    "Utilisez snprintf().", "C-SEC-003"))

            # malloc without cast check (very basic)
            if re.search(r'\bmalloc\s*\(', stripped) and "free" not in content:
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.RELIABILITY,
                    "malloc() détecté — vérifiez que free() est bien appelé.",
                    "Vérifiez chaque malloc avec son free correspondant.", "C-REL-001"))

            # NULL pointer dereference risk
            if re.search(r'=\s*malloc\s*\(.+\);', stripped):
                next_lines = "\n".join(lines[i:min(i+3, len(lines))])
                if not re.search(r'if\s*\(\s*\w+\s*(==\s*NULL|!=\s*NULL)', next_lines):
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.RELIABILITY,
                        "malloc() sans vérification du retour (NULL).",
                        "Ajoutez 'if (ptr == NULL) { ... }' après malloc.", "C-REL-002"))

            # Global variables (heuristic: top-level declarations outside function)
            if re.match(r'^(int|float|double|char|long|unsigned)\s+\w+\s*[=;]', stripped):
                if not stripped.startswith("//"):
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.ARCHITECTURE,
                        "Variable globale potentielle — difficile à tester.",
                        "Préférez passer par paramètre ou static dans le fichier.", "C-ARCH-001"))

            # TODO/FIXME
            m = re.search(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', stripped, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                    f"Commentaire '{m.group(1)}' non résolu.",
                    "Tracez dans un issue tracker.", "C-MAINT-002"))

            # Trailing whitespace
            if line != line.rstrip():
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "Espace(s) en fin de ligne.",
                    "Supprimez les espaces de fin.", "C-STYL-002"))

        return issues

    def _check_functions(self, filepath, content, lines):
        """Detect functions without preceding comment."""
        issues = []
        func_def = re.compile(
            r'^(?:static\s+|inline\s+|extern\s+)?'
            r'(?:const\s+)?(?:unsigned\s+)?'
            r'(?:void|int|float|double|char|long|short|bool|\w+_t)\s*\*?\s*'
            r'(\w+)\s*\([^;]*\)\s*\{',
            re.MULTILINE
        )
        for m in func_def.finditer(content):
            fname = m.group(1)
            if fname in ("main", "if", "for", "while", "switch"):
                continue
            lineno = content[:m.start()].count("\n") + 1
            # Check if there's a comment in the 3 lines before
            start = max(0, lineno - 4)
            preceding = "\n".join(lines[start:lineno - 1])
            if not re.search(r'(//|/\*|\*)', preceding):
                issues.append(self._make_issue(
                    filepath, lineno, Severity.INFO, Category.DOCUMENTATION,
                    f"Fonction '{fname}' sans commentaire de documentation.",
                    "Ajoutez un commentaire décrivant le rôle, paramètres et retour.", "C-DOC-001"))
        return issues
