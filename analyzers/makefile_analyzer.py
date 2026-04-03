import re
from typing import List
from pathlib import Path
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class MakefileAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".mk"}

    def can_analyze(self, filepath: str) -> bool:
        name = Path(filepath).name.lower()
        return name in ("makefile", "gnumakefile", "bsdmakefile") or filepath.endswith(".mk")

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        lines = content.splitlines()

        issues += self._check_structure(filepath, lines, content)
        issues += self._check_style(filepath, lines)
        return issues

    def _check_structure(self, filepath, lines, content):
        issues = []
        targets = {}
        has_phony = ".PHONY" in content
        has_all = bool(re.search(r'^all\s*:', content, re.MULTILINE))
        has_clean = bool(re.search(r'^clean\s*:', content, re.MULTILINE))
        has_help = bool(re.search(r'^help\s*:', content, re.MULTILINE))

        # Collect targets
        for i, line in enumerate(lines, 1):
            m = re.match(r'^([a-zA-Z0-9_\-\.][a-zA-Z0-9_\-\.]*)(?:\s+[a-zA-Z0-9_\-\.]*)*\s*:', line)
            if m and not line.startswith("\t") and not line.startswith("#"):
                targets[m.group(1)] = i

        if not has_phony:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.CONVENTION,
                ".PHONY manquant — les cibles comme 'clean' peuvent conflictuellement être des fichiers.",
                "Ajoutez '.PHONY: all clean install test' etc.", "MAKE-CONV-001"))

        if not has_all:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONVENTION,
                "Cible 'all' manquante.",
                "Ajoutez 'all:' comme première cible par convention.", "MAKE-CONV-002"))

        if not has_clean:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONVENTION,
                "Cible 'clean' manquante.",
                "Ajoutez 'clean:' pour nettoyer les fichiers générés.", "MAKE-CONV-003"))

        if not has_help:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.DOCUMENTATION,
                "Cible 'help' manquante.",
                "Ajoutez 'help:' listant les cibles disponibles.", "MAKE-DOC-001"))

        # Check for use of $var without $() or ${}
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Single-char var ok ($@, $<, $^, $*, $%, $?, $|, $+, $/)
            bad_vars = re.findall(r'\$(?![(@<\^*%\?|+/\$\({\)}\s])[a-zA-Z_]', stripped)
            if bad_vars:
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.STYLE,
                    f"Variable sans parenthèses : {', '.join(bad_vars)}.",
                    "Utilisez $(VARNAME) pour la lisibilité.", "MAKE-STYL-001"))

        # Missing CC/CFLAGS variables (for C projects)
        if "gcc" in content.lower() or ".c" in content:
            if "CC" not in content and "cc" not in content.lower():
                issues.append(self._make_issue(
                    filepath, None, Severity.INFO, Category.CONVENTION,
                    "Compilateur C non défini via CC=.",
                    "Définissez 'CC = gcc' pour rendre le Makefile portable.", "MAKE-CONV-004"))

        return issues

    def _check_style(self, filepath, lines):
        issues = []
        for i, line in enumerate(lines, 1):
            if not line.startswith("#") and not line.startswith("\t") and not line.startswith("."):
                # Recipe lines must use tabs, not spaces
                if re.match(r'^    ', line) and "=" not in line and ":" not in line:
                    issues.append(self._make_issue(
                        filepath, i, Severity.CRITICAL, Category.SYNTAX,
                        "Recette Makefile indentée avec des espaces au lieu de tabulations.",
                        "Les recettes Makefile DOIVENT être indentées avec une tabulation.", "MAKE-SYN-001"))

            # TODO/FIXME
            m = re.search(r'\b(TODO|FIXME|HACK)\b', line, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                    f"Commentaire '{m.group(1)}' non résolu.", "", "MAKE-MAINT-001"))

        return issues
