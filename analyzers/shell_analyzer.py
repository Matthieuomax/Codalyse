import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class ShellAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".sh", ".bash", ".zsh"}

    def can_analyze(self, filepath: str) -> bool:
        from pathlib import Path
        p = Path(filepath)
        if p.suffix.lower() in self.EXTENSIONS:
            return True
        # Files without extension that start with shebang
        return False

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        lines = content.splitlines()

        issues += self._check_shebang(filepath, lines)
        issues += self._check_strict_mode(filepath, content, lines)
        issues += self._check_line_issues(filepath, lines)
        return issues

    def _check_shebang(self, filepath, lines):
        issues = []
        if not lines:
            return issues
        first = lines[0].strip()
        if not first.startswith("#!"):
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.CONVENTION,
                "Shebang manquant.",
                "Ajoutez '#!/usr/bin/env bash' (portable) ou '#!/bin/bash'.", "SH-CONV-001"))
        elif first in ("#!/bin/sh", "#!/usr/bin/sh"):
            issues.append(self._make_issue(
                filepath, 1, Severity.INFO, Category.CONVENTION,
                "Shebang /bin/sh : portabilité POSIX mais fonctionnalités limitées.",
                "Si vous utilisez des bashismes, changez pour '#!/usr/bin/env bash'.", "SH-CONV-002"))
        return issues

    def _check_strict_mode(self, filepath, content, lines):
        issues = []
        has_set_e = bool(re.search(r'\bset\b.*-[a-zA-Z]*e', content))
        has_set_u = bool(re.search(r'\bset\b.*-[a-zA-Z]*u', content))
        has_set_o = bool(re.search(r'set\s+-o\s+pipefail', content))

        if not has_set_e:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.RELIABILITY,
                "'set -e' manquant — le script continue malgré les erreurs.",
                "Ajoutez 'set -euo pipefail' en début de script.", "SH-REL-001"))
        if not has_set_u:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.RELIABILITY,
                "'set -u' manquant — variables non définies silencieuses.",
                "Ajoutez 'set -u' pour détecter les variables non initialisées.", "SH-REL-002"))
        if not has_set_o:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.RELIABILITY,
                "'set -o pipefail' manquant — erreurs dans les pipes ignorées.",
                "Ajoutez 'set -o pipefail'.", "SH-REL-003"))
        return issues

    def _check_line_issues(self, filepath, lines):
        issues = []
        in_heredoc = False
        heredoc_marker = None

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track heredoc
            m = re.search(r'<<[-\s]*["\']?(\w+)["\']?', stripped)
            if m and not in_heredoc:
                in_heredoc = True
                heredoc_marker = m.group(1)
            if in_heredoc and stripped == heredoc_marker:
                in_heredoc = False
                continue
            if in_heredoc:
                continue

            if stripped.startswith("#"):
                # TODO/FIXME
                t = re.search(r'\b(TODO|FIXME|HACK|XXX)\b', stripped, re.IGNORECASE)
                if t:
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                        f"Commentaire '{t.group(1)}' non résolu.", "", "SH-MAINT-001"))
                continue

            # Unquoted variables in conditions / strings (basic heuristic)
            if re.search(r'\[\s+\$\w+\s', stripped) and not re.search(r'\[\s+"?\$\w+"?\s', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.RELIABILITY,
                    "Variable non quotée dans une condition — risque de word splitting.",
                    'Utilisez "$variable" au lieu de $variable.', "SH-REL-004"))

            # Backticks (deprecated command substitution)
            if "`" in stripped:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "Backticks `` déconseillés pour la substitution de commande.",
                    "Utilisez $(...) à la place.", "SH-STYL-001"))

            # eval usage
            if re.match(r'\beval\b', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "eval() détecté — risque d'injection de commande.",
                    "Évitez eval(). Refactorisez si possible.", "SH-SEC-001"))

            # chmod 777
            if re.search(r'\bchmod\s+777\b', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "chmod 777 — permissions trop permissives.",
                    "Appliquez le principe du moindre privilège (ex: 755 ou 644).", "SH-SEC-002"))

            # curl | bash
            if re.search(r'\bcurl\b.*\|\s*(ba)?sh\b', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SECURITY,
                    "curl | bash — exécution de code distant sans vérification.",
                    "Téléchargez le script, vérifiez-le, puis exécutez-le séparément.", "SH-SEC-003"))

            # rm -rf /  or rm -rf /* 
            if re.search(r'\brm\s+(-rf|--recursive\s+--force)\s+(/\s*$|/\s+|\*)', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SECURITY,
                    "rm -rf / ou rm -rf /* — destruction potentielle du système.",
                    "Vérifiez soigneusement le chemin avant tout rm -rf.", "SH-SEC-004"))

            # cd without error check
            if re.match(r'^\s*cd\s+', stripped) and "||" not in stripped and "&&" not in stripped:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.RELIABILITY,
                    "cd sans vérification d'erreur.",
                    "Utilisez 'cd /path || exit 1'.", "SH-REL-005"))

            # Line too long
            if len(line.rstrip()) > 120:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    f"Ligne trop longue : {len(line.rstrip())} caractères.",
                    "Découpez avec \\.", "SH-STYL-002"))

            # Trailing whitespace
            if line != line.rstrip("\n"):
                if line.rstrip("\n") != line.rstrip():
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.STYLE,
                        "Espace(s) en fin de ligne.", "", "SH-STYL-003"))

        return issues
