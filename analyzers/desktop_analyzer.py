import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category

REQUIRED_FIELDS = ["Type", "Name", "Exec"]
RECOMMENDED_FIELDS = ["Icon", "Categories", "Comment", "Version"]
VALID_TYPES = {"Application", "Link", "Directory"}


class DesktopAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".desktop"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        sections = self._parse(content)
        entry = sections.get("Desktop Entry", {})

        if not entry:
            issues.append(self._make_issue(
                filepath, None, Severity.CRITICAL, Category.SYNTAX,
                "Section [Desktop Entry] manquante.",
                "Ajoutez '[Desktop Entry]' en tête de fichier.", "DESK-SYN-001"))
            return issues

        # Required fields
        for field in REQUIRED_FIELDS:
            if field not in entry:
                issues.append(self._make_issue(
                    filepath, None, Severity.CRITICAL, Category.CONFIGURATION,
                    f"Champ obligatoire manquant : {field}.",
                    f"Ajoutez '{field}=<valeur>'.", "DESK-CFG-001"))

        # Recommended fields
        for field in RECOMMENDED_FIELDS:
            if field not in entry:
                issues.append(self._make_issue(
                    filepath, None, Severity.INFO, Category.CONFIGURATION,
                    f"Champ recommandé manquant : {field}.",
                    f"Ajoutez '{field}=<valeur>' pour une meilleure intégration.", "DESK-CFG-002"))

        # Type value
        type_val = entry.get("Type", "")
        if type_val and type_val not in VALID_TYPES:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.CONFIGURATION,
                f"Type='{type_val}' invalide.",
                f"Valeurs valides : {', '.join(VALID_TYPES)}.", "DESK-CFG-003"))

        # Exec field: should not use deprecated %f/%u without handling
        exec_val = entry.get("Exec", "")
        if exec_val and not re.search(r'%[fFuUdDnNickvm%]', exec_val):
            pass  # no field codes, fine

        # Categories format
        cats = entry.get("Categories", "")
        if cats and not cats.endswith(";"):
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.CONVENTION,
                "Categories doit se terminer par ';'.",
                f"Changez en 'Categories={cats};'.", "DESK-CONV-001"))

        # NoDisplay or Hidden
        if entry.get("NoDisplay", "").lower() == "true":
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONFIGURATION,
                "NoDisplay=true — l'entrée est cachée des menus.",
                "Normal si intentionnel (autostart, etc.).", "DESK-CFG-004"))

        # Deprecated Encoding field
        if "Encoding" in entry:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONVENTION,
                "Champ Encoding= déprécié (UTF-8 implicite depuis freedesktop 1.0).",
                "Supprimez ce champ.", "DESK-CONV-002"))

        # Terminal field should be boolean
        term = entry.get("Terminal", "")
        if term and term.lower() not in ("true", "false"):
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.CONFIGURATION,
                f"Terminal='{term}' — valeur non booléenne.",
                "Utilisez 'Terminal=true' ou 'Terminal=false'.", "DESK-CFG-005"))

        return issues

    def _parse(self, content: str) -> dict:
        sections = {}
        current = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                current = stripped[1:-1]
                sections[current] = {}
            elif current and "=" in stripped and not stripped.startswith("#"):
                key, _, val = stripped.partition("=")
                sections[current][key.strip()] = val.strip()
        return sections
