import json
import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class DataAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        ext = filepath.rsplit(".", 1)[-1].lower()
        if ext == "json":
            return self._analyze_json(filepath, content)
        elif ext in ("yaml", "yml"):
            return self._analyze_yaml(filepath, content)
        elif ext == "toml":
            return self._analyze_toml(filepath, content)
        elif ext in ("ini", "cfg", "conf"):
            return self._analyze_ini(filepath, content)
        return []

    # ─────────────────────────────── JSON ────────────────────────────────

    def _analyze_json(self, filepath, content):
        issues = []
        if not content.strip():
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.SYNTAX,
                "Fichier JSON vide.", "", "JSON-001"))
            return issues

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            issues.append(self._make_issue(
                filepath, e.lineno, Severity.CRITICAL, Category.SYNTAX,
                f"JSON invalide : {e.msg}",
                "Validez avec 'python -m json.tool fichier.json'.", "JSON-SYN-001"))
            return issues

        # Check nesting depth
        depth = self._json_depth(data)
        if depth > 6:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.COMPLEXITY,
                f"JSON très profondément imbriqué (profondeur {depth}).",
                "Aplatissez la structure si possible.", "JSON-CPLX-001"))

        # Large file warning
        lines = content.count("\n")
        if lines > 500:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.PERFORMANCE,
                f"Fichier JSON volumineux : {lines} lignes.",
                "Envisagez de le diviser ou d'utiliser un format binaire.", "JSON-PERF-001"))

        # Check for TODO in values (heuristic)
        if "TODO" in content or "FIXME" in content:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.MAINTAINABILITY,
                "Valeur TODO/FIXME détectée dans le JSON.",
                "Remplacez par la valeur définitive.", "JSON-MAINT-001"))

        return issues

    def _json_depth(self, obj, current=0):
        if isinstance(obj, dict):
            if not obj:
                return current
            return max(self._json_depth(v, current + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current
            return max(self._json_depth(v, current + 1) for v in obj)
        return current

    # ─────────────────────────────── YAML ────────────────────────────────

    def _analyze_yaml(self, filepath, content):
        issues = []
        if not content.strip():
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.SYNTAX,
                "Fichier YAML vide.", "", "YAML-001"))
            return issues

        try:
            import yaml
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                line = getattr(getattr(e, "problem_mark", None), "line", None)
                issues.append(self._make_issue(
                    filepath, line, Severity.CRITICAL, Category.SYNTAX,
                    f"YAML invalide : {str(e)[:120]}",
                    "Validez avec 'python -c \"import yaml; yaml.safe_load(open(\\'fichier.yml\\'))\"'.", "YAML-SYN-001"))
                return issues
        except ImportError:
            # No pyyaml – do basic checks
            issues += self._yaml_basic_check(filepath, content)
            return issues

        # Tabs in YAML
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if "\t" in line:
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SYNTAX,
                    "Tabulation détectée dans le YAML — interdit.",
                    "Remplacez toutes les tabulations par des espaces.", "YAML-SYN-002"))
                break

        # Inconsistent indentation
        indents = set()
        for line in lines:
            if line.strip() and not line.strip().startswith("#"):
                indent = len(line) - len(line.lstrip())
                if indent > 0:
                    indents.add(indent)
        # Check if smallest indent divides all others
        if indents:
            min_indent = min(indents)
            if min_indent > 0:
                bad = [i for i in indents if i % min_indent != 0]
                if bad:
                    issues.append(self._make_issue(
                        filepath, None, Severity.WARNING, Category.STYLE,
                        "Indentation YAML incohérente.",
                        "Utilisez un multiple fixe d'espaces (2 ou 4).", "YAML-STYL-001"))

        return issues

    def _yaml_basic_check(self, filepath, content):
        issues = []
        for i, line in enumerate(content.splitlines(), 1):
            if "\t" in line:
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SYNTAX,
                    "Tabulation détectée dans le YAML — interdit.",
                    "Remplacez les tabulations par des espaces.", "YAML-SYN-002"))
                break
        return issues

    # ─────────────────────────────── TOML ────────────────────────────────

    def _analyze_toml(self, filepath, content):
        issues = []
        try:
            import tomllib  # Python 3.11+
            tomllib.loads(content)
        except ImportError:
            try:
                import tomli
                tomli.loads(content)
            except ImportError:
                # No parser available – basic checks only
                return self._toml_basic_check(filepath, content)
            except Exception as e:
                issues.append(self._make_issue(
                    filepath, None, Severity.CRITICAL, Category.SYNTAX,
                    f"TOML invalide : {str(e)[:120]}", "", "TOML-SYN-001"))
        except Exception as e:
            issues.append(self._make_issue(
                filepath, None, Severity.CRITICAL, Category.SYNTAX,
                f"TOML invalide : {str(e)[:120]}", "", "TOML-SYN-001"))
        return issues

    def _toml_basic_check(self, filepath, content):
        issues = []
        for i, line in enumerate(content.splitlines(), 1):
            if "\t" in line and not line.strip().startswith("#"):
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "Tabulation dans le TOML — préférez les espaces.", "", "TOML-STYL-001"))
        return issues

    # ──────────────────────────────── INI ────────────────────────────────

    def _analyze_ini(self, filepath, content):
        issues = []
        lines = content.splitlines()
        in_section = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_section = True
                section_name = stripped[1:-1]
                if not section_name:
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.SYNTAX,
                        "Section INI avec nom vide.", "", "INI-SYN-001"))
                continue
            if "=" not in stripped and ":" not in stripped and in_section:
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SYNTAX,
                    f"Ligne INI sans '=' ni ':' : '{stripped[:50]}'.",
                    "Format attendu : 'clé = valeur'.", "INI-SYN-002"))

        return issues
