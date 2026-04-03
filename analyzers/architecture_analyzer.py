import re
from pathlib import Path
from typing import List, Dict
from core.issue import Issue, Severity, Category


class ArchitectureAnalyzer:
    """Project-level architecture analysis (not file-level)."""

    def __init__(self, root: Path):
        self.root = root

    def can_analyze(self, filepath: str) -> bool:
        return False  # Does not analyze individual files

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        return []  # Not used for single files

    def analyze_project(self, files: Dict[str, str]) -> List[Issue]:
        issues = []
        paths = list(files.keys())
        filenames = [Path(p).name.lower() for p in paths]
        extensions = [Path(p).suffix.lower() for p in paths]

        issues += self._check_meta_files(filenames, paths)
        issues += self._check_structure(paths)
        issues += self._check_naming_consistency(paths)
        issues += self._check_encoding(files)
        return issues

    def _check_meta_files(self, filenames, paths):
        issues = []
        root_filenames = [Path(p).name.lower() for p in paths if "/" not in p and "\\" not in p]

        if "readme.md" not in root_filenames and "readme.rst" not in root_filenames and "readme.txt" not in root_filenames:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.WARNING,
                category=Category.DOCUMENTATION,
                message="Pas de fichier README trouvé.",
                suggestion="Créez un README.md décrivant le projet, l'installation et l'utilisation.",
                rule="ARCH-DOC-001"))

        if "license" not in root_filenames and "licence" not in root_filenames:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.INFO,
                category=Category.ARCHITECTURE,
                message="Pas de fichier LICENSE.",
                suggestion="Ajoutez un fichier LICENSE (MIT, GPL, Apache…).",
                rule="ARCH-001"))

        if ".gitignore" not in root_filenames:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.WARNING,
                category=Category.ARCHITECTURE,
                message="Pas de fichier .gitignore.",
                suggestion="Créez un .gitignore pour exclure les fichiers générés, secrets, etc.",
                rule="ARCH-002"))

        # Check for requirements.txt or pyproject.toml if .py files exist
        has_python = any(p.endswith(".py") for p in paths)
        has_req = "requirements.txt" in root_filenames or "pyproject.toml" in root_filenames or "setup.py" in root_filenames
        if has_python and not has_req:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.INFO,
                category=Category.ARCHITECTURE,
                message="Projet Python sans requirements.txt ni pyproject.toml.",
                suggestion="Listez vos dépendances dans requirements.txt ou pyproject.toml.",
                rule="ARCH-003"))

        # Check for Makefile / CMakeLists in C projects
        has_c = any(p.endswith(".c") or p.endswith(".cpp") for p in paths)
        has_build = "makefile" in root_filenames or "cmakelists.txt" in root_filenames
        if has_c and not has_build:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.INFO,
                category=Category.ARCHITECTURE,
                message="Projet C/C++ sans Makefile ni CMakeLists.txt.",
                suggestion="Ajoutez un système de build (Makefile, CMake, Meson).",
                rule="ARCH-004"))

        # .env.example if .env referenced
        has_dotenv = ".env" in root_filenames
        has_env_example = ".env.example" in root_filenames or ".env.sample" in root_filenames
        if has_dotenv and not has_env_example:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.WARNING,
                category=Category.SECURITY,
                message=".env présent sans .env.example.",
                suggestion="Ajoutez .env à .gitignore et créez .env.example avec les clés (sans valeurs).",
                rule="ARCH-005"))

        return issues

    def _check_structure(self, paths):
        issues = []
        # Very flat or very deep structures
        max_depth = max((p.count("/") + p.count("\\") for p in paths), default=0)
        n_files = len(paths)

        if n_files > 30 and max_depth <= 1:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.INFO,
                category=Category.ARCHITECTURE,
                message=f"{n_files} fichiers dans un projet plat (pas de sous-dossiers).",
                suggestion="Organisez en sous-dossiers selon la responsabilité (src/, lib/, tests/, docs/).",
                rule="ARCH-STRUCT-001"))

        if max_depth > 8:
            issues.append(Issue(
                file="(projet)",
                line=None,
                severity=Severity.INFO,
                category=Category.ARCHITECTURE,
                message=f"Hiérarchie très profonde (profondeur max : {max_depth}).",
                suggestion="Aplatissez l'arborescence si certains niveaux n'apportent pas de valeur.",
                rule="ARCH-STRUCT-002"))

        return issues

    def _check_naming_consistency(self, paths):
        """Detect mixed naming conventions for files in the same folder."""
        issues = []
        from collections import defaultdict
        folder_styles = defaultdict(set)

        for p in paths:
            parts = p.replace("\\", "/").split("/")
            filename = parts[-1]
            folder = "/".join(parts[:-1]) or "(racine)"
            stem = Path(filename).stem

            if "_" in stem and "-" not in stem and not stem.startswith("."):
                folder_styles[folder].add("snake_case")
            elif "-" in stem and "_" not in stem:
                folder_styles[folder].add("kebab-case")
            elif re.match(r'^[A-Z][a-z]', stem):
                folder_styles[folder].add("PascalCase")
            elif re.match(r'^[a-z][A-Z]', stem):
                folder_styles[folder].add("camelCase")

        for folder, styles in folder_styles.items():
            if len(styles) > 1:
                issues.append(Issue(
                    file=f"{folder}/",
                    line=None,
                    severity=Severity.INFO,
                    category=Category.NAMING,
                    message=f"Conventions de nommage mixtes dans '{folder}' : {', '.join(styles)}.",
                    suggestion="Choisissez une convention unique par dossier et par langage.",
                    rule="ARCH-NAM-001"))

        return issues

    def _check_encoding(self, files: Dict[str, str]):
        """Detect files with Windows line endings (CRLF)."""
        issues = []
        for filepath, content in files.items():
            if "\r\n" in content:
                issues.append(Issue(
                    file=filepath,
                    line=None,
                    severity=Severity.INFO,
                    category=Category.CONVENTION,
                    message="Fins de ligne Windows (CRLF) détectées.",
                    suggestion="Configurez git: 'git config core.autocrlf input' et convertissez avec dos2unix.",
                    rule="ARCH-ENC-001"))
        return issues
