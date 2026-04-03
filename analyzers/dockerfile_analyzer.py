import re
from typing import List
from pathlib import Path
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class DockerfileAnalyzer(BaseAnalyzer):
    EXTENSIONS = {""}  # Handled via can_analyze

    def can_analyze(self, filepath: str) -> bool:
        name = Path(filepath).name.lower()
        return name == "dockerfile" or name.startswith("dockerfile.")

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        lines = content.splitlines()

        issues += self._check_structure(filepath, lines, content)
        issues += self._check_security(filepath, lines)
        issues += self._check_best_practices(filepath, lines, content)
        return issues

    def _check_structure(self, filepath, lines, content):
        issues = []

        # Must start with FROM (or ARG before FROM)
        first_instruction = None
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                first_instruction = stripped.upper().split()[0]
                break

        if first_instruction and first_instruction not in ("FROM", "ARG"):
            issues.append(self._make_issue(
                filepath, 1, Severity.CRITICAL, Category.SYNTAX,
                f"Dockerfile ne commence pas par FROM (trouvé: {first_instruction}).",
                "Débutez par 'FROM <image>:<tag>'.", "DOCK-SYN-001"))

        # FROM without tag (latest is bad)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if re.match(r'^FROM\s+\S+\s*$', stripped, re.IGNORECASE):
                image = stripped.split()[1]
                if ":" not in image and "@" not in image and image.lower() != "scratch":
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.RELIABILITY,
                        f"FROM {image} sans tag explicite — utilise 'latest' implicitement.",
                        "Épinglez une version : 'FROM ubuntu:22.04'.", "DOCK-REL-001"))
            elif re.match(r'^FROM\s+\S+:latest', stripped, re.IGNORECASE):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.RELIABILITY,
                    "FROM avec tag ':latest' — non reproductible.",
                    "Utilisez un tag de version fixe (ex: :22.04, :3.11-slim).", "DOCK-REL-002"))

        return issues

    def _check_security(self, filepath, lines):
        issues = []
        has_user = False
        runs_as_root = True

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # USER instruction
            if re.match(r'^USER\s+', stripped, re.IGNORECASE):
                has_user = True
                user = stripped.split(None, 1)[1].strip()
                if user in ("root", "0"):
                    issues.append(self._make_issue(
                        filepath, i, Severity.CRITICAL, Category.SECURITY,
                        "USER root explicite — s'exécute en root dans le conteneur.",
                        "Créez et utilisez un utilisateur non-root : 'USER appuser'.", "DOCK-SEC-001"))

            # ADD with URL (better to use curl + verify)
            if re.match(r'^ADD\s+https?://', stripped, re.IGNORECASE):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "ADD avec URL — pas de vérification d'intégrité.",
                    "Utilisez RUN curl + vérification de hash.", "DOCK-SEC-002"))

            # Secrets in ENV
            if re.match(r'^ENV\s+', stripped, re.IGNORECASE):
                env_val = stripped[4:].strip()
                if re.search(r'(?i)(password|secret|key|token)\s*=\s*\S+', env_val):
                    issues.append(self._make_issue(
                        filepath, i, Severity.CRITICAL, Category.SECURITY,
                        "Secret potentiel dans ENV — visible dans les métadonnées image.",
                        "Utilisez des secrets Docker (--secret) ou un vault.", "DOCK-SEC-003"))

            # Secrets in ARG
            if re.match(r'^ARG\s+', stripped, re.IGNORECASE):
                arg_val = stripped[4:].strip()
                if re.search(r'(?i)(password|secret|key|token)\s*=', arg_val):
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.SECURITY,
                        "Secret potentiel dans ARG — exposé via 'docker history'.",
                        "Utilisez Docker BuildKit secrets (--mount=type=secret).", "DOCK-SEC-004"))

            # RUN with sudo
            if re.match(r'^RUN\s+.*\bsudo\b', stripped, re.IGNORECASE):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "sudo dans RUN — probablement inutile (déjà root) et mauvaise pratique.",
                    "Supprimez sudo et changez d'utilisateur avec USER.", "DOCK-SEC-005"))

            # chmod 777
            if re.search(r'\bchmod\s+(777|a\+rwx)', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "chmod 777 dans le Dockerfile — permissions trop larges.",
                    "Appliquez le principe du moindre privilège.", "DOCK-SEC-006"))

        if not has_user:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.SECURITY,
                "Pas de directive USER — le conteneur s'exécutera en root.",
                "Ajoutez 'RUN useradd -r appuser && USER appuser' avant CMD/ENTRYPOINT.", "DOCK-SEC-007"))

        return issues

    def _check_best_practices(self, filepath, lines, content):
        issues = []
        run_count = 0
        has_healthcheck = False
        has_label = False
        apt_lines = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if re.match(r'^RUN\s+', stripped, re.IGNORECASE):
                run_count += 1
                # apt-get without --no-install-recommends
                if re.search(r'\bapt-get\s+install\b', stripped):
                    apt_lines.append(i)
                    if "--no-install-recommends" not in stripped:
                        issues.append(self._make_issue(
                            filepath, i, Severity.INFO, Category.PERFORMANCE,
                            "apt-get install sans --no-install-recommends.",
                            "Ajoutez --no-install-recommends pour réduire la taille.", "DOCK-PERF-001"))
                    # apt-get without rm -rf /var/lib/apt/lists
                    if "rm -rf /var/lib/apt/lists" not in content:
                        issues.append(self._make_issue(
                            filepath, i, Severity.INFO, Category.PERFORMANCE,
                            "Cache apt non nettoyé après install.",
                            "Ajoutez '&& rm -rf /var/lib/apt/lists/*' dans le même RUN.", "DOCK-PERF-002"))

                # pip install without --no-cache-dir
                if re.search(r'\bpip\s+install\b', stripped) and "--no-cache-dir" not in stripped:
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.PERFORMANCE,
                        "pip install sans --no-cache-dir.",
                        "Ajoutez --no-cache-dir pour réduire la taille de l'image.", "DOCK-PERF-003"))

            elif re.match(r'^HEALTHCHECK\s+', stripped, re.IGNORECASE):
                has_healthcheck = True

            elif re.match(r'^LABEL\s+', stripped, re.IGNORECASE):
                has_label = True

            # COPY . . (copies everything, needs .dockerignore)
            if re.match(r'^COPY\s+\.\s+\.', stripped, re.IGNORECASE):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.ARCHITECTURE,
                    "COPY . . — copie tout le contexte, pensez à .dockerignore.",
                    "Ajoutez un .dockerignore pour exclure node_modules, .git, etc.", "DOCK-ARCH-001"))

        # Too many RUN layers
        if run_count > 6:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.PERFORMANCE,
                f"{run_count} instructions RUN séparées — beaucoup de couches.",
                "Chaînez avec && pour réduire le nombre de layers.", "DOCK-PERF-004"))

        if not has_healthcheck:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.RELIABILITY,
                "Pas de HEALTHCHECK défini.",
                "Ajoutez 'HEALTHCHECK CMD curl -f http://localhost/ || exit 1'.", "DOCK-REL-003"))

        if not has_label:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.DOCUMENTATION,
                "Pas de LABEL de métadonnées.",
                "Ajoutez 'LABEL maintainer=... version=... description=...'.", "DOCK-DOC-001"))

        return issues
