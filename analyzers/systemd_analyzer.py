import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class SystemdAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".service", ".timer", ".socket", ".mount", ".target", ".path"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        sections = self._parse_sections(content)
        ext = filepath.rsplit(".", 1)[-1].lower()

        if ext == "service":
            issues += self._check_service(filepath, sections)
        elif ext == "timer":
            issues += self._check_timer(filepath, sections)
        elif ext == "socket":
            issues += self._check_socket(filepath, sections)

        issues += self._check_unit_section(filepath, sections)
        issues += self._check_install_section(filepath, sections)
        issues += self._check_line_style(filepath, content)
        return issues

    def _parse_sections(self, content: str) -> dict:
        """Parse INI-like sections into {section: {key: value}}."""
        sections = {}
        current = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                current = stripped[1:-1]
                sections[current] = {}
            elif current and "=" in stripped and not stripped.startswith("#") and not stripped.startswith(";"):
                key, _, val = stripped.partition("=")
                sections[current][key.strip()] = val.strip()
        return sections

    def _check_unit_section(self, filepath, sections):
        issues = []
        unit = sections.get("Unit", {})
        if "Description" not in unit:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.DOCUMENTATION,
                "[Unit] Description manquante.",
                "Ajoutez 'Description=<description du service>'.", "SYSD-DOC-001"))
        elif len(unit.get("Description", "")) < 5:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.DOCUMENTATION,
                "[Unit] Description trop courte.",
                "Soyez plus descriptif.", "SYSD-DOC-002"))
        return issues

    def _check_service(self, filepath, sections):
        issues = []
        svc = sections.get("Service", {})

        # Required: ExecStart
        if "ExecStart" not in svc:
            issues.append(self._make_issue(
                filepath, None, Severity.CRITICAL, Category.CONFIGURATION,
                "[Service] ExecStart manquant — service invalide.",
                "Ajoutez 'ExecStart=/path/to/binary'.", "SYSD-CFG-001"))

        # Running as root
        if "User" not in svc and "DynamicUser" not in svc:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.SECURITY,
                "Service sans User= — s'exécute en root par défaut.",
                "Ajoutez 'User=nom_utilisateur' pour réduire les privilèges.", "SYSD-SEC-001"))

        # Restart policy
        if "Restart" not in svc:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.RELIABILITY,
                "Pas de politique de redémarrage (Restart=).",
                "Ajoutez 'Restart=on-failure' pour les services critiques.", "SYSD-REL-001"))

        # Security hardening
        security_directives = [
            "NoNewPrivileges", "ProtectSystem", "PrivateTmp",
            "ProtectHome", "ReadOnlyPaths",
        ]
        missing = [d for d in security_directives if d not in svc]
        if missing:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.SECURITY,
                f"Directives de sécurité manquantes : {', '.join(missing[:3])}…",
                "Ajoutez 'NoNewPrivileges=yes' et 'ProtectSystem=strict' au minimum.", "SYSD-SEC-002"))

        # PrivateTmp
        if "PrivateTmp" not in svc:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.SECURITY,
                "PrivateTmp non défini.",
                "Ajoutez 'PrivateTmp=yes' pour isoler /tmp.", "SYSD-SEC-003"))

        # Type
        if "Type" not in svc:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONFIGURATION,
                "Type de service non spécifié (défaut: simple).",
                "Définissez 'Type=simple|forking|notify|oneshot' explicitement.", "SYSD-CFG-002"))

        return issues

    def _check_timer(self, filepath, sections):
        issues = []
        timer = sections.get("Timer", {})
        if "OnCalendar" not in timer and "OnActiveSec" not in timer and "OnBootSec" not in timer:
            issues.append(self._make_issue(
                filepath, None, Severity.CRITICAL, Category.CONFIGURATION,
                "[Timer] Aucune planification définie.",
                "Ajoutez 'OnCalendar=daily' ou 'OnBootSec=5min'.", "SYSD-TIMER-001"))
        if "AccuracySec" not in timer:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONFIGURATION,
                "AccuracySec non défini (défaut: 1min).",
                "Précisez 'AccuracySec=1s' si la précision est importante.", "SYSD-TIMER-002"))
        return issues

    def _check_socket(self, filepath, sections):
        issues = []
        sock = sections.get("Socket", {})
        if "ListenStream" not in sock and "ListenDatagram" not in sock and "ListenSequentialPacket" not in sock:
            issues.append(self._make_issue(
                filepath, None, Severity.CRITICAL, Category.CONFIGURATION,
                "[Socket] Aucune directive Listen* définie.",
                "Ajoutez 'ListenStream=<port_ou_chemin>'.", "SYSD-SOCK-001"))
        return issues

    def _check_install_section(self, filepath, sections):
        issues = []
        install = sections.get("Install", {})
        if not install:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONFIGURATION,
                "Section [Install] manquante — 'systemctl enable' ne fonctionnera pas.",
                "Ajoutez [Install] avec 'WantedBy=multi-user.target'.", "SYSD-INST-001"))
        elif "WantedBy" not in install and "RequiredBy" not in install and "Also" not in install:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.CONFIGURATION,
                "[Install] sans WantedBy/RequiredBy.",
                "Ajoutez 'WantedBy=multi-user.target'.", "SYSD-INST-002"))
        return issues

    def _check_line_style(self, filepath, content):
        issues = []
        for i, line in enumerate(content.splitlines(), 1):
            if line != line.rstrip():
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "Espace(s) en fin de ligne.", "", "SYSD-STYL-001"))
        return issues
