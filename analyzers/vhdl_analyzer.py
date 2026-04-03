import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class VHDLAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".vhd", ".vhdl"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        lines = content.splitlines()

        issues += self._check_structure(filepath, content)
        issues += self._check_naming(filepath, content)
        issues += self._check_style(filepath, lines)
        return issues

    def _check_structure(self, filepath, content):
        issues = []
        content_lower = content.lower()

        has_entity = "entity" in content_lower
        has_architecture = "architecture" in content_lower
        has_library = "library ieee" in content_lower
        has_use_std = "use ieee.std_logic_1164.all" in content_lower

        if not has_entity:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.ARCHITECTURE,
                "Aucune déclaration 'entity' trouvée.",
                "Chaque fichier VHDL doit avoir au moins une entité.", "VHDL-ARCH-001"))

        if not has_architecture:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.ARCHITECTURE,
                "Aucune 'architecture' trouvée.",
                "Ajoutez une architecture associée à l'entité.", "VHDL-ARCH-002"))

        if has_entity and not has_library:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.CONVENTION,
                "Déclaration 'library IEEE' manquante.",
                "Ajoutez 'library IEEE;' en tête de fichier.", "VHDL-CONV-001"))

        if has_library and not has_use_std:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONVENTION,
                "'use IEEE.STD_LOGIC_1164.ALL' manquant.",
                "Ajoutez cette clause use après library IEEE.", "VHDL-CONV-002"))

        return issues

    def _check_naming(self, filepath, content):
        issues = []

        # Entity names: should be lowercase or mixed (PascalCase allowed)
        for m in re.finditer(r'\bentity\s+(\w+)\s+is\b', content, re.IGNORECASE):
            name = m.group(1)
            lineno = content[:m.start()].count("\n") + 1
            # Check naming convention (prefer lowercase or snake_case for VHDL)
            if re.search(r'[A-Z]{2,}', name):
                issues.append(self._make_issue(
                    filepath, lineno, Severity.INFO, Category.NAMING,
                    f"Entité '{name}' en MAJUSCULES — préférez lowercase ou snake_case.",
                    "Convention VHDL : noms en minuscules ou snake_case.", "VHDL-NAM-001"))

        # Signal names: convention s_ prefix for signals
        for m in re.finditer(r'\bsignal\s+(\w+)\s*:', content, re.IGNORECASE):
            name = m.group(1)
            lineno = content[:m.start()].count("\n") + 1
            if not name.lower().startswith("s_") and not name.lower().startswith("sig_"):
                issues.append(self._make_issue(
                    filepath, lineno, Severity.INFO, Category.NAMING,
                    f"Signal '{name}' sans préfixe 's_'.",
                    "Convention recommandée : 's_nom_signal'.", "VHDL-NAM-002"))

        # Port names: i_ for inputs, o_ for outputs, io_ for inout
        port_block = re.search(r'\bport\s*\((.*?)\)\s*;', content, re.DOTALL | re.IGNORECASE)
        if port_block:
            for m in re.finditer(r'(\w+)\s*:\s*(in|out|inout)\b', port_block.group(1), re.IGNORECASE):
                name = m.group(1)
                direction = m.group(2).lower()
                if direction == "in" and not name.lower().startswith("i_"):
                    pass  # info only – too noisy, skip
                if direction == "out" and not name.lower().startswith("o_"):
                    pass  # info only – skip

        # Process labels: should be present
        processes = list(re.finditer(r'\bprocess\b', content, re.IGNORECASE))
        labeled = list(re.finditer(r'\w+\s*:\s*process\b', content, re.IGNORECASE))
        if len(processes) > len(labeled):
            unlabeled = len(processes) - len(labeled)
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.NAMING,
                f"{unlabeled} process(es) sans label.",
                "Ajoutez des labels aux process : 'PROC_NOM : process(...)'.", "VHDL-NAM-003"))

        return issues

    def _check_style(self, filepath, lines):
        issues = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Line too long
            if len(line.rstrip()) > 100:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    f"Ligne trop longue : {len(line.rstrip())} caractères.",
                    "Limitez à 100 caractères.", "VHDL-STYL-001"))

            # Magic numbers (integers > 1 not in constant declarations)
            if not re.search(r'\bconstant\b', stripped, re.IGNORECASE):
                nums = re.findall(r'(?<!["\w])([3-9]\d+|\d{3,})(?!\w)', stripped)
                if nums and not stripped.strip().startswith("--"):
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                        f"Nombre magique : {', '.join(nums)}.",
                        "Définissez une constante nommée.", "VHDL-MAINT-001"))

            # TODO/FIXME
            m = re.search(r'\b(TODO|FIXME|HACK|XXX)\b', stripped, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                    f"Commentaire '{m.group(1)}' non résolu.", "", "VHDL-MAINT-002"))

            # Trailing whitespace
            if line != line.rstrip("\n") and line.rstrip("\n") != line.rstrip():
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    "Espace(s) en fin de ligne.", "", "VHDL-STYL-002"))

        return issues
