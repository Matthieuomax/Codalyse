import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category


class MarkdownAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".md", ".rst"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues = []
        lines = content.splitlines()
        ext = filepath.rsplit(".", 1)[-1].lower()

        if ext == "md":
            issues += self._check_markdown(filepath, content, lines)
        elif ext == "rst":
            issues += self._check_rst(filepath, lines)
        return issues

    def _check_markdown(self, filepath, content, lines):
        issues = []
        has_h1 = False
        last_heading_level = 0
        code_block = False
        code_block_langs = []

        for i, line in enumerate(lines, 1):
            # Track code blocks
            if line.startswith("```"):
                if not code_block:
                    code_block = True
                    lang = line[3:].strip()
                    if not lang:
                        code_block_langs.append(i)
                else:
                    code_block = False
                continue

            if code_block:
                continue

            # Headings
            m = re.match(r'^(#{1,6})\s+(.*)', line)
            if m:
                level = len(m.group(1))
                title = m.group(2).strip()

                if level == 1:
                    if has_h1:
                        issues.append(self._make_issue(
                            filepath, i, Severity.INFO, Category.CONVENTION,
                            "Plusieurs titres H1 (#) dans le document.",
                            "Un document doit avoir un seul H1.", "MD-CONV-001"))
                    has_h1 = True

                # Heading hierarchy skip
                if last_heading_level and level > last_heading_level + 1:
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.CONVENTION,
                        f"Saut de niveau dans les titres : H{last_heading_level} → H{level}.",
                        "Les titres doivent être hiérarchiques (H1→H2→H3…).", "MD-CONV-002"))

                # Empty heading
                if not title:
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.STYLE,
                        "Titre de section vide.", "Ajoutez un titre.", "MD-STYL-001"))

                last_heading_level = level

            # Long lines (not in code) > 160 chars
            if len(line) > 160:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    f"Ligne très longue : {len(line)} caractères.",
                    "Insérez un retour à la ligne.", "MD-STYL-002"))

        # No H1
        if not has_h1 and content.strip():
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.DOCUMENTATION,
                "Document sans titre principal (H1).",
                "Ajoutez un titre '#' en tête de document.", "MD-DOC-001"))

        # Code blocks without language
        for lineno in code_block_langs:
            issues.append(self._make_issue(
                filepath, lineno, Severity.INFO, Category.STYLE,
                "Bloc de code sans langage spécifié.",
                "Ajoutez le langage : ` ```python `, ` ```bash `, etc.", "MD-STYL-003"))

        # Unclosed code block
        if code_block:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.SYNTAX,
                "Bloc de code ``` non fermé.",
                "Vérifiez que chaque ``` ouvrant a son ``` fermant.", "MD-SYN-001"))

        # TODO in text
        for i, line in enumerate(lines, 1):
            if re.search(r'\bTODO\b|\bFIXME\b', line, re.IGNORECASE):
                if not line.strip().startswith("#") and not line.strip().startswith("```"):
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                        "TODO/FIXME dans la documentation.",
                        "Complétez ou supprimez avant publication.", "MD-MAINT-001"))

        # Empty file
        if not content.strip():
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.DOCUMENTATION,
                "Fichier Markdown vide.", "Rédigez le contenu.", "MD-DOC-002"))

        return issues

    def _check_rst(self, filepath, lines):
        issues = []
        # Basic check: has a title (underlined)
        has_title = False
        for i, line in enumerate(lines, 1):
            if i > 1 and re.match(r'^[=\-~^"\'`#*+!@$%&.,:;|_?]{3,}$', line):
                has_title = True
                break
        if not has_title and any(l.strip() for l in lines):
            issues.append(self._make_issue(
                filepath, 1, Severity.INFO, Category.DOCUMENTATION,
                "Document RST sans titre visible.",
                "Ajoutez un titre souligné.", "RST-DOC-001"))
        return issues
