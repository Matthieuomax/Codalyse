import re
from typing import List
from analyzers.base import BaseAnalyzer
from core.issue import Issue, Severity, Category

# ─────────────────────────────────────────────────────────────────────────────
# Analyseur HTML — couvre :
#   Syntaxe & structure      (DOCTYPE, balises fermantes, imbrication)
#   Sécurité                 (XSS inline, iframes sans sandbox, target=_blank)
#   Accessibilité (a11y)     (alt manquant, labels, lang, title)
#   SEO                      (meta description, title, heading hierarchy)
#   Performance              (scripts bloquants, CSS inline excessif)
#   Bonnes pratiques         (deprecated tags, style inline, id dupliqués)
# ─────────────────────────────────────────────────────────────────────────────


class HtmlAnalyzer(BaseAnalyzer):
    EXTENSIONS = {".html", ".htm"}

    def analyze(self, filepath: str, content: str) -> List[Issue]:
        issues: List[Issue] = []
        lines = content.splitlines()

        issues += self._check_structure(filepath, content, lines)
        issues += self._check_security(filepath, content, lines)
        issues += self._check_accessibility(filepath, content, lines)
        issues += self._check_seo(filepath, content, lines)
        issues += self._check_performance(filepath, content, lines)
        issues += self._check_best_practices(filepath, content, lines)
        return issues

    # ─────────────────────── Structure & Syntaxe ─────────────────────────

    def _check_structure(self, filepath, content, lines):
        issues = []
        cl = content.lower()

        # DOCTYPE manquant
        if not re.search(r'<!doctype\s+html', cl):
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.CONVENTION,
                "DOCTYPE manquant.",
                "Ajoutez '<!DOCTYPE html>' en toute première ligne.", "HTML-STR-001"))

        # Balise <html> manquante
        if "<html" not in cl:
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.CONVENTION,
                "Balise <html> manquante.",
                "Enveloppez tout le document dans <html lang=\"fr\">...</html>.", "HTML-STR-002"))

        # <head> manquant
        if "<head" not in cl:
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.CONVENTION,
                "Balise <head> manquante.",
                "Ajoutez une section <head> avec au moins <meta charset> et <title>.", "HTML-STR-003"))

        # <body> manquant
        if "<body" not in cl and "<html" in cl:
            issues.append(self._make_issue(
                filepath, 1, Severity.INFO, Category.CONVENTION,
                "Balise <body> manquante.",
                "Enveloppez le contenu visible dans <body>...</body>.", "HTML-STR-004"))

        # Encodage non déclaré
        if not re.search(r'<meta[^>]+charset', cl):
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.CONVENTION,
                "Encodage non déclaré (meta charset manquant).",
                "Ajoutez <meta charset=\"UTF-8\"> dans <head>.", "HTML-STR-005"))

        # Viewport manquant (important pour responsive)
        if not re.search(r'<meta[^>]+name=["\']viewport["\']', cl):
            issues.append(self._make_issue(
                filepath, 1, Severity.INFO, Category.CONVENTION,
                "Meta viewport manquante — rendu mobile non contrôlé.",
                "Ajoutez <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">.", "HTML-STR-006"))

        # Balises auto-fermantes mal formées (void elements avec </tag>)
        void_tags = ("area", "base", "br", "col", "embed", "hr", "img",
                     "input", "link", "meta", "param", "source", "track", "wbr")
        for tag in void_tags:
            for m in re.finditer(rf'</{tag}\s*>', content, re.IGNORECASE):
                lineno = content[:m.start()].count("\n") + 1
                issues.append(self._make_issue(
                    filepath, lineno, Severity.WARNING, Category.SYNTAX,
                    f"Balise vide <{tag}> fermée avec </{tag}> — invalide en HTML5.",
                    f"Supprimez </{tag}>, les void elements ne se ferment pas.", "HTML-STR-007"))

        # Imbrication incorrecte basique : <a> dans <a>
        if re.search(r'<a\b[^>]*>.*?<a\b', content, re.DOTALL | re.IGNORECASE):
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.SYNTAX,
                "Imbrication <a> dans <a> — invalide.",
                "Les liens ne peuvent pas être imbriqués.", "HTML-STR-008"))

        # IDs dupliqués
        ids = re.findall(r'\bid=["\']([^"\']+)["\']', content, re.IGNORECASE)
        seen = {}
        for id_val in ids:
            seen[id_val] = seen.get(id_val, 0) + 1
        for id_val, count in seen.items():
            if count > 1:
                issues.append(self._make_issue(
                    filepath, None, Severity.WARNING, Category.RELIABILITY,
                    f"ID dupliqué : id=\"{id_val}\" apparaît {count} fois.",
                    "Les IDs HTML doivent être uniques dans tout le document.", "HTML-STR-009"))

        # ─────────────────────────────────────────────────────────────────
        # NOUVEAU : Vérification stricte des balises non fermées
        # ─────────────────────────────────────────────────────────────────
        # Liste des balises communes qui nécessitent OBLIGATOIREMENT une fermeture
        tags_to_check = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span', 'a', 'strong', 'em', 'ul', 'ol', 'li', 'table', 'tr', 'td', 'th', 'form', 'button', 'label', 'select', 'textarea', 'script', 'style', 'head', 'body', 'html', 'title']

        for tag in tags_to_check:
            # Compte le nombre de balises ouvrantes (ex: <h1 ou <h1 class="titre">)
            # On utilise \b pour éviter que <h1 ne matche <h1> et <h1>
            open_count = len(re.findall(rf'<{tag}\b[^>]*>', content, re.IGNORECASE))
            
            # Compte le nombre de balises fermantes (ex: </h1>)
            close_count = len(re.findall(rf'</{tag}\s*>', content, re.IGNORECASE))

            if open_count > close_count:
                # S'il y a plus d'ouvertures que de fermetures
                diff = open_count - close_count
                issues.append(self._make_issue(
                    filepath, None, Severity.WARNING, Category.SYNTAX,
                    f"Balise <{tag}> non fermée détectée ({diff} manquante(s)).",
                    f"Assurez-vous que chaque <{tag}> possède un </{tag}> correspondant.", "HTML-STR-010"))
            
            elif close_count > open_count:
                # S'il y a plus de fermetures que d'ouvertures (balise orpheline)
                diff = close_count - open_count
                issues.append(self._make_issue(
                    filepath, None, Severity.WARNING, Category.SYNTAX,
                    f"Balise fermante </{tag}> orpheline détectée ({diff} en trop).",
                    f"Vous avez fermé un </{tag}> qui n'a jamais été ouvert.", "HTML-STR-011"))
        # ─────────────────────────────────────────────────────────────────
        return issues

    # ────────────────────────────── Sécurité ─────────────────────────────

    def _check_security(self, filepath, content, lines):
        issues = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Gestionnaire d'événement inline avec code non trivial (onclick="..longcode..")
            for evt in ("onclick", "onload", "onerror", "onmouseover", "onfocus",
                        "onchange", "onsubmit", "onkeyup", "onkeydown"):
                m = re.search(rf'\b{evt}\s*=\s*["\']([^"\']+)["\']', stripped, re.IGNORECASE)
                if m:
                    code = m.group(1).strip()
                    # Seulement si c'est du code complexe (pas juste un appel de fonction)
                    if len(code) > 30 or "document" in code or "window" in code or "eval" in code:
                        issues.append(self._make_issue(
                            filepath, i, Severity.WARNING, Category.SECURITY,
                            f"Code complexe dans {evt}= — difficile à maintenir et risque XSS.",
                            "Déplacez la logique dans un fichier .js externe avec addEventListener.", "HTML-SEC-001"))

            # eval() dans les scripts inline
            if re.search(r'\beval\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.CRITICAL, Category.SECURITY,
                    "eval() détecté dans le HTML — exécution de code arbitraire possible.",
                    "Supprimez eval(). Utilisez JSON.parse() ou refactorisez.", "HTML-SEC-002"))

            # innerHTML avec variable (XSS potentiel)
            if re.search(r'\.innerHTML\s*=\s*(?!["\'`])', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "innerHTML assigné à une variable — risque XSS.",
                    "Utilisez textContent ou DOMPurify.sanitize() avant injection.", "HTML-SEC-003"))

            # document.write()
            if re.search(r'\bdocument\.write\s*\(', stripped):
                issues.append(self._make_issue(
                    filepath, i, Severity.WARNING, Category.SECURITY,
                    "document.write() détecté — vecteur XSS et bloque le rendu.",
                    "Utilisez les méthodes DOM modernes (appendChild, insertAdjacentHTML).", "HTML-SEC-004"))

            # <iframe> sans sandbox
            if re.search(r'<iframe\b', stripped, re.IGNORECASE):
                if not re.search(r'\bsandbox\b', stripped, re.IGNORECASE):
                    # Vérifie les 3 lignes suivantes aussi pour les attributs multi-lignes
                    context = " ".join(lines[i-1:min(i+3, len(lines))])
                    if not re.search(r'\bsandbox\b', context, re.IGNORECASE):
                        issues.append(self._make_issue(
                            filepath, i, Severity.WARNING, Category.SECURITY,
                            "<iframe> sans attribut sandbox.",
                            "Ajoutez sandbox=\"allow-scripts allow-same-origin\" pour limiter les permissions.", "HTML-SEC-005"))

            # target="_blank" sans rel="noopener"
            if re.search(r'target=["\']_blank["\']', stripped, re.IGNORECASE):
                context = " ".join(lines[max(0, i-2):min(i+2, len(lines))])
                if not re.search(r'rel=["\'][^"\']*noopener', context, re.IGNORECASE):
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.SECURITY,
                        "target=\"_blank\" sans rel=\"noopener noreferrer\" — risque tabnapping.",
                        "Ajoutez rel=\"noopener noreferrer\" sur tous les liens target=\"_blank\".", "HTML-SEC-006"))

            # Inclusion de ressources HTTP (pas HTTPS)
            for attr in ("src", "href", "action"):
                m = re.search(rf'{attr}=["\']http://(?!localhost|127\.0\.0\.1)', stripped, re.IGNORECASE)
                if m:
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.SECURITY,
                        f"Ressource chargée en HTTP (non chiffrée) dans {attr}=.",
                        "Utilisez HTTPS pour toutes les ressources externes.", "HTML-SEC-007"))

            # Secrets hardcodés dans les attributs value/data
            if re.search(r'(?i)(password|secret|token|api.?key)\s*=\s*["\'][^"\']{6,}["\']', stripped):
                # Évite les faux positifs sur type="password"
                if not re.search(r'type=["\']password["\']', stripped, re.IGNORECASE):
                    issues.append(self._make_issue(
                        filepath, i, Severity.CRITICAL, Category.SECURITY,
                        "Secret potentiellement codé en dur dans le HTML.",
                        "Ne jamais mettre de secrets dans le HTML — utilisez des variables côté serveur.", "HTML-SEC-008"))

        return issues

    # ──────────────────────── Accessibilité (a11y) ───────────────────────

    def _check_accessibility(self, filepath, content, lines):
        issues = []

        # Attribut lang manquant sur <html>
        html_tag = re.search(r'<html\b[^>]*>', content, re.IGNORECASE)
        if html_tag and "lang" not in html_tag.group(0).lower():
            lineno = content[:html_tag.start()].count("\n") + 1
            issues.append(self._make_issue(
                filepath, lineno, Severity.WARNING, Category.CONVENTION,
                "<html> sans attribut lang — problème d'accessibilité.",
                "Ajoutez lang=\"fr\" (ou la langue du document) sur la balise <html>.", "HTML-A11Y-001"))

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # <img> sans alt
            for m in re.finditer(r'<img\b([^>]*?)>', stripped, re.IGNORECASE):
                attrs = m.group(1)
                if "alt" not in attrs.lower():
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.CONVENTION,
                        "<img> sans attribut alt — inaccessible aux lecteurs d'écran.",
                        "Ajoutez alt=\"description\" ou alt=\"\" si l'image est décorative.", "HTML-A11Y-002"))

            # <input> sans <label> associé (heuristique : input sans id ET sans aria-label)
            for m in re.finditer(r'<input\b([^>]*?)>', stripped, re.IGNORECASE):
                attrs = m.group(1)
                itype = re.search(r'type=["\'](\w+)["\']', attrs, re.IGNORECASE)
                type_val = itype.group(1).lower() if itype else "text"
                if type_val in ("hidden", "submit", "button", "reset", "image"):
                    continue
                has_id       = "id=" in attrs.lower()
                has_aria     = "aria-label" in attrs.lower() or "aria-labelledby" in attrs.lower()
                has_title    = "title=" in attrs.lower()
                has_placeholder = "placeholder=" in attrs.lower()
                if not (has_id or has_aria or has_title or has_placeholder):
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.CONVENTION,
                        "<input> sans label associé (ni id, ni aria-label).",
                        "Ajoutez un <label for=\"id\"> ou aria-label=\"...\" sur l'input.", "HTML-A11Y-003"))

            # <button> vide (pas de texte et pas d'aria-label)
            for m in re.finditer(r'<button\b([^>]*?)>\s*</button>', stripped, re.IGNORECASE):
                attrs = m.group(1)
                if "aria-label" not in attrs.lower() and "title" not in attrs.lower():
                    issues.append(self._make_issue(
                        filepath, i, Severity.WARNING, Category.CONVENTION,
                        "<button> vide sans texte ni aria-label.",
                        "Ajoutez un texte visible ou aria-label=\"action\" pour les lecteurs d'écran.", "HTML-A11Y-004"))

            # tabindex > 0 (mauvaise pratique)
            m = re.search(r'tabindex=["\']([1-9]\d*)["\']', stripped, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.CONVENTION,
                    f"tabindex={m.group(1)} positif — perturbe l'ordre de navigation au clavier.",
                    "Utilisez tabindex=\"0\" ou réorganisez le DOM.", "HTML-A11Y-005"))

        return issues

    # ────────────────────────────── SEO ──────────────────────────────────

    def _check_seo(self, filepath, content, lines):
        issues = []
        cl = content.lower()

        # <title> manquant
        if not re.search(r'<title\b', cl):
            issues.append(self._make_issue(
                filepath, 1, Severity.WARNING, Category.DOCUMENTATION,
                "Balise <title> manquante.",
                "Ajoutez <title>Titre de la page</title> dans le <head>.", "HTML-SEO-001"))
        else:
            # <title> trop court ou trop long
            m = re.search(r'<title\b[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            if m:
                title_text = re.sub(r'<[^>]+>', '', m.group(1)).strip()
                if len(title_text) < 10:
                    issues.append(self._make_issue(
                        filepath, None, Severity.INFO, Category.DOCUMENTATION,
                        f"<title> trop court : \"{title_text}\" ({len(title_text)} caractères).",
                        "Un titre SEO idéal fait entre 50 et 60 caractères.", "HTML-SEO-002"))
                elif len(title_text) > 60:
                    issues.append(self._make_issue(
                        filepath, None, Severity.INFO, Category.DOCUMENTATION,
                        f"<title> trop long : {len(title_text)} caractères (max recommandé : 60).",
                        "Raccourcissez le titre pour éviter la troncature dans les résultats Google.", "HTML-SEO-003"))

        # Meta description manquante
        if not re.search(r'<meta[^>]+name=["\']description["\']', cl):
            issues.append(self._make_issue(
                filepath, 1, Severity.INFO, Category.DOCUMENTATION,
                "Meta description manquante.",
                "Ajoutez <meta name=\"description\" content=\"...\"> dans le <head>.", "HTML-SEO-004"))

        # Plusieurs <h1> (mauvais pour le SEO)
        h1_count = len(re.findall(r'<h1\b', content, re.IGNORECASE))
        if h1_count == 0:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.DOCUMENTATION,
                "Aucun <h1> trouvé — structure de titres absente.",
                "Ajoutez un <h1> unique décrivant le contenu principal de la page.", "HTML-SEO-005"))
        elif h1_count > 1:
            issues.append(self._make_issue(
                filepath, None, Severity.WARNING, Category.DOCUMENTATION,
                f"{h1_count} balises <h1> trouvées — une seule recommandée par page.",
                "Gardez un seul <h1> et utilisez <h2>-<h6> pour la hiérarchie.", "HTML-SEO-006"))

        # Hiérarchie des titres vérifiée
        headings = re.findall(r'<h([1-6])\b', content, re.IGNORECASE)
        if headings:
            levels = [int(h) for h in headings]
            for j in range(1, len(levels)):
                if levels[j] > levels[j-1] + 1:
                    issues.append(self._make_issue(
                        filepath, None, Severity.INFO, Category.DOCUMENTATION,
                        f"Saut dans la hiérarchie des titres : H{levels[j-1]} → H{levels[j]}.",
                        "Les titres doivent être hiérarchiques : H1→H2→H3.", "HTML-SEO-007"))
                    break  # Une seule alerte suffit

        return issues

    # ──────────────────────────── Performance ────────────────────────────

    def _check_performance(self, filepath, content, lines):
        issues = []

        # Scripts bloquants dans <head> (sans defer/async)
        in_head = False
        head_end = content.lower().find("</head>")
        head_content = content[:head_end] if head_end > 0 else ""
        for m in re.finditer(r'<script\b([^>]*?)>', head_content, re.IGNORECASE):
            attrs = m.group(1)
            # Ignore les scripts avec src= qui ont defer ou async
            if "src=" in attrs.lower():
                if "defer" not in attrs.lower() and "async" not in attrs.lower():
                    lineno = content[:m.start()].count("\n") + 1
                    issues.append(self._make_issue(
                        filepath, lineno, Severity.WARNING, Category.PERFORMANCE,
                        "Script externe dans <head> sans defer/async — bloque le rendu.",
                        "Ajoutez l'attribut defer ou async, ou déplacez le script avant </body>.", "HTML-PERF-001"))

        # Styles inline excessifs (sur un même élément)
        for i, line in enumerate(lines, 1):
            m = re.search(r'style=["\']([^"\']{120,})["\']', line, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                    "Style inline très long (>120 caractères) — difficile à maintenir.",
                    "Déplacez ce style dans une classe CSS dans un fichier externe.", "HTML-PERF-002"))

        # Absence totale de CSS externe (page non stylée ou tout inline)
        has_css_link = bool(re.search(r'<link[^>]+rel=["\']stylesheet["\']', content, re.IGNORECASE))
        has_style_tag = bool(re.search(r'<style\b', content, re.IGNORECASE))
        has_inline_styles = len(re.findall(r'\bstyle=["\']', content, re.IGNORECASE)) > 5
        if has_inline_styles and not has_css_link and not has_style_tag:
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.MAINTAINABILITY,
                "Nombreux styles inline sans feuille de style externe.",
                "Centralisez les styles dans un fichier CSS externe pour la maintenabilité.", "HTML-PERF-003"))

        # Images sans width/height (cause Cumulative Layout Shift)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'<img\b([^>]*?)>', line, re.IGNORECASE):
                attrs = m.group(1)
                if "width" not in attrs.lower() or "height" not in attrs.lower():
                    # Seulement si c'est une image externe (src=http ou src="fichier.xxx")
                    if re.search(r'src=["\'][^"\']+\.(jpg|png|gif|webp|svg)["\']', attrs, re.IGNORECASE):
                        issues.append(self._make_issue(
                            filepath, i, Severity.INFO, Category.PERFORMANCE,
                            "<img> sans width/height — provoque un décalage de mise en page (CLS).",
                            "Ajoutez width=\"...\" height=\"...\" pour réserver l'espace avant le chargement.", "HTML-PERF-004"))
                        break

        return issues

    # ──────────────────────── Bonnes pratiques ───────────────────────────

    def _check_best_practices(self, filepath, content, lines):
        issues = []
        cl = content.lower()

        # Balises dépréciées HTML5
        deprecated = {
            "font":     "Utilisez CSS (font-family, font-size, color).",
            "center":   "Utilisez CSS (text-align: center; ou margin: auto;).",
            "marquee":  "Utilisez des animations CSS.",
            "blink":    "Supprimez — non supporté et mauvaise UX.",
            "strike":   "Utilisez <del> ou CSS (text-decoration: line-through;).",
            "big":      "Utilisez CSS (font-size).",
            "small":    "Utilisez <small> uniquement pour annotations légales, sinon CSS.",
            "tt":       "Utilisez <code> ou <kbd>.",
            "frame":    "Les frames sont obsolètes — utilisez <iframe> ou du CSS.",
            "frameset": "Les framesets sont obsolètes — restructurez avec du CSS.",
        }
        for tag, suggestion in deprecated.items():
            if f"<{tag}" in cl or f"<{tag} " in cl:
                # Trouver le numéro de ligne
                m = re.search(rf'<{tag}\b', content, re.IGNORECASE)
                lineno = content[:m.start()].count("\n") + 1 if m else None
                issues.append(self._make_issue(
                    filepath, lineno, Severity.WARNING, Category.CONVENTION,
                    f"Balise dépréciée <{tag}> — non standard en HTML5.",
                    suggestion, "HTML-DEP-001"))

        # TODO/FIXME dans les commentaires HTML
        for i, line in enumerate(lines, 1):
            m = re.search(r'<!--.*?(TODO|FIXME|HACK|XXX).*?-->', line, re.IGNORECASE)
            if m:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.MAINTAINABILITY,
                    f"Commentaire '{m.group(1)}' non résolu dans le HTML.",
                    "Tracez dans un issue tracker ou résolvez avant mise en production.", "HTML-MAINT-001"))

        # Lignes trop longues (> 200 caractères, seuil plus élevé que Python)
        for i, line in enumerate(lines, 1):
            if len(line.rstrip()) > 200:
                issues.append(self._make_issue(
                    filepath, i, Severity.INFO, Category.STYLE,
                    f"Ligne très longue : {len(line.rstrip())} caractères.",
                    "Indentez correctement et découpez les attributs HTML sur plusieurs lignes.", "HTML-STYL-001"))

        # Attributs onclick= contenant des fonctions non définies (heuristique simple)
        for i, line in enumerate(lines, 1):
            # Formulaire sans action ni méthode
            m = re.search(r'<form\b([^>]*?)>', line, re.IGNORECASE)
            if m:
                attrs = m.group(1)
                if "action=" not in attrs.lower() and "onsubmit=" not in attrs.lower():
                    issues.append(self._make_issue(
                        filepath, i, Severity.INFO, Category.CONVENTION,
                        "<form> sans attribut action — le formulaire ne sera pas soumis.",
                        "Ajoutez action=\"/endpoint\" ou gérez la soumission en JavaScript.", "HTML-CONV-001"))

        # Pas de favicon
        if not re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\']', cl):
            issues.append(self._make_issue(
                filepath, None, Severity.INFO, Category.CONVENTION,
                "Favicon non déclarée.",
                "Ajoutez <link rel=\"icon\" href=\"/favicon.ico\"> dans le <head>.", "HTML-CONV-002"))

        return issues
