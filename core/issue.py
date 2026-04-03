from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    WARNING  = "warning"
    INFO     = "info"


class Category(Enum):
    SECURITY        = "Sécurité"
    NAMING          = "Nommage"
    STYLE           = "Style"
    ARCHITECTURE    = "Architecture"
    DOCUMENTATION   = "Documentation"
    PERFORMANCE     = "Performance"
    RELIABILITY     = "Fiabilité"
    CONVENTION      = "Convention"
    COMPLEXITY      = "Complexité"
    SYNTAX          = "Syntaxe"
    CONFIGURATION   = "Configuration"
    MAINTAINABILITY = "Maintenabilité"


GRADE_THRESHOLDS = [
    (95, "A+"), (90, "A"), (85, "B+"), (80, "B"),
    (75, "C+"), (70, "C"), (60, "D"), (0, "F"),
]


@dataclass
class Issue:
    file:       str
    line:       Optional[int]
    severity:   Severity
    category:   Category
    message:    str
    suggestion: str = ""
    rule:       str = ""

    def to_dict(self) -> dict:
        return {
            "file":       self.file,
            "line":       self.line,
            "severity":   self.severity.value,
            "category":   self.category.value,
            "message":    self.message,
            "suggestion": self.suggestion,
            "rule":       self.rule,
        }


def compute_score(issues: list) -> tuple:
    """
    Score plafonné par catégorie.

    Pénalités :
      Critique : -15 pts, plafond -60  → 4 critiques = score <= 40
      Warning  : -3  pts, plafond -25
      Info     : -0.3 pts, plafond -10

    Exemples :
      2 crit + 8 warn + 30 info = 100-30-24-9   = 37  (F)
      0 crit + 5 warn + 40 info = 100-0-15-10   = 75  (C+)
      0 crit + 0 warn + 100 info = 100-0-0-10   = 90  (A)
      1 crit + 2 warn + 10 info = 100-15-6-3    = 76  (C+)
    """
    n_crit = sum(1 for i in issues if i.severity == Severity.CRITICAL)
    n_warn = sum(1 for i in issues if i.severity == Severity.WARNING)
    n_info = sum(1 for i in issues if i.severity == Severity.INFO)

    penalty_crit = min(n_crit * 15, 60)
    penalty_warn = min(n_warn * 3,  25)
    penalty_info = min(n_info * 0.3, 10)

    score = 100.0 - penalty_crit - penalty_warn - penalty_info
    score = max(0.0, min(100.0, score))

    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return int(round(score)), grade
    return 0, "F"
