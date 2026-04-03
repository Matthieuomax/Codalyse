import os
from pathlib import Path
from typing import Dict, List, Set

IGNORE_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "__pycache__", ".tox", ".venv", "venv",
    "env", ".env", "node_modules", ".idea", ".vscode", "dist",
    "build", "target", ".mypy_cache", ".pytest_cache", ".eggs",
    "*.egg-info", ".DS_Store", "vendor",
}

SUPPORTED_EXTENSIONS: Set[str] = {
    # Code
    ".py", ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".sh", ".bash", ".zsh",
    # Systemd / Config
    ".service", ".timer", ".socket", ".mount", ".target", ".path",
    # Desktop
    ".desktop",
    # VHDL / HDL
    ".vhd", ".vhdl", ".v", ".sv",
    # Data / Config
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    # Docs
    ".md", ".rst", ".txt",
    # Web
    ".html", ".htm", ".css", ".js", ".ts",
    # Makefiles
    ".mk",
}

BINARY_EXTENSIONS: Set[str] = {
    ".pyc", ".o", ".a", ".so", ".dll", ".exe", ".bin", ".png",
    ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip",
    ".tar", ".gz", ".bz2", ".xz",
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


class ProjectScanner:
    def __init__(self, root: Path, ignore: List[str] = None):
        self.root = root
        self.extra_ignore: Set[str] = set(ignore or [])

    def scan(self) -> Dict[str, str]:
        """Returns {relative_path: content} for all scannable files."""
        result: Dict[str, str] = {}
        ignore = IGNORE_DIRS | self.extra_ignore

        for dirpath, dirnames, filenames in os.walk(self.root):
            # Prune ignored dirs in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in ignore and not d.startswith(".")
            ]

            for filename in filenames:
                filepath = Path(dirpath) / filename
                ext = filepath.suffix.lower()

                # Skip binaries
                if ext in BINARY_EXTENSIONS:
                    continue

                # Only supported extensions (or no extension for Makefile, Dockerfile…)
                if ext not in SUPPORTED_EXTENSIONS and ext != "":
                    base = filename.lower()
                    if base not in {"makefile", "dockerfile", "cmakelists.txt",
                                    "rakefile", "gemfile", "procfile"}:
                        continue

                # Skip large files
                try:
                    if filepath.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                try:
                    content = filepath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                rel = str(filepath.relative_to(self.root))
                result[rel] = content

        return result

    def file_tree(self) -> Dict:
        """Returns nested dict representing the file tree (for HTML report)."""
        tree: Dict = {}
        ignore = IGNORE_DIRS | self.extra_ignore

        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [
                d for d in dirnames
                if d not in ignore and not d.startswith(".")
            ]
            rel_dir = Path(dirpath).relative_to(self.root)
            node = tree
            if str(rel_dir) != ".":
                for part in rel_dir.parts:
                    node = node.setdefault(part, {})
            for f in filenames:
                node[f] = None

        return tree
