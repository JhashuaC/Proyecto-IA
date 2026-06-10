"""Punto de entrada de la aplicacion."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_detector.presentation.web.server import run


if __name__ == "__main__":
    run()
