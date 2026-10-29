import sys
from pathlib import Path


for candidate in Path(__file__).resolve().parents:
    if (candidate / "worker" / "lief_extract.py").is_file():
        sys.path.insert(0, str(candidate))
        break
