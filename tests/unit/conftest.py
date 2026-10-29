import sys
from pathlib import Path


for app_root in (Path("/app"), Path(__file__).parents[2] / "backend"):
    if (app_root / "app").is_dir():
        sys.path.insert(0, str(app_root))
        break
