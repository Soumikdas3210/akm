"""Give each verifier its OWN key folder, holding only what its rung permits."""
from __future__ import annotations

import shutil
from pathlib import Path

LAYOUT = {
    "v2minus": ["kek_old.bin", "kek_new.bin"],
    "v2":      ["kek_new.bin"],
    "v3":      ["kek_old.bin", "kek_new.bin"],
    "f7":      ["kek_new.bin"],          # the world after K_old is retired
}


def stage_keys(run_dir: str | Path) -> None:
    keys = Path(run_dir) / "keys"
    for folder, files in LAYOUT.items():
        d = keys / folder
        d.mkdir(parents=True, exist_ok=True)
        for f in files:
            shutil.copy(keys / f, d / f)
