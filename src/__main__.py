from __future__ import annotations

import json

from .dataset import ROOT
from .diagram import write as write_diagram
from .simulate import run_all
from .tables import render


def main() -> None:
    results_dir = ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    diagram = write_diagram()
    text = render()
    (results_dir / "tables.md").write_text(text)
    (results_dir / "simulation.json").write_text(json.dumps(run_all(), indent=2) + "\n")
    print(text)
    print(f"Wrote {results_dir / 'tables.md'}")
    print(f"Wrote {results_dir / 'simulation.json'}")
    print(f"Wrote {diagram}")


if __name__ == "__main__":
    main()
