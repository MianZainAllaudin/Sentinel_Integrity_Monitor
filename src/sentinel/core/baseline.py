from pathlib import Path
from typing import List
from .models import FileSnapshot, BaselineData


def build_baseline(
    root: Path,
    snapshots: List[FileSnapshot],
) -> BaselineData:
    raise NotImplementedError
