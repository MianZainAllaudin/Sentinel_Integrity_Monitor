from pathlib import Path
from typing import List, Tuple, Optional
from .models import FileSnapshot, ScanError


def scan_directory(
    root: Path,
    ignore_file: Optional[Path] = None,
    chunk_size: int = 1048576,
) -> Tuple[List[FileSnapshot], List[ScanError]]:
    return [], []
